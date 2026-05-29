/**
 * auth.js — HMAC de requests plugin↔central + cifrado de tokens ML.
 *
 * MODELO DE FIRMA
 * ===============
 *
 * Cada request del plugin al central lleva 3 headers:
 *
 *   X-Wftn-Account   public_id de la cuenta (ej. "acc_a3f9...")
 *   X-Wftn-Ts        timestamp Unix (segundos) — protege contra replay
 *   X-Wftn-Sig       hex(HMAC-SHA256(secret, payload))
 *
 * El payload firmado es la concatenación:
 *
 *   method ‖ '\n' ‖ path ‖ '\n' ‖ ts ‖ '\n' ‖ body_sha256_hex
 *
 *   Donde body_sha256_hex = sha256 del body crudo (string vacío "" si no hay body).
 *
 * Si los datos están firmados correctamente Y el ts está dentro de ±5 minutos del
 * server, el request pasa. Sino → 401.
 *
 * El secret por cuenta vive en `accounts.shared_secret` (32 bytes random base64).
 * Se genera en /v1/handshake y NUNCA se devuelve después.
 *
 * CIFRADO DE REFRESH TOKENS
 * =========================
 *
 * Los refresh_tokens de ML se guardan encriptados con AES-256-GCM:
 *
 *   stored = base64( iv (12 bytes) ‖ ciphertext ‖ tag (16 bytes) )
 *
 * La key vive en env var `WFTN_TOKEN_KEY` (32 bytes base64). Rotable: para rotar,
 * agregás `WFTN_TOKEN_KEY_PREV`, decrypts viejos siguen funcionando hasta que
 * todos los tokens se re-encripten con la nueva key en su próximo refresh.
 */

import crypto from 'node:crypto';

const SIG_WINDOW_SEC = 5 * 60; // ±5 min de tolerancia para clock skew

// ----------------------------------------------------------------------------
// HMAC: firma + verificación
// ----------------------------------------------------------------------------

/**
 * Calcula la firma HMAC para un request dado.
 *
 * @param {string} secret   secret de la cuenta (base64; nosotros decodificamos)
 * @param {string} method   GET / POST / etc.
 * @param {string} path     path absoluto SIN dominio (ej. "/v1/jobs")
 * @param {number} ts       timestamp en segundos
 * @param {string} body     body crudo del request (string, NO objeto)
 */
export function signRequest(secret, method, path, ts, body = '') {
    const bodyHash = crypto.createHash('sha256').update(body, 'utf8').digest('hex');
    const payload = `${method.toUpperCase()}\n${path}\n${ts}\n${bodyHash}`;
    return crypto.createHmac('sha256', Buffer.from(secret, 'base64'))
        .update(payload, 'utf8')
        .digest('hex');
}

/**
 * Comparación constant-time para evitar timing attacks.
 */
export function safeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const ab = Buffer.from(a, 'utf8');
    const bb = Buffer.from(b, 'utf8');
    if (ab.length !== bb.length) return false;
    return crypto.timingSafeEqual(ab, bb);
}

/**
 * Verifica todo el package: headers + ventana de tiempo + signature.
 *
 * @returns {{ ok: boolean, reason?: string }}
 */
export function verifyRequest({ secret, method, path, ts, body, sigGiven }) {
    if (!secret || !method || !path || !ts || !sigGiven) {
        return { ok: false, reason: 'missing fields' };
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum)) return { ok: false, reason: 'bad ts' };
    if (Math.abs(nowSec - tsNum) > SIG_WINDOW_SEC) {
        return { ok: false, reason: 'ts out of window' };
    }
    const expected = signRequest(secret, method, path, tsNum, body || '');
    if (!safeEqual(expected, sigGiven)) {
        return { ok: false, reason: 'sig mismatch' };
    }
    return { ok: true };
}

// ----------------------------------------------------------------------------
// Generación de secrets y public_ids
// ----------------------------------------------------------------------------

/** Genera un secret base64 random de 32 bytes (256 bits). */
export function generateSecret() {
    return crypto.randomBytes(32).toString('base64');
}

/** Genera un public_id legible con prefijo (acc_xxxxxxx). */
export function generatePublicId(prefix) {
    const id = crypto.randomBytes(12).toString('hex'); // 24 chars hex
    return `${prefix}_${id}`;
}

// ----------------------------------------------------------------------------
// Cifrado de refresh_tokens (AES-256-GCM)
// ----------------------------------------------------------------------------

function getTokenKey() {
    const raw = process.env.WFTN_TOKEN_KEY;
    if (!raw) {
        throw new Error('WFTN_TOKEN_KEY no está definida en el entorno');
    }
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) {
        throw new Error(`WFTN_TOKEN_KEY debe ser 32 bytes (base64); actual: ${key.length} bytes`);
    }
    return key;
}

/**
 * Encripta un string (refresh_token) y devuelve { ciphertext, iv } como base64
 * para guardar en la DB en columnas separadas.
 */
export function encryptToken(plaintext) {
    if (typeof plaintext !== 'string' || plaintext === '') {
        return { ciphertext: '', iv: '' };
    }
    const key = getTokenKey();
    const iv = crypto.randomBytes(12); // GCM recomienda 96 bits
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Convención: ciphertext + tag concatenados → un solo blob base64.
    return {
        ciphertext: Buffer.concat([enc, tag]).toString('base64'),
        iv: iv.toString('base64'),
    };
}

/**
 * Decripta. Devuelve null si la auth tag no valida (token corrupto o key rotada
 * sin migrar). NO throw: el caller decide qué hacer.
 */
export function decryptToken(ciphertextB64, ivB64) {
    if (!ciphertextB64 || !ivB64) return null;
    try {
        const key = getTokenKey();
        const iv = Buffer.from(ivB64, 'base64');
        const blob = Buffer.from(ciphertextB64, 'base64');
        // Los últimos 16 bytes son el auth tag (GCM standard).
        const tag = blob.subarray(blob.length - 16);
        const enc = blob.subarray(0, blob.length - 16);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
        return dec.toString('utf8');
    } catch (err) {
        console.warn('[auth] decryptToken failed:', err.message);
        return null;
    }
}
