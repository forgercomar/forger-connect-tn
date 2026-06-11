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
 *
 * CIFRADO AT-REST DEL SHARED_SECRET
 * =================================
 *
 * `accounts.shared_secret` también se guarda cifrado (misma key + AES-256-GCM),
 * en la MISMA columna, distinguible por formato (ver sealSecret/openSecret):
 *
 *   legacy (plano):  base64 de 32 bytes — alfabeto [A-Za-z0-9+/=], sin ':'
 *   cifrado:         "enc1:" + iv_b64 + ":" + (ciphertext‖tag)_b64
 *
 * Read-path backward-compat: filas legacy planas siguen funcionando tal cual.
 * El protocolo plugin↔central NO cambia: el HMAC siempre se computa con el
 * secret PLANO en memoria.
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
        return decryptWithKey(getTokenKey(), ciphertextB64, ivB64);
    } catch (err) {
        // Rotación de key: reintentar con WFTN_TOKEN_KEY_PREV si está definida.
        const prev = getPrevTokenKey();
        if (prev) {
            try {
                return decryptWithKey(prev, ciphertextB64, ivB64);
            } catch (err2) {
                console.warn('[auth] decryptToken failed (key actual y _PREV):', err2.message);
                return null;
            }
        }
        console.warn('[auth] decryptToken failed:', err.message);
        return null;
    }
}

/** Decripta con una key concreta. Throw si la auth tag no valida. */
function decryptWithKey(key, ciphertextB64, ivB64) {
    const iv = Buffer.from(ivB64, 'base64');
    const blob = Buffer.from(ciphertextB64, 'base64');
    // Los últimos 16 bytes son el auth tag (GCM standard).
    const tag = blob.subarray(blob.length - 16);
    const enc = blob.subarray(0, blob.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return dec.toString('utf8');
}

/**
 * Key anterior para rotación (WFTN_TOKEN_KEY_PREV). Devuelve null si no está
 * definida o es inválida — en ese caso el fallback simplemente no se intenta.
 */
function getPrevTokenKey() {
    const raw = process.env.WFTN_TOKEN_KEY_PREV;
    if (!raw) return null;
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) {
        console.warn('[auth] WFTN_TOKEN_KEY_PREV inválida (debe ser 32 bytes base64) — ignorada');
        return null;
    }
    return key;
}

// ----------------------------------------------------------------------------
// Cifrado at-rest del shared_secret (misma key/algoritmo que los tokens)
// ----------------------------------------------------------------------------
//
// Formato en DB (misma columna accounts.shared_secret):
//
//   "enc1:" + iv_b64 + ":" + (ciphertext‖tag)_b64
//
// Inequívoco vs. legacy: el valor plano es base64 estándar (alfabeto
// [A-Za-z0-9+/=]) que NUNCA contiene ':'. El prefijo "enc1:" además versiona
// el formato. NO se loguea jamás el secreto (ni plano ni cifrado).

const SECRET_ENC_PREFIX = 'enc1:';

/** ¿El valor guardado en DB está en formato cifrado (enc1)? */
export function isSealedSecret(stored) {
    return typeof stored === 'string' && stored.startsWith(SECRET_ENC_PREFIX);
}

/**
 * Cifra un shared_secret para persistirlo. Devuelve "enc1:<iv>:<ct+tag>".
 * THROW si la key de cifrado falta/es inválida (mismo contrato que
 * encryptToken): el write-path debe fallar explícito, nunca guardar plano
 * por accidente ni un valor a medias.
 */
export function sealSecret(plainSecret) {
    if (typeof plainSecret !== 'string' || plainSecret === '') {
        throw new Error('sealSecret: secret vacío');
    }
    const { ciphertext, iv } = encryptToken(plainSecret);
    return `${SECRET_ENC_PREFIX}${iv}:${ciphertext}`;
}

/**
 * Devuelve el shared_secret PLANO a partir de lo que haya en la DB:
 *
 *   - formato enc1       → decrypt; null si la key no valida (key rotada sin
 *                          migrar / fila corrupta) → el caller rechaza la auth
 *                          de ESA cuenta, sin crash del proceso.
 *   - cualquier otro     → fila legacy en texto plano: se usa tal cual.
 *
 * NUNCA throw y NUNCA loguea el secreto.
 */
export function openSecret(stored) {
    if (typeof stored !== 'string' || stored === '') return null;
    if (!isSealedSecret(stored)) return stored; // fila legacy plana
    const rest = stored.slice(SECRET_ENC_PREFIX.length);
    const sep = rest.indexOf(':');
    if (sep <= 0 || sep === rest.length - 1) return null; // formato corrupto
    const iv = rest.slice(0, sep);
    const ciphertext = rest.slice(sep + 1);
    // decryptToken ya es no-throw y loguea solo err.message (sin secreto).
    return decryptToken(ciphertext, iv);
}
