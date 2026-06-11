/**
 * license-enforce.js — Estado + política de enforcement del capability-token (Fase 6).
 *
 * GEMELO de forger-connect-ml: capa ADICIONAL sobre la auth HMAC existente
 * (shared_secret / hub_secret). No la reemplaza ni la toca. Aporta:
 *
 *   - La config de runtime leída de env (modo, pública Ed25519, gracia, skew).
 *   - La denylist en memoria (Set de license_id revocados) con refresh desde la
 *     tabla license_denylist (007), compartida por server / routes-v1 / worker.
 *   - El helper evaluateToken() que envuelve verifyCapabilityToken aplicando la
 *     política (off / observe / enforce) y la decisión de gracia.
 *
 * INVARIANTES (no romper):
 *   - LICENSE_ENFORCE default = 'observe' → NUNCA bloquea salvo == 'enforce'.
 *   - fail-safe de infra: si no hay LICENSE_API_PUBLIC_KEY, se comporta como
 *     'off' (no bloquea), aunque LICENSE_ENFORCE diga 'enforce'.
 *   - La denylist (revoke explícito) gana SIEMPRE sobre la gracia.
 */

import crypto from 'node:crypto';
import { verifyCapabilityToken } from './license-token.js';
import { query } from './db.js';

// Producto que este central exige en claim.product_slugs.
export const EXPECT_PRODUCT = 'wf-tiendanube';

// Header HTTP que trae el capability-token desde el plugin (TN).
export const LICENSE_TOKEN_HEADER = 'x-wftn-license-token';

// Ventana de gracia para los endpoints account-authed (jobs/next-batch/report/
// orders/etc — gate en authAccount, igual que connect-ml). Default 72h.
// NUNCA aplica al handshake (entrada nueva).
const GRACE_PERIOD_SEC = Math.max(0, Number(process.env.GRACE_PERIOD_SEC) || 259200);

// Margen de reloj para exp del token.
const SKEW_SEC = Math.max(0, Number(process.env.LICENSE_SKEW_SEC) || 30);

// Modo de enforcement.
//   off      → no se verifica nada.
//   observe  → se verifica y LOGUEA, pero NO bloquea (default).
//   enforce  → bloquea de verdad.
function readMode() {
    const raw = String(process.env.LICENSE_ENFORCE || 'observe').trim().toLowerCase();
    if (raw === 'off' || raw === 'enforce' || raw === 'observe') return raw;
    return 'observe';
}

// Pública Ed25519 del license-api. PEM (SPKI) en LICENSE_API_PUBLIC_KEY, con los
// '\n' eventualmente escapados (EasyPanel guarda multilinea como '\n' literales).
let _publicKey = null;
let _publicKeyLoaded = false;
function loadPublicKey() {
    if (_publicKeyLoaded) return _publicKey;
    _publicKeyLoaded = true;
    let pem = String(process.env.LICENSE_API_PUBLIC_KEY || '').trim();
    if (!pem) { _publicKey = null; return null; }
    // Robusto contra cómo los paneles de envs (EasyPanel) guardan el PEM multilínea:
    // comillas envolventes + '\n'/'\r\n' literales escapados + CR reales.
    if ((pem.startsWith('"') && pem.endsWith('"')) || (pem.startsWith("'") && pem.endsWith("'"))) {
        pem = pem.slice(1, -1);
    }
    pem = pem.replace(/\\r\\n/g, '\n').replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\r/g, '');
    try {
        _publicKey = crypto.createPublicKey(pem);
    } catch (e) {
        console.error('[license] LICENSE_API_PUBLIC_KEY inválida — enforcement DESACTIVADO (fail-safe):', e.message);
        _publicKey = null;
    }
    return _publicKey;
}

// -----------------------------------------------------------------------------
// Denylist en memoria, respaldada por la tabla license_denylist (007).
// -----------------------------------------------------------------------------
const _denylist = new Set();

/** Lee la denylist desde la DB y reemplaza el Set en memoria. */
export async function refreshDenylist() {
    try {
        const r = await query('SELECT license_id FROM license_denylist');
        const next = new Set();
        for (const row of r.rows) {
            if (row.license_id) next.add(String(row.license_id));
        }
        _denylist.clear();
        for (const id of next) _denylist.add(id);
    } catch (e) {
        // No pisar la denylist en memoria si la DB falla: mejor conservar lo que
        // ya teníamos (un revoke vigente no debe perderse por una caída de pg).
        console.warn('[license] refreshDenylist falló (se conserva la cache):', e.message);
    }
    return _denylist;
}

/** Agrega un license_id a la denylist (memoria + DB). Idempotente. */
export async function addToDenylist(licenseId, reason) {
    const id = String(licenseId || '').trim();
    if (!id) return false;
    _denylist.add(id);
    try {
        await query(
            `INSERT INTO license_denylist (license_id, reason) VALUES ($1, $2)
             ON CONFLICT (license_id) DO UPDATE SET reason = EXCLUDED.reason, revoked_at = NOW()`,
            [id, reason ? String(reason).slice(0, 512) : null]
        );
    } catch (e) {
        console.error('[license] addToDenylist persist falló:', e.message);
        // Igual queda en memoria de esta instancia.
    }
    return true;
}

/** Saca un license_id de la denylist (memoria + DB). Idempotente. */
export async function removeFromDenylist(licenseId) {
    const id = String(licenseId || '').trim();
    if (!id) return false;
    _denylist.delete(id);
    try {
        await query('DELETE FROM license_denylist WHERE license_id = $1', [id]);
    } catch (e) {
        console.error('[license] removeFromDenylist persist falló:', e.message);
        // Igual quedó fuera de la memoria de esta instancia.
    }
    return true;
}

/** Snapshot del Set para pasarlo a verifyCapabilityToken. */
export function getDenylist() {
    return _denylist;
}

// -----------------------------------------------------------------------------
// Config snapshot + helpers de política
// -----------------------------------------------------------------------------

/**
 * Estado efectivo del enforcement.
 *   active=false → off (por env o por fail-safe sin pública).
 */
export function licenseConfig() {
    const mode = readMode();
    const pub = loadPublicKey();
    // fail-safe: sin pública nos comportamos como 'off' aunque pidan enforce.
    const active = mode !== 'off' && !!pub;
    return {
        mode,
        active,
        enforcing: active && mode === 'enforce',
        hasPublicKey: !!pub,
        publicKey: pub,
        graceSec: GRACE_PERIOD_SEC,
        skewSec: SKEW_SEC,
        expectProduct: EXPECT_PRODUCT,
    };
}

/**
 * Verifica el token crudo aplicando product+denylist+skew. NO decide gracia
 * (eso depende del endpoint). Devuelve el verdict de verifyCapabilityToken más
 * la config usada. Si no hay pública, valid=false reason='no_pubkey'.
 *
 * @param {string} token   valor del header X-Wftn-License-Token (o vacío)
 * @param {object} [extra] { expectDomain?: string }
 */
export function evaluateToken(token, extra = {}) {
    const cfg = licenseConfig();
    const verdict = verifyCapabilityToken(token, {
        publicKey: cfg.publicKey,
        skewSec: cfg.skewSec,
        denylist: _denylist,
        expectProduct: cfg.expectProduct,
        expectDomain: extra.expectDomain || undefined,
    });
    return { verdict, cfg };
}

/**
 * ¿El reason corresponde a un revoke explícito? El revoke gana sobre la gracia.
 */
export function isRevoked(verdict) {
    return !!(verdict && verdict.reason === 'revoked');
}

/**
 * Gate del WORKER (sin HTTP / sin token a mano). ESPEJO de connect-ml
 * (licenseBlocksJob): gatea por accounts.license_exp — el vencimiento REAL del
 * último claim válido presentado (lo sella stampValidLicense en routes-v1.js) —
 * y NO por la edad del watermark. El worker corre después, de forma asíncrona,
 * así que no re-verifica un token (no lo tiene): solo corta VENCIMIENTOS
 * confirmados y revokes explícitos.
 *
 * Devuelve { allow, reason }.
 *   - off / observe → SIEMPRE allow.
 *   - enforce:
 *       license_id en denylist      → deny 'revoked' (gana incluso sobre gracia).
 *       sin license_exp (NULL)      → allow (fail-open: cuenta pre-Fase6 / pre-
 *                                      migración 008; el gate de authAccount ya
 *                                      filtra los requests en vivo).
 *       license_exp > now           → allow (licencia vigente).
 *       vencida + dentro de gracia  → allow (ancla = last_valid_license_token_at).
 *       vencida + fuera de gracia   → deny 'expired'.
 *
 * @param {object} account fila accounts con license_id, license_exp y
 *                         last_valid_license_token_at.
 */
export function workerLicenseGate(account) {
    const cfg = licenseConfig();
    if (!cfg.enforcing) return { allow: true, reason: cfg.active ? 'observe' : 'off' };

    // Revoke explícito gana siempre (incluso sobre gracia).
    if (account && account.license_id && _denylist.has(String(account.license_id))) {
        return { allow: false, reason: 'revoked' };
    }

    const expMs = account && account.license_exp ? new Date(account.license_exp).getTime() : 0;
    // Sin license_exp conocido: nunca presentó un token válido (o pre-Fase6 /
    // pre-migración 008). No bloqueamos por ausencia de datos — el gate del
    // request (authAccount) ya cubre handshake/jobs en vivo; acá solo cortamos
    // vencimientos confirmados.
    if (!expMs) return { allow: true, reason: 'no_license_exp' };

    const now = Date.now();
    if (expMs > now) return { allow: true, reason: 'license_valid' };

    // Vencida → ¿dentro de gracia? (ancla = último token válido presentado).
    const anchorMs = account.last_valid_license_token_at
        ? new Date(account.last_valid_license_token_at).getTime()
        : 0;
    const inGrace = anchorMs > 0 && (now - anchorMs) <= cfg.graceSec * 1000;
    if (inGrace) return { allow: true, reason: 'within_grace' };

    return { allow: false, reason: 'expired' };
}
