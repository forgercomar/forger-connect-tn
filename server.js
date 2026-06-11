/**
 * forger-connect-tn — Microservicio OAuth bridge + Central Orchestrator para TiendaNube.
 *
 * Stateless: no DB, no sesiones server-side. El "state" del flow OAuth se
 * codifica en URL (base64 del JSON) y se valida con HMAC en cada paso.
 *
 * Flow:
 *
 *   [Plugin cliente] ─── popup ───>  GET /connect-tn?site_url=&return_to=&nonce=
 *                                    (este endpoint codifica state y redirige a ML)
 *
 *   [User en TN]     ─── login ───>  https://www.tiendanube.com/apps/{app_id}/authorize
 *                                    (TN pide autorizar acceso a la tienda)
 *
 *   [TN]             ─── 302 ────>   GET /connect-tn/oauth/callback?code=XXX&state=YYY
 *                                    (este endpoint intercambia code → token y
 *                                     redirige al return_to del cliente con
 *                                     payload firmado)
 *
 *   [Plugin cliente] ─── valida ──>  Recibe payload + firma, valida HMAC contra
 *                                    WFTN_OAUTH_HUB_SECRET compartido, upsert
 *                                    de la tienda en su DB local.
 *
 * Variables de entorno requeridas:
 *
 *   TN_CLIENT_ID           App ID de partners.tiendanube.com (app 32980)
 *   TN_CLIENT_SECRET       Client Secret de partners.tiendanube.com (SOLO acá;
 *                          el plugin WP nunca lo ve)
 *   WFTN_OAUTH_HUB_SECRET  Shared secret con los plugins clientes (HMAC key,
 *                          generar con `openssl rand -base64 48`)
 *   WFTN_TOKEN_KEY         Key AES-256 (32 bytes base64) para cifrar tokens at-rest
 *   TN_OAUTH_BASE          (opcional) Default 'https://www.tiendanube.com'.
 *                          Para Brasil (Nuvemshop): 'https://www.nuvemshop.com.br'.
 *   TN_API_BASE            (opcional) Default 'https://api.tiendanube.com'.
 *   TN_API_VERSION         (opcional) Default '2025-03'.
 *   TN_USER_AGENT          (opcional) Default 'Forger (info@forger.com.ar)'. TN
 *                          EXIGE User-Agent con email de contacto.
 *   BASE_URL               (opcional) Default 'https://forger.com.ar'. Usado para
 *                          construir el callback URL. Tiene que coincidir con el
 *                          redirect URI registrado en partners.tiendanube.com:
 *                          {BASE_URL}/connect-tn/oauth/callback.
 *   PORT                   (opcional) Default 3000.
 *
 * @author forger.com.ar
 */

import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { mountV1 } from './routes-v1.js';
import { ping as dbPing, query as dbQuery } from './db.js';
import { startWorker } from './worker.js';
import { startScheduler } from './scheduler.js';
import { createRateLimiter } from './rate-limit.js';
import { licenseConfig, refreshDenylist, addToDenylist, removeFromDenylist } from './license-enforce.js';

// Versión del bridge — leído de package.json al arrancar. Se expone en /version
// para que el cliente pueda verificar qué build está corriendo sin acceso al
// container. Útil para diagnosticar "deploy aplicado vs. no aplicado".
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let PKG_VERSION = 'unknown';
try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    PKG_VERSION = pkg.version || 'unknown';
} catch (_) { /* ignore */ }
const STARTED_AT = new Date().toISOString();

// ============================================================================
// Storage simple en JSON file para el mapping store_id → site_url.
// El forwarder de webhooks lo usa para saber a dónde reenviar las notifications
// que recibe del bridge cuando ML las manda a /connect-tn/webhooks.
//
// Se popula al confirmar OAuth en /connect-tn/finish (ahí tenemos return_to →
// site_url + payload.store_id). Si el bridge reinicia y se pierde el archivo,
// los clientes existentes dejan de recibir webhooks hasta que reconecten.
//
// Para persistencia entre rebuilds, EasyPanel debe montar un volume en /data.
// ============================================================================
const DATA_DIR = process.env.DATA_DIR || '/data';
const MAPPINGS_FILE = path.join(DATA_DIR, 'mappings.json');
try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
} catch (e) {
    console.warn('[mappings] no se pudo crear DATA_DIR ' + DATA_DIR + ': ' + e.message);
}

function loadMappings() {
    try {
        const raw = fs.readFileSync(MAPPINGS_FILE, 'utf8');
        const parsed = JSON.parse(raw);
        return (parsed && typeof parsed === 'object') ? parsed : {};
    } catch (_) {
        return {};
    }
}

function saveMappings(map) {
    try {
        fs.writeFileSync(MAPPINGS_FILE, JSON.stringify(map, null, 2), 'utf8');
    } catch (e) {
        console.error('[mappings] save error:', e.message);
    }
}

function registerMapping(mlUserId, siteUrl) {
    if (!mlUserId || !siteUrl) return;
    const map = loadMappings();
    const key = String(mlUserId);
    const prev = map[key] || {};
    map[key] = {
        site_url:      siteUrl,
        registered_at: prev.registered_at || Math.floor(Date.now() / 1000),
        updated_at:    Math.floor(Date.now() / 1000),
    };
    saveMappings(map);
    console.log(`[mappings] registered user=${mlUserId} site=${siteUrl}`);
}

/**
 * Deriva la URL raíz de WordPress desde el return_to del OAuth.
 * WordPress puede vivir en subcarpeta (htdocs/wordpress/), entonces el return_to
 * típico es:
 *   https://misitio.com/wordpress/wp-admin/admin-post.php?action=wftn_oauth_callback
 *
 * Para forwardear webhooks correctamente necesitamos el path completo del WP root
 * (https://misitio.com/wordpress), no solo el origin. Cortamos antes de /wp-admin/.
 *
 * Si el return_to ya viene root-relative (sin /wp-admin/, raro), devolvemos origin.
 */
function deriveSiteRootFromReturnTo(returnTo) {
    try {
        const u = new URL(returnTo);
        let path = u.pathname || '';
        const idx = path.toLowerCase().indexOf('/wp-admin/');
        if (idx >= 0) path = path.substring(0, idx);
        // Quitamos trailing slash para que el forwarder pueda hacer site + '/wp-json/...'.
        return u.origin + path.replace(/\/+$/, '');
    } catch (_) {
        return null;
    }
}

// ============================================================================
// Config — leído de env vars
// ============================================================================
const PORT             = Number(process.env.PORT || 3000);
const TN_CLIENT_ID     = process.env.TN_CLIENT_ID || '';
const TN_CLIENT_SECRET = process.env.TN_CLIENT_SECRET || '';
const HUB_SECRET       = process.env.WFTN_OAUTH_HUB_SECRET || '';
const LICENSE_REVOKE_SECRET = process.env.LICENSE_REVOKE_SECRET || ''; // revoke S2S: secreto DEDICADO (paridad con connect-ml)
// Base de las páginas de OAuth de TiendaNube (authorize + token exchange).
// Para tiendas de Brasil (Nuvemshop): https://www.nuvemshop.com.br
const TN_OAUTH_BASE    = (process.env.TN_OAUTH_BASE || 'https://www.tiendanube.com').replace(/\/$/, '');
// Base de la API REST de TiendaNube (para traer datos de la tienda en el callback).
const TN_API_BASE      = (process.env.TN_API_BASE || 'https://api.tiendanube.com').replace(/\/$/, '');
const TN_API_VERSION   = process.env.TN_API_VERSION || '2025-03';
const TN_USER_AGENT    = process.env.TN_USER_AGENT || 'Forger (info@forger.com.ar)';
const BASE_URL         = (process.env.BASE_URL || 'https://forger.com.ar').replace(/\/$/, '');
// Redirect URI registrado en el panel de partners de TiendaNube (app 32980).
const CALLBACK_URL     = `${BASE_URL}/connect-tn/oauth/callback`;

// Validar config al arrancar — fail-fast.
const missing = [];
if (!TN_CLIENT_ID)     missing.push('TN_CLIENT_ID');
if (!TN_CLIENT_SECRET) missing.push('TN_CLIENT_SECRET');
if (!HUB_SECRET)       missing.push('WFTN_OAUTH_HUB_SECRET');
if (missing.length) {
    console.error('[forger-connect-tn] FATAL: faltan env vars:', missing.join(', '));
    process.exit(1);
}

// Hardening #30 (2026-05-25): validar WFTN_TOKEN_KEY al boot, no lazy. La key
// se usa por auth.js (encryptToken / decryptToken) cada vez que persistimos o
// leemos un refresh_token. Antes se validaba SOLO al primer call de encrypt —
// el server arrancaba OK con la key faltante y fallaba minutos/horas después
// en el primer handshake, complicando el debug ("¿por qué falla ahora?").
const tokenKeyRaw = process.env.WFTN_TOKEN_KEY || '';
if (!tokenKeyRaw) {
    console.error('[forger-connect-tn] FATAL: WFTN_TOKEN_KEY no está definida en el entorno');
    process.exit(1);
}
try {
    const tk = Buffer.from(tokenKeyRaw, 'base64');
    if (tk.length !== 32) {
        console.error(`[forger-connect-tn] FATAL: WFTN_TOKEN_KEY debe ser 32 bytes base64; actual: ${tk.length} bytes`);
        process.exit(1);
    }
} catch (e) {
    console.error('[forger-connect-tn] FATAL: WFTN_TOKEN_KEY no es base64 válido');
    process.exit(1);
}

const app = express();
app.disable('x-powered-by');

// Trust proxy — el reverse proxy termina TLS y reenvía con X-Forwarded-*.
app.set('trust proxy', true);

// Anti-caché global. Cualquier respuesta del bridge debe ser fresh — sino
// el reverse proxy o el browser pueden servir HTML viejo del deploy anterior
// (ej. la pantalla "Conectaste tu cuenta" después de que la removimos).
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('X-Bridge-Version', PKG_VERSION);
    next();
});

// Middleware de parsing — antes de los route handlers para que /connect-tn/finish
// y /refresh-token reciban req.body parseado.
//
// El body JSON crudo se stashea en req.rawBody (string) para que /v1/* pueda
// verificar el HMAC sobre el contenido exacto que viajó por la red. Sin esto,
// el re-stringify de express.json() podría no matchear bit a bit con lo que
// el cliente firmó (orden de keys, espacios, etc.).
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({
    limit: '4mb', // v1/jobs con miles de items necesita más
    verify: (req, _res, buf) => {
        req.rawBody = buf && buf.length ? buf.toString('utf8') : '';
    },
}));

// ============================================================================
// Redact helper (hardening #30, 2026-05-25)
// ============================================================================
// Sanitiza objetos antes de loguearlos. Antes podíamos loguear directamente
// `tokenData` de ML que en happy path contiene access_token + refresh_token, o
// `req.body` del handoff con el payload b64 (decodificable). En error paths los
// objetos llegan vacíos pero la sola posibilidad de que un futuro change los
// loguee es suficiente: redactamos por defecto.
//
// Detecta claves típicas (token, secret, password, key) y reemplaza el valor.
// Recursivo en objetos anidados. Limita profundidad a 6 niveles para evitar
// loops en objetos cíclicos (rare pero defensivo).
const REDACT_KEY_RE = /(^|_)(token|secret|password|key|auth|cookie|session)(_|$)/i;
function redactSecrets(value, depth = 0) {
    if (depth > 6) return '[depth limit]';
    if (value == null) return value;
    if (typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map((v) => redactSecrets(v, depth + 1));
    const out = {};
    for (const k of Object.keys(value)) {
        if (REDACT_KEY_RE.test(k)) {
            out[k] = '[REDACTED]';
        } else {
            out[k] = redactSecrets(value[k], depth + 1);
        }
    }
    return out;
}

// ============================================================================
// Rate limiters por bucket (hardening #25, 2026-05-25)
// ============================================================================
// Tiers calibrados para uso legítimo + headroom:
//   - OAuth start/callback: rarísimo (1 por install). 30/15min/IP cubre soporte
//     que prueba varias veces sin abrir las puertas a un atacante.
//   - finish + refresh-token: el plugin refresca tokens proactivamente; 60/min
//     es 1 por segundo, suficiente para uso normal y refresh batch.
//   - /v1/handshake: 1 por install típicamente, pero un plugin recién instalado
//     puede reintentar si falla. 20/15min/IP.
//   - /v1/* general: el plugin hace polling de jobs (status, poll central).
//     200/min/IP cubre polls cada ~300ms sin bloquear, deja techo razonable.
//   - /webhooks (de ML) y /healthz/version: BYPASS — no son endpoints de
//     cliente nuestro.
const limitOauthStart    = createRateLimiter({ bucket: 'oauth-start',    windowMs: 15 * 60_000, max: 30,  label: '/connect-tn start' });
const limitOauthCallback = createRateLimiter({ bucket: 'oauth-cb',       windowMs: 15 * 60_000, max: 30,  label: '/connect-tn/callback' });
const limitFinishRefresh = createRateLimiter({ bucket: 'finish-refresh', windowMs: 60_000,      max: 60,  label: '/connect-tn/finish + /refresh-token' });
const limitV1Handshake = createRateLimiter({ bucket: 'v1-handshake', windowMs: 15 * 60_000, max: 20, label: '/v1/handshake' });
const limitV1General   = createRateLimiter({ bucket: 'v1-general',   windowMs: 60_000,      max: 200, label: '/v1/*' });
// Webhooks: ML legítimo manda decenas/segundo en picos, así que el limit por IP
// tiene que ser alto. Pero cualquier IP puede llegar al endpoint público — sin
// rate limit, un atacante puede inundar la DB. 600 req/min por IP es ~10/seg,
// alcanza para ML real con margen, frena floods.
const limitWebhooks      = createRateLimiter({ bucket: 'webhooks',       windowMs: 60_000,      max: 600, label: '/connect-tn/webhooks' });

// ============================================================================
// Helpers
// ============================================================================

/** Codifica un objeto JSON a base64url (sin padding, URL-safe). */
function b64urlEncode(json) {
    return Buffer.from(JSON.stringify(json), 'utf8')
        .toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodifica base64url a objeto. */
function b64urlDecode(s) {
    const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
}

/** HMAC-SHA256 en base64 standard (no URL-safe — pareo con el lado PHP). */
function hmac(payloadB64) {
    return crypto.createHmac('sha256', HUB_SECRET).update(payloadB64).digest('base64');
}

/** Sanity: ¿return_to está bien formado y apunta a un dominio razonable? */
function isValidReturnTo(url) {
    try {
        const u = new URL(url);
        return (u.protocol === 'http:' || u.protocol === 'https:');
    } catch (e) {
        return false;
    }
}

/**
 * Hardening 2026-05-25: valida que return_to.origin === site_url.origin.
 * Esto bloquea open-redirect attacks donde un atacante intenta robar tokens
 * de la víctima redirigiendo a evil.com.
 */
function returnToMatchesSiteUrl(returnTo, siteUrl) {
    try {
        const r = new URL(returnTo);
        const s = new URL(siteUrl);
        return r.origin === s.origin;
    } catch (e) { return false; }
}

/**
 * Hardening 2026-05-25: verifica firma del query del plugin en /connect-tn start.
 * El plugin firma sha = HMAC(HUB_SECRET, site_url|return_to|nonce|ts). El
 * central re-calcula y compara timing-safe. Sin firma válida, el endpoint
 * rechaza — bloquea generación de links arbitrarios por terceros.
 *
 * También chequea ts (timestamp unix seconds) dentro de window ±5min para
 * prevenir replay de links viejos capturados de logs/history.
 */
function verifyStartSignature({ site_url, return_to, nonce, ts, sig }) {
    if (!sig || !ts) return { ok: false, reason: 'missing_sig' };
    const tsNum = parseInt(String(ts), 10);
    if (!Number.isFinite(tsNum)) return { ok: false, reason: 'bad_ts' };
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - tsNum) > 300) return { ok: false, reason: 'ts_window' };
    const canon = `${site_url}|${return_to}|${nonce}|${ts}`;
    // base64url (RFC 4648 §5) — match con el plugin. Base64 estándar mete
    // '+' que viaja como ' ' en query string y rompe la comparación.
    const expected = crypto.createHmac('sha256', HUB_SECRET).update(canon).digest('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    try {
        const a = Buffer.from(expected);
        const b = Buffer.from(String(sig));
        if (a.length !== b.length) return { ok: false, reason: 'sig_len' };
        if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'sig_mismatch' };
        return { ok: true };
    } catch (e) {
        return { ok: false, reason: 'sig_compare_error' };
    }
}

/**
 * Hardening 2026-05-25: persistencia de oauth_states en Postgres.
 * Antes el state viajaba codificado en base64 en la URL y volvía sin
 * validación server-side ("no confiamos en el contenido del state cuando
 * vuelve" — comment original). Ahora persistimos cada state emitido con
 * TTL 10min + flag consumed para evitar reuso.
 */
async function createOAuthState({ site_url, return_to, nonce }) {
    const stateId = crypto.randomBytes(32).toString('hex');
    const now = Math.floor(Date.now() / 1000);
    await dbQuery(
        `INSERT INTO oauth_states (state_id, site_url, return_to, nonce, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [stateId, site_url, return_to, nonce, now]
    );
    return stateId;
}

async function consumeOAuthState(stateId) {
    // SELECT + UPDATE en una sola query para race-safety: si dos requests
    // intentan consumir el mismo state, solo una matchea consumed_at IS NULL.
    const res = await dbQuery(
        `UPDATE oauth_states
            SET consumed_at = $2
          WHERE state_id = $1
            AND consumed_at IS NULL
            AND created_at > $3
        RETURNING site_url, return_to, nonce`,
        [stateId, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) - 600]
    );
    return res.rowCount > 0 ? res.rows[0] : null;
}

/**
 * Garbage-collect de oauth_states viejos. Corre al arrancar + cada 10 min.
 */
async function cleanupOAuthStates() {
    const cutoff = Math.floor(Date.now() / 1000) - 3600; // 1h: borra incluso los consumed
    try {
        await dbQuery('DELETE FROM oauth_states WHERE created_at < $1', [cutoff]);
        await dbQuery('DELETE FROM request_nonces WHERE created_at < $1', [cutoff]);
    } catch (e) {
        console.warn('[oauth] cleanup error:', e.message);
    }
}

/**
 * Anti-replay genérico: rechaza si el nonce ya se vio en window de 10min.
 * Usado por: handshake (purpose='handshake'), oauth_start (purpose='oauth_start').
 */
async function checkAndConsumeNonce(nonce, purpose) {
    const now = Math.floor(Date.now() / 1000);
    try {
        await dbQuery(
            `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, $2, $3)`,
            [nonce, purpose, now]
        );
        return { ok: true };
    } catch (e) {
        // Duplicate key = replay.
        if (e.code === '23505') return { ok: false, reason: 'replay' };
        throw e;
    }
}

/** Render simple HTML para páginas de error / fallback. */
function htmlPage(title, body) {
    return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>${title} · Forger</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #1f2937; padding: 40px 20px; line-height: 1.55; }
  .wrap { max-width: 560px; margin: 60px auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); padding: 32px 40px; }
  h1 { margin: 0 0 12px; font-size: 22px; color: #1e1b4b; }
  p { color: #4b5563; margin: 8px 0; }
  code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #c2410c; }
  .ok { color: #166534; }
  .err { color: #991b1b; }
</style>
</head><body>
<div class="wrap">${body}</div>
<p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:30px;">forger-connect-tn · stateless OAuth bridge</p>
</body></html>`;
}

/**
 * Pantalla de confirmación pre-handoff: el usuario revisa los datos de la cuenta
 * y decide si confirmar (mandar al plugin) o cancelar (volver sin guardar).
 *
 * Stateless: payload + return_to + nonce viajan como hidden fields firmados con
 * HMAC. El handler /connect-tn/finish valida la firma y decide qué hacer.
 */
function confirmationPage({ payload, returnTo, nonce, siteUrl, alreadyConnected = false }) {
    const payloadB64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    // Hardening #27 (2026-05-25): TTL + jti en el formSig.
    //   ts  → ventana de 15 min entre render del confirm y submit del finish.
    //         Sin esto, alguien que captura el form (logs HTTP de proxy, history
    //         de browser, screenshot) puede submitearlo en cualquier momento.
    //   jti → nonce one-use. Sin esto, el mismo form sumiteado 2 veces persiste
    //         la cuenta 2 veces (cada submit registra mapping + redirige al
    //         plugin que valida nonce WP — pero el central podría duplicar.).
    const ts  = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex');
    // Firma sobre el sextuple payload|return_to|nonce|ts|jti para evitar
    // tampering Y replay del form.
    const formSig = crypto.createHmac('sha256', HUB_SECRET)
        .update(payloadB64 + '|' + returnTo + '|' + nonce + '|' + ts + '|' + jti)
        .digest('base64');

    const warnings = [];
    // UX: avisar si la tienda ya está conectada a este site (registro previo en
    // tabla `accounts`). El flow sigue OK (es idempotente vía store_id), pero
    // avisamos para evitar la confusión "no me conectó la otra".
    if (alreadyConnected) {
        warnings.push('Esta tienda de TiendaNube <strong>ya está conectada en este sitio</strong>. Confirmar acá simplemente refresca el token de esta tienda (no duplica nada).');
    }

    const warningsHtml = warnings.length === 0 ? '' : `
        <div class="warnings">
            <strong>⚠ Atención antes de confirmar:</strong>
            <ul>${warnings.map(w => `<li>${w}</li>`).join('')}</ul>
        </div>
    `;

    return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Confirmá tu cuenta · Forger</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: linear-gradient(180deg,#f5f7fa 0%,#eef2f7 100%); color: #1f2937; padding: 20px; line-height: 1.55; min-height: 100vh; margin: 0; }
  .wrap { max-width: 680px; margin: 40px auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.06); overflow: hidden; }
  /* === Hero trío === */
  .hero { background: radial-gradient(circle at 25% 50%, rgba(33,117,191,0.06), transparent 45%), radial-gradient(circle at 75% 50%, rgba(255,230,0,0.10), transparent 45%), linear-gradient(180deg,#fafbfc 0%,#f3f4f6 100%); padding: 32px 24px 28px; border-bottom: 1px solid #e5e7eb; }
  .trio { display: grid; grid-template-columns: 1fr 80px 1.3fr 80px 1fr; align-items: center; justify-items: center; gap: 0; max-width: 560px; margin: 0 auto; }
  .side, .center { display: flex; flex-direction: column; align-items: center; gap: 8px; text-align: center; position: relative; }
  .ring { background: #fff; border-radius: 50%; width: 56px; height: 56px; display: inline-flex; align-items: center; justify-content: center; box-shadow: 0 4px 14px rgba(0,0,0,0.08), 0 1px 3px rgba(0,0,0,0.04); border: 1px solid rgba(0,0,0,0.04); position: relative; z-index: 1; }
  .ring img { max-width: 36px; max-height: 36px; object-fit: contain; }
  .ring.is-center { width: 76px; height: 76px; box-shadow: 0 8px 24px rgba(229,91,15,0.18), 0 2px 6px rgba(0,0,0,0.08); }
  .ring.is-center img { max-width: 52px; max-height: 52px; }
  .halo { position: absolute; top: 0; left: 50%; transform: translateX(-50%); width: 76px; height: 76px; border-radius: 50%; background: radial-gradient(circle, rgba(229,91,15,0.25) 0%, transparent 70%); animation: pulse 2.6s ease-in-out infinite; pointer-events: none; z-index: 0; }
  @keyframes pulse { 0%,100% { transform: translateX(-50%) scale(1); opacity: 0.7; } 50% { transform: translateX(-50%) scale(1.15); opacity: 0.3; } }
  .label { font-size: 11px; color: #4b5563; line-height: 1.3; font-weight: 500; }
  .label.is-center { font-size: 12px; }
  .label.is-center strong { color: #E55B0F; font-weight: 700; font-size: 13px; }
  .label.is-center span { color: #6b7280; font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; }
  .connector { position: relative; width: 100%; height: 18px; display: flex; align-items: center; }
  .line { width: 100%; height: 2px; background: linear-gradient(90deg,transparent 0%,#cbd5e1 15%,#cbd5e1 85%,transparent 100%); border-radius: 999px; }
  .dot { position: absolute; top: 50%; left: 0; width: 6px; height: 6px; border-radius: 50%; background: #E55B0F; transform: translateY(-50%); box-shadow: 0 0 8px rgba(229,91,15,0.6); animation: flow 2.4s linear infinite; }
  .dot.d2 { animation-delay: 0.8s; } .dot.d3 { animation-delay: 1.6s; }
  @keyframes flow { 0% { left: -6px; opacity: 0; transform: translateY(-50%) scale(0.5); } 10% { opacity: 1; transform: translateY(-50%) scale(1); } 90% { opacity: 1; transform: translateY(-50%) scale(1); } 100% { left: calc(100% + 6px); opacity: 0; transform: translateY(-50%) scale(0.5); } }
  /* === Body === */
  .body { padding: 26px 32px 28px; }
  h1 { margin: 0 0 6px; font-size: 20px; color: #111827; }
  .intro { color: #4b5563; font-size: 13.5px; margin: 0 0 18px; }
  .site-pill { display: inline-block; background: #eef2ff; color: #3730a3; padding: 3px 10px; border-radius: 6px; font-size: 12px; font-family: ui-monospace, Menlo, Consolas, monospace; margin-left: 4px; }
  .details { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 10px; padding: 4px 0; margin-bottom: 16px; }
  .row { display: flex; padding: 10px 16px; border-bottom: 1px solid #f3f4f6; }
  .row:last-child { border-bottom: 0; }
  .row .k { width: 130px; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; font-weight: 600; flex-shrink: 0; }
  .row .v { flex: 1; font-size: 13px; color: #111827; }
  .row .v code { background: #f3f4f6; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  .row .v.big { font-weight: 700; font-size: 15px; }
  .ok { color: #047857; }
  .err { color: #b91c1c; }
  .warnings { background: #fef3c7; border: 1px solid #fde68a; border-radius: 10px; padding: 12px 16px; margin-bottom: 18px; color: #78350f; font-size: 12.5px; }
  .warnings strong { display: block; margin-bottom: 6px; }
  .warnings ul { margin: 0; padding-left: 18px; }
  .warnings li { margin: 4px 0; line-height: 1.45; }
  .actions { display: flex; gap: 12px; justify-content: flex-end; }
  .btn { padding: 10px 18px; border-radius: 8px; border: 1px solid; font-size: 14px; font-weight: 600; cursor: pointer; font-family: inherit; transition: all 0.15s; }
  .btn-primary { background: #E55B0F; border-color: #E55B0F; color: #fff; }
  .btn-primary:hover { background: #c44a08; border-color: #c44a08; }
  .btn-secondary { background: #fff; border-color: #d1d5db; color: #374151; }
  .btn-secondary:hover { background: #f9fafb; border-color: #9ca3af; }
  .hint { margin: 18px 0 0; font-size: 11.5px; color: #9ca3af; text-align: center; line-height: 1.5; }
  @media (max-width: 560px) {
      .trio { grid-template-columns: 1fr 30px 1.3fr 30px 1fr; }
      .row { flex-direction: column; gap: 4px; }
      .row .k { width: auto; }
      .actions { flex-direction: column-reverse; }
      .btn { width: 100%; }
  }
</style>
</head><body>
<div class="wrap">
    <div class="hero">
        <div class="trio">
            <div class="side">
                <div class="ring"><img src="https://s.w.org/style/images/about/WordPress-logotype-wmark.png" alt="WordPress" /></div>
                <span class="label">Tu tienda<br>WooCommerce</span>
            </div>
            <div class="connector" aria-hidden="true">
                <span class="line"></span><span class="dot"></span><span class="dot d2"></span><span class="dot d3"></span>
            </div>
            <div class="center">
                <div class="halo" aria-hidden="true"></div>
                <div class="ring is-center"><img src="https://forger.com.ar/forger-logo.png" alt="Forger" onerror="this.style.display='none'" /></div>
                <span class="label is-center"><strong>Forger</strong><br><span>Capa de integración</span></span>
            </div>
            <div class="connector" aria-hidden="true">
                <span class="line"></span><span class="dot"></span><span class="dot d2"></span><span class="dot d3"></span>
            </div>
            <div class="side">
                <div class="ring"><svg width="34" height="34" viewBox="0 0 16 16" fill="#2C3357" xmlns="http://www.w3.org/2000/svg" aria-label="TiendaNube"><path d="M10.25 2.24a5.79 5.79 0 0 0-4 1.63 4.48 4.48 0 1 0 0 8.26 5.76 5.76 0 1 0 4-9.89zm0 10.24A4.49 4.49 0 0 1 5.76 8H4.48a5.74 5.74 0 0 0 .89 3.07 3.29 3.29 0 0 1-.88.13 3.2 3.2 0 0 1 0-6.4A3.2 3.2 0 0 1 7.69 8H9a4.42 4.42 0 0 0-1.63-3.43 4.48 4.48 0 1 1 2.88 7.91z"/></svg></div>
                <span class="label">Tu tienda<br>en TiendaNube</span>
            </div>
        </div>
    </div>
    <div class="body">
        <h1>Confirmá tu tienda TiendaNube</h1>
        <p class="intro">Estos son los datos de la cuenta que vamos a enviar a tu sitio
            <span class="site-pill">${escapeHtml(siteUrl || 'tu WordPress')}</span>.
            <strong>Antes de guardarlos</strong>, revisá que sea la cuenta correcta — la sesión activa en este browser puede no ser la que querés conectar.</p>

        <div class="details">
            <div class="row"><span class="k">Tienda</span><span class="v big">${escapeHtml(payload.store_name || '—')}</span></div>
            <div class="row"><span class="k">Email</span><span class="v">${escapeHtml(payload.email || '—')}</span></div>
            <div class="row"><span class="k">Idioma</span><span class="v">${payload.store_lang ? `<code>${escapeHtml(payload.store_lang)}</code>` : '—'}</span></div>
            <div class="row"><span class="k">Store ID</span><span class="v"><code>${payload.store_id}</code></span></div>
            <div class="row"><span class="k">access_token</span><span class="v"><span class="ok">✓ recibido (${String(payload.access_token).length} chars)</span> · no expira</span></div>
            <div class="row"><span class="k">scope</span><span class="v">${payload.scope ? `<code>${escapeHtml(payload.scope)}</code>` : '—'}</span></div>
        </div>

        ${warningsHtml}

        <form method="POST" action="/connect-tn/finish" class="actions">
            <input type="hidden" name="payload" value="${escapeHtml(payloadB64)}" />
            <input type="hidden" name="return_to" value="${escapeHtml(returnTo)}" />
            <input type="hidden" name="nonce" value="${escapeHtml(nonce)}" />
            <input type="hidden" name="ts" value="${ts}" />
            <input type="hidden" name="jti" value="${jti}" />
            <input type="hidden" name="form_sig" value="${escapeHtml(formSig)}" />
            <button type="submit" name="decision" value="cancel" class="btn btn-secondary">Cancelar (usar otra cuenta)</button>
            <button type="submit" name="decision" value="confirm" class="btn btn-primary">Confirmar y conectar</button>
        </form>

        <p class="hint">Si esta no es la tienda correcta: cancelá, cerrá sesión en tiendanube.com o cambiá de cuenta en el browser, y volvé a iniciar la conexión desde tu sitio.</p>
    </div>
</div>
<p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:24px;">forger-connect-tn · OAuth bridge</p>
</body></html>`;
}

// ============================================================================
// API v1 — Central Orchestrator
// Endpoints /v1/* para que los plugins clientes orquesten jobs (sync, push, etc.)
// vía el central. Auth con HMAC shared-secret por cuenta (ver routes-v1.js).
// ============================================================================
mountV1(app, {
    hubSecret: HUB_SECRET,
    rlGeneral:   limitV1General,
    rlHandshake: limitV1Handshake,
});

// ============================================================================
// GET /healthz — liveness check para el reverse proxy.
// Registrado en ambas formas porque algunos reverse proxies no strippean el
// path prefix del dominio (https://example/connect-tn/healthz puede llegar al
// container literal como /connect-tn/healthz).
// Si la DB no es accesible, devolvemos { ok: false, db: false } pero status
// 200 para no romper el healthcheck del proxy: el OAuth bridge sigue
// funcionando aunque la DB esté caída.
// ============================================================================
app.get(['/healthz', '/connect-tn/healthz'], async (req, res) => {
    let dbOk = false;
    try { dbOk = await dbPing(); } catch (_) { dbOk = false; }
    res.json({ ok: true, db: dbOk, ts: Date.now() });
});

// ============================================================================
// GET /version — qué build está corriendo. Útil para verificar que un deploy
// haya tomado efecto sin tener que entrar al container.
// ============================================================================
app.get(['/version', '/connect-tn/version'], (req, res) => {
    res.json({
        ok: true,
        version: PKG_VERSION,
        started_at: STARTED_AT,
        ts: Date.now(),
    });
});

// ============================================================================
// GET /mappings/count — diagnóstico simple para verificar que los mappings
// store_id → site_url se están persistiendo (sin exponer URLs sensibles).
// ============================================================================
app.get(['/mappings/count', '/connect-tn/mappings/count'], (req, res) => {
    const map = loadMappings();
    const keys = Object.keys(map);
    res.json({
        ok:           true,
        count:        keys.length,
        user_ids:     keys,
        data_dir:     DATA_DIR,
        data_dir_writable: (() => {
            try { fs.accessSync(DATA_DIR, fs.constants.W_OK); return true; } catch (_) { return false; }
        })(),
    });
});

// ============================================================================
// POST /internal/license-revoked — el license-api avisa que una licencia fue
// revocada antes de su exp natural. La sumamos a la denylist (memoria + DB) para
// que el enforcement la rechace de inmediato, ganándole a la gracia.
//
// Auth server-to-server UNIFICADA con connect-ml (paridad de seguridad):
//   HMAC-SHA256(rawBody, LICENSE_REVOKE_SECRET) en X-Wf-Revoke-Sig (HEX)
//   + X-Wf-Revoke-Ts (unix seconds, ±5min anti-replay) + nonce one-use
//   (request_nonces, purpose='license_revoke'). Secreto DEDICADO — NO reusa el
//   HUB_SECRET global. Sin firma válida → 401. Única forma de mutar la denylist.
//
// Body JSON: { license_id: string, nonce?: string, reason?: string }
// ============================================================================
app.post(['/internal/license-revoked', '/connect-tn/internal/license-revoked'], async (req, res) => {
    if (!LICENSE_REVOKE_SECRET) {
        // Sin secret no podemos autenticar — fail-closed para este endpoint.
        return res.status(503).json({ ok: false, error: 'revoke_disabled' });
    }
    const sigGiven = String(req.get('X-Wf-Revoke-Sig') || '');
    const tsGiven  = String(req.get('X-Wf-Revoke-Ts')  || '');
    const raw      = req.rawBody || '';
    if (!sigGiven || !tsGiven) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    // 1) HMAC sobre el body crudo (constant-time).
    let sigOk = false;
    try {
        const expected = crypto.createHmac('sha256', LICENSE_REVOKE_SECRET).update(raw, 'utf8').digest('hex');
        const a = Buffer.from(expected);
        const b = Buffer.from(sigGiven);
        sigOk = a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (_) { sigOk = false; }
    if (!sigOk) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    // 2) Ventana de timestamp ±5min.
    const tsNum = parseInt(tsGiven, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(tsNum) || Math.abs(nowSec - tsNum) > 300) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const licenseId = String((req.body && req.body.license_id) || '').trim();
    const reqNonce  = String((req.body && req.body.nonce) || '').trim();
    const reason    = (req.body && req.body.reason) ? String(req.body.reason) : null;
    if (!licenseId) {
        return res.status(400).json({ ok: false, error: 'missing_license_id' });
    }
    // 3) Nonce one-use (si vino).
    if (reqNonce) {
        try {
            const dup = await dbQuery(
                `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (nonce, purpose) DO NOTHING RETURNING nonce`,
                [reqNonce, 'license_revoke', nowSec]
            );
            if (dup.rowCount === 0) {
                return res.status(409).json({ ok: false, error: 'replay' });
            }
        } catch (e) {
            console.error('[license-revoked] nonce insert error:', e.message);
            return res.status(500).json({ ok: false, error: 'internal' });
        }
    }
    try {
        await addToDenylist(licenseId, reason);
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'persist_failed', message: e.message });
    }
    console.warn(`[license] revoke recibido license_id=${licenseId} reason=${reason || '-'}`);
    return res.json({ ok: true, revoked: licenseId });
});

// ============================================================================
// POST /internal/license-activated — ESPEJO EXACTO de /internal/license-revoked.
// El license-api avisa que una licencia fue DESBLOQUEADA (un-revoke): la sacamos
// de la denylist (memoria + DB) para que el enforcement vuelva a permitirla.
//
// El license-api manda este webhook desde syncLicenseBlockState() SOLO cuando la
// licencia NO debe estar bloqueada (status no bloqueante && is_blocked=false).
//
// Misma auth server-to-server que el revoke (paridad de seguridad):
//   HMAC-SHA256(rawBody, LICENSE_REVOKE_SECRET) en X-Wf-Revoke-Sig (HEX)
//   + X-Wf-Revoke-Ts (unix seconds, ±5min anti-replay) + nonce one-use
//   (request_nonces, purpose='license_activate'). Secreto DEDICADO compartido con
//   el revoke. Sin firma válida → 401.
//
// Body JSON: { license_id: string, nonce?: string, reason?: string }
// ============================================================================
app.post(['/internal/license-activated', '/connect-tn/internal/license-activated'], async (req, res) => {
    if (!LICENSE_REVOKE_SECRET) {
        // Sin secret no podemos autenticar — fail-closed para este endpoint.
        return res.status(503).json({ ok: false, error: 'revoke_disabled' });
    }
    const sigGiven = String(req.get('X-Wf-Revoke-Sig') || '');
    const tsGiven  = String(req.get('X-Wf-Revoke-Ts')  || '');
    const raw      = req.rawBody || '';
    if (!sigGiven || !tsGiven) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    // 1) HMAC sobre el body crudo (constant-time).
    let sigOk = false;
    try {
        const expected = crypto.createHmac('sha256', LICENSE_REVOKE_SECRET).update(raw, 'utf8').digest('hex');
        const a = Buffer.from(expected);
        const b = Buffer.from(sigGiven);
        sigOk = a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch (_) { sigOk = false; }
    if (!sigOk) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    // 2) Ventana de timestamp ±5min.
    const tsNum = parseInt(tsGiven, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(tsNum) || Math.abs(nowSec - tsNum) > 300) {
        return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    const licenseId = String((req.body && req.body.license_id) || '').trim();
    const reqNonce  = String((req.body && req.body.nonce) || '').trim();
    const reason    = (req.body && req.body.reason) ? String(req.body.reason) : null;
    if (!licenseId) {
        return res.status(400).json({ ok: false, error: 'missing_license_id' });
    }
    // 3) Nonce one-use (si vino). purpose distinto del revoke para que un nonce
    //    no sea reusable entre ambos webhooks.
    if (reqNonce) {
        try {
            const dup = await dbQuery(
                `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (nonce, purpose) DO NOTHING RETURNING nonce`,
                [reqNonce, 'license_activate', nowSec]
            );
            if (dup.rowCount === 0) {
                return res.status(409).json({ ok: false, error: 'replay' });
            }
        } catch (e) {
            console.error('[license-activated] nonce insert error:', e.message);
            return res.status(500).json({ ok: false, error: 'internal' });
        }
    }
    try {
        await removeFromDenylist(licenseId);
    } catch (e) {
        return res.status(500).json({ ok: false, error: 'persist_failed', message: e.message });
    }
    console.warn(`[license] activate recibido license_id=${licenseId} reason=${reason || '-'}`);
    return res.json({ ok: true, activated: licenseId });
});

// ============================================================================
// GET /connect-tn — inicio del flow. Recibe los params del cliente y redirige a ML.
//
//   site_url   identifica al cliente (solo informativo).
//   return_to  URL del admin del cliente donde devolver el resultado (típicamente
//              <site>/wp-admin/admin-post.php?action=wftn_oauth_callback).
//   nonce      anti-CSRF generado por el plugin del cliente.
// ============================================================================
app.get('/connect-tn', limitOauthStart, async (req, res) => {
    const { site_url = '', return_to = '', nonce = '', ts = '', sig = '' } = req.query;

    if (!return_to || !isValidReturnTo(String(return_to))) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido</h1>
            <p>El plugin del cliente debe enviar el parámetro <code>return_to</code> con una URL HTTP/HTTPS válida.</p>`
        ));
    }
    if (!site_url || !isValidReturnTo(String(site_url))) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ site_url inválido</h1>`
        ));
    }
    if (!nonce) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ nonce faltante</h1>
            <p>El plugin del cliente no envió el parámetro <code>nonce</code>.</p>`
        ));
    }

    // Hardening #22: return_to.origin DEBE matchear site_url.origin. Bloquea
    // open-redirect attacks (atacante manda link a víctima con return_to=evil.com).
    if (!returnToMatchesSiteUrl(String(return_to), String(site_url))) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Origen del return_to no coincide con el site_url</h1>
            <p>Por seguridad, este flow requiere que <code>return_to</code> sea del mismo origin que <code>site_url</code>.</p>`
        ));
    }

    // Hardening #22: verificar firma del plugin. Sin esto cualquiera puede
    // generar links de OAuth.
    const sigCheck = verifyStartSignature({ site_url, return_to, nonce, ts, sig });
    if (!sigCheck.ok) {
        return res.status(401).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Firma inválida (${escapeHtml(sigCheck.reason)})</h1>
            <p>El link de OAuth está corrupto o expirado. Volvé al plugin y reintentá la conexión.</p>`
        ));
    }

    // NOTA (fix 2026-05-30): el START NO consume el nonce como one-use. El plugin
    // manda un WP nonce (reutilizable dentro de su ventana ~12h), así que
    // consumirlo acá rompía el reintento legítimo del usuario ("Link ya usado" al
    // cerrar el popup y volver a clickear). La protección del start ya la dan:
    //   - firma HMAC + freshness del ts (±5min) en verifyStartSignature → anti-forja
    //     y anti-replay de links viejos capturados.
    //   - oauth_state one-use (se consume en el callback) → anti-replay del callback.
    //   - nonce one-use del lado del PLUGIN en su callback (hardening #29).
    // Iniciar el OAuth varias veces es inocuo: solo redirige a TiendaNube a loguear;
    // sin completar el callback no pasa nada.

    // Hardening #24: persistir state server-side. El state que va a ML es
    // solo un ID random opaco — el server lookup el contexto en callback.
    let stateId;
    try {
        stateId = await createOAuthState({
            site_url: String(site_url),
            return_to: String(return_to),
            nonce: String(nonce),
        });
    } catch (e) {
        console.error('[connect-tn] state create error:', e.message);
        return res.status(500).type('html').send(htmlPage('Error', `<h1 class="err">⚠ Error creando state</h1>`));
    }

    // TiendaNube: el authorize lleva el app_id (= client_id) en el PATH; el
    // redirect_uri está fijado en el panel del partner, no se manda como query.
    const authUrl = new URL(`${TN_OAUTH_BASE}/apps/${encodeURIComponent(TN_CLIENT_ID)}/authorize`);
    authUrl.searchParams.set('state', stateId);

    res.redirect(302, authUrl.toString());
});

// ============================================================================
// GET /connect-tn/callback — vuelve del flow de ML con ?code= y ?state=.
//
// 1. Decodifica state → recupera return_to + nonce.
// 2. Intercambia code por access_token + refresh_token + user_id (POST a ML).
// 3. Pide /users/me para nickname + email + site_id.
// 4. Arma payload, lo firma con HMAC, redirige al return_to del cliente.
// ============================================================================
app.get('/connect-tn/oauth/callback', limitOauthCallback, async (req, res) => {
    const { code, state, error, error_description } = req.query;

    if (error) {
        return res.status(400).type('html').send(htmlPage('Acceso denegado',
            `<h1 class="err">⚠ ${escapeHtml(String(error))}</h1>
            <p>${escapeHtml(String(error_description || 'TiendaNube rechazó la solicitud.'))}</p>
            <p>Cerrá esta ventana y volvé a intentar desde el plugin.</p>`
        ));
    }
    if (!code || !state) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Callback inválido</h1>
            <p>Faltó <code>code</code> o <code>state</code> en la respuesta de ML.</p>`
        ));
    }

    // Hardening #24: consumir el state server-side. Si no existe, ya se usó,
    // o expiró → rechazar. Esto cierra el vector de "atacante precomputa
    // /callback?code=...&state=..." sin pasar por /connect-tn.
    let stateRow;
    try {
        stateRow = await consumeOAuthState(String(state));
    } catch (e) {
        console.error('[callback] state lookup error:', e.message);
        return res.status(500).type('html').send(htmlPage('Error', `<h1 class="err">⚠ Error verificando state</h1>`));
    }
    if (!stateRow) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ State inválido, expirado o ya usado</h1>
            <p>El flow de conexión expiró o ya fue completado. Volvé al plugin y reintentá.</p>`
        ));
    }
    const return_to = stateRow.return_to;
    const nonce     = stateRow.nonce;
    const site_url  = stateRow.site_url;
    // Defense in depth: re-validar return_to (por si alguien manipuló DB).
    if (!return_to || !isValidReturnTo(return_to) || !returnToMatchesSiteUrl(return_to, site_url)) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido en state persistido</h1>`
        ));
    }

    // 1) Intercambiar code → tokens.
    let tokenData;
    try {
        const resp = await fetch(`${TN_OAUTH_BASE}/apps/authorize/token`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                client_id:     TN_CLIENT_ID,
                client_secret: TN_CLIENT_SECRET,
                grant_type:    'authorization_code',
                code:          String(code),
            }).toString(),
        });
        tokenData = await resp.json();
        if (!resp.ok) {
            console.error('[oauth/token] error', resp.status, redactSecrets(tokenData));
            return res.status(502).type('html').send(htmlPage('Error',
                `<h1 class="err">⚠ TiendaNube rechazó el code</h1>
                <p><code>${escapeHtml((tokenData && tokenData.message) || resp.status)}</code></p>
                <p>Esto normalmente significa que el code ya se usó o expiró. Reintentá desde el plugin.</p>`
            ));
        }
    } catch (e) {
        console.error('[oauth/token] transport', e.message);
        return res.status(502).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ No pudimos contactar a TiendaNube</h1>
            <p>Reintentá en unos minutos.</p>`
        ));
    }

    // 2) Pedir GET /store para datos de la tienda (nombre, email, idioma). El
    //    store_id es el user_id que vino en la respuesta del token exchange.
    const storeId = Number(tokenData.user_id || 0);
    let store = {};
    try {
        const r = await fetch(`${TN_API_BASE}/${TN_API_VERSION}/${storeId}/store`, {
            headers: {
                'Accept': 'application/json',
                'Authentication': 'bearer ' + tokenData.access_token,
                'User-Agent': TN_USER_AGENT,
            },
        });
        if (r.ok) store = await r.json();
    } catch (e) {
        // No fatal — si falla, igual mandamos lo del token (store_id ya lo tenemos).
        console.warn('[store] no se pudo enriquecer:', e.message);
    }

    // 3) Armar payload normalizado para el plugin. TN: el token NO expira y NO
    //    hay refresh_token. El nombre de la tienda es i18n (objeto { es, pt }).
    const storeName = (store && store.name)
        ? (typeof store.name === 'object'
            ? (store.name.es || store.name.pt || Object.values(store.name).find(Boolean) || '')
            : store.name)
        : '';
    const payload = {
        store_id:     storeId,
        store_name:   String(storeName || ''),
        email:        String((store && store.email) || ''),
        store_lang:   String((store && (store.language || store.main_language)) || ''),
        access_token: String(tokenData.access_token || ''),
        scope:        String(tokenData.scope || ''),
    };
    if (!payload.store_id || !payload.access_token) {
        return res.status(502).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Respuesta inesperada de TiendaNube</h1>
            <p>Faltan campos críticos en el payload (user_id / access_token).</p>`
        ));
    }

    // 4) Detectar si esta cuenta ML (store_id + site_url) ya está conectada en
    //    este sitio. Si sí, el confirmation muestra un warning explícito (#31).
    let alreadyConnected = false;
    try {
        const exists = await dbQuery(
            `SELECT 1 FROM accounts
             WHERE store_id = $1 AND site_url = $2 AND revoked_at IS NULL
             LIMIT 1`,
            [Number(payload.store_id) || 0, String(site_url || '')]
        );
        alreadyConnected = exists.rowCount > 0;
    } catch (e) {
        console.warn('[callback] alreadyConnected check failed:', e.message);
    }

    // 5) En lugar de redirigir directo al plugin, mostramos pantalla de confirmación
    //    para que el usuario verifique que la cuenta sea la correcta antes de que
    //    sus tokens lleguen a su WordPress. El form postea a /connect-tn/finish con
    //    los datos firmados; ahí se decide redirect o cancel.
    res.type('html').send(confirmationPage({
        payload,
        returnTo: return_to,
        nonce: String(nonce),
        siteUrl: String(site_url || ''),
        alreadyConnected,
    }));
});

// ============================================================================
// POST /connect-tn/finish — el usuario confirmó o canceló la pantalla pre-handoff.
//
// Valida la firma del form (HMAC sobre payload|return_to|nonce) y según `decision`:
//   - confirm: firma el payload con HUB_SECRET y redirige al return_to del plugin.
//   - cancel:  redirige al return_to con ?wftn_cancel=1 (plugin muestra notice).
// ============================================================================
app.post(['/connect-tn/finish', '/finish'], limitFinishRefresh, async (req, res) => {
    const payloadB64 = String((req.body && req.body.payload)    || '');
    const returnTo   = String((req.body && req.body.return_to)  || '');
    const nonce      = String((req.body && req.body.nonce)      || '');
    const ts         = String((req.body && req.body.ts)         || '');
    const jti        = String((req.body && req.body.jti)        || '');
    const formSig    = String((req.body && req.body.form_sig)   || '');
    const decision   = String((req.body && req.body.decision)   || '');

    if (!payloadB64 || !returnTo || !nonce || !formSig || !ts || !jti) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Form incompleto</h1>
            <p>Faltan campos en el formulario de confirmación. Cerrá esta ventana y reintentá desde tu sitio.</p>`
        ));
    }
    if (!isValidReturnTo(returnTo)) {
        return res.status(400).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ return_to inválido</h1>`
        ));
    }

    // Validar firma del form (anti-tampering). Cubre payload + return_to + nonce
    // + ts + jti — cualquier mutación rompe la firma.
    const expectedSig = crypto.createHmac('sha256', HUB_SECRET)
        .update(payloadB64 + '|' + returnTo + '|' + nonce + '|' + ts + '|' + jti)
        .digest('base64');
    const expectedBuf = Buffer.from(expectedSig);
    const receivedBuf = Buffer.from(formSig);
    if (expectedBuf.length !== receivedBuf.length ||
        !crypto.timingSafeEqual(expectedBuf, receivedBuf)) {
        return res.status(403).type('html').send(htmlPage('Error',
            `<h1 class="err">⚠ Firma inválida</h1>
            <p>El formulario fue manipulado o el shared secret cambió. Reintentá desde tu sitio.</p>`
        ));
    }

    // Hardening #27 (2026-05-25): TTL del handoff. 15 min entre el render de la
    // confirmación y el submit. El user tiene tiempo razonable para pensar; un
    // form capturado expira y no se puede submitear más tarde.
    const tsNum = parseInt(ts, 10);
    const nowSec = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(tsNum) || Math.abs(nowSec - tsNum) > 15 * 60) {
        return res.status(403).type('html').send(htmlPage('Expirado',
            `<h1 class="err">⚠ Confirmación expirada</h1>
            <p>Pasaron más de 15 minutos desde que abriste esta pantalla. Por seguridad, volvé al plugin y reintentá la conexión.</p>`
        ));
    }

    // Hardening #27: jti one-use. Si el mismo form se submitea 2 veces (back del
    // browser, doble click, replay del atacante), el segundo es rechazado.
    // Solo lo consumimos si confirm (cancel no tiene side-effects que prevenir).
    if (decision !== 'cancel') {
        const jtiCheck = await checkAndConsumeNonce(jti, 'handoff');
        if (!jtiCheck.ok) {
            return res.status(409).type('html').send(htmlPage('Ya usado',
                `<h1 class="err">⚠ Confirmación ya procesada</h1>
                <p>Esta confirmación ya se procesó antes. Si tu cuenta no quedó conectada, volvé al plugin y reintentá.</p>`
            ));
        }
    }

    // Decisión del usuario.
    if (decision === 'cancel') {
        // Volvemos al plugin con un flag de cancelación — sin payload ni firma.
        const cancelUrl = new URL(returnTo);
        cancelUrl.searchParams.set('nonce', nonce);
        cancelUrl.searchParams.set('wftn_cancel', '1');
        return res.type('html').send(htmlPage('Cancelado', `
            <h1>Conexión cancelada</h1>
            <p>No se guardó ninguna cuenta en tu sitio.</p>
            <p style="margin-top:14px;"><a href="${escapeHtml(cancelUrl.toString())}">Volver al panel del plugin</a></p>
            <script>setTimeout(function(){ window.location.href = ${JSON.stringify(cancelUrl.toString())}; }, 1500);</script>
        `));
    }

    // Confirmar: re-firmamos el payload con el HMAC standard que espera el plugin.
    const signature = hmac(payloadB64);

    // Registrar mapping store_id → site_url (WP root) para forward de webhooks.
    // El site_url debe incluir el path donde vive WP (puede estar en subcarpeta
    // tipo /wordpress/). Lo derivamos del returnTo cortando antes de /wp-admin/.
    try {
        const decoded = JSON.parse(Buffer.from(payloadB64, 'base64').toString('utf8'));
        const siteRoot = deriveSiteRootFromReturnTo(returnTo);
        if (decoded.store_id && siteRoot) {
            registerMapping(decoded.store_id, siteRoot);
        }
    } catch (e) {
        console.warn('[finish] register mapping failed:', e.message);
    }

    // Hardening #28 (2026-05-25): POST self-submit en vez de redirect GET. Antes
    // los tokens viajaban en la query string del redirect (?payload=BASE64&signature=...)
    // y quedaban en:
    //   - logs del web server del cliente (access.log)
    //   - history del browser
    //   - Referer headers si la página del plugin redirigía
    //   - bookmarks accidentales
    // Con POST self-submit los tokens van en el body, no en la URL. La URL del
    // browser termina siendo solo /wp-admin/admin-post.php (sin params sensibles).
    // El form se auto-submitea con JS; si JS está deshabilitado hay un botón
    // fallback manual.
    const escAttr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    // El returnTo viene como /wp-admin/admin-post.php?action=wftn_oauth_callback
    // Strippeamos el query string para que la URL del browser no muestre nada
    // sospechoso al inspeccionar; el `action` lo mandamos en el body (mismo
    // dispatch en WordPress, sin duplicación visible).
    const returnUrl = new URL(returnTo);
    returnUrl.search = '';
    const formAction = escAttr(returnUrl.toString());
    res.type('html').send(`<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Conectando · Forger</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f8fafc; color: #1f2937; padding: 40px 20px; line-height: 1.55; text-align: center; }
  .wrap { max-width: 480px; margin: 80px auto; background: #fff; border: 1px solid #e5e7eb; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.05); padding: 32px 40px; }
  h1 { color: #16a34a; font-size: 22px; margin: 0 0 10px; }
  .spin { display: inline-block; width: 28px; height: 28px; border: 3px solid #e5e7eb; border-top-color: #16a34a; border-radius: 50%; animation: s 0.8s linear infinite; margin: 18px 0; }
  @keyframes s { to { transform: rotate(360deg); } }
  .fallback-btn { display: inline-block; margin-top: 14px; padding: 10px 20px; background: #1a73e8; color: #fff; border: none; border-radius: 8px; font-size: 14px; cursor: pointer; }
</style>
</head><body>
<div class="wrap">
  <h1>✓ Listo, conectando tu cuenta...</h1>
  <div class="spin"></div>
  <p>Volviendo a tu panel Forger con las credenciales validadas.</p>
  <form id="wftnHandoff" method="POST" action="${formAction}">
    <input type="hidden" name="action" value="wftn_oauth_callback">
    <input type="hidden" name="nonce" value="${escAttr(nonce)}">
    <input type="hidden" name="payload" value="${escAttr(payloadB64)}">
    <input type="hidden" name="signature" value="${escAttr(signature)}">
    <noscript>
      <p style="margin-top:14px;font-size:13px;color:#6b7280;">JavaScript está desactivado.</p>
      <button type="submit" class="fallback-btn">Continuar manualmente</button>
    </noscript>
  </form>
  <script>setTimeout(function(){ document.getElementById('wftnHandoff').submit(); }, 700);</script>
</div>
</body></html>`);
});

// ============================================================================
// POST /refresh-token — refresh del access_token usando el refresh_token.
//
// Endpoint llamado por los plugins WF cuando reciben 401 de ML.
//
// Body esperado (form-urlencoded o JSON):
//   refresh_token  el refresh token actual (largo TG-xxxxxx).
//   payload_sig    HMAC-SHA256(refresh_token, WFTN_OAUTH_HUB_SECRET) en base64.
//
// Validamos firma para evitar que cualquiera llame a refresh con un refresh
// token robado: el solicitante tiene que conocer el shared secret.
//
// Respuesta (JSON):
//   { ok: true,  payload: <base64>, signature: <base64> }   — payload tiene los tokens nuevos
//   { ok: false, error: <string> }
// ============================================================================
app.post(['/refresh-token', '/connect-tn/refresh-token'], limitFinishRefresh, (req, res) => {
    // TiendaNube: los access_token NO expiran y NO hay refresh_token. Este
    // endpoint existe solo por compatibilidad de ruta con el contrato del bridge
    // de ML; nunca debería llamarse desde el plugin de TiendaNube. Responde 200
    // con ok:false para que cualquier cliente legacy lo maneje con gracia.
    return res.status(200).json({
        ok: false,
        error: 'tiendanube access tokens do not expire; no refresh available',
    });
});

// ============================================================================
// POST /connect-tn/webhooks — receptor de webhooks de TiendaNube.
//
// Modelo pull (no forward): TN manda un payload "thin" { store_id, event, id };
// el central NO reenvía al WordPress del cliente (eso exigiría que el WP sea
// públicamente accesible — muchos no lo son). En su lugar:
//
//   1. Verifica el HMAC del webhook (x-linkedstore-hmac-sha256 = HMAC-SHA256 del
//      body crudo con el client_secret, en hex).
//   2. Identifica la cuenta por store_id.
//   3. Según el evento: product/* → webhook_events, order/* → order_events,
//      app/uninstalled|suspended → revoca la cuenta.
//
// El debouncer del scheduler agrupa los product/* por cuenta y encola un job
// sync_incremental; el ledger procesa los order/*. El plugin baja el resultado
// en su próximo poll. Así el tiempo real funciona aunque el WP del cliente no
// sea alcanzable desde fuera.
//
// TN reintenta si no respondemos 2xx rápido: respondemos ANTES de procesar.
// ============================================================================
// Defensa en capas del endpoint público de webhooks:
//   1. Rate limit por IP (limitWebhooks). Frena floods.
//   2. HMAC: TN firma cada webhook con HMAC-SHA256(rawBody, client_secret) en hex,
//      en el header x-linkedstore-hmac-sha256. Verificamos timing-safe; mismatch
//      → descarte (nadie sin el client_secret puede inyectar eventos).
//   3. store_id DEBE estar registrado en accounts. Si no, descarte temprano.
//   4. Idempotencia por (store_id, event, id) TTL 1h en memoria. Incluir el
//      evento permite que transiciones de estado de una orden NO se dedupliquen
//      entre sí, pero sí los reintentos idénticos de TN.
const WEBHOOK_SEEN_TTL_MS = 60 * 60_000; // 1h
const webhookSeen = new Map(); // "store_id:event:id" → expiresAt (ms)
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of webhookSeen.entries()) {
        if (v < now) webhookSeen.delete(k);
    }
}, 5 * 60_000).unref();

app.post(['/connect-tn/webhooks', '/webhooks'], limitWebhooks, (req, res) => {
    // 1. Responder 200 INMEDIATO. TN reintenta si tarda o status != 2xx.
    res.status(200).json({ ok: true });

    // 2. Verificar HMAC sobre el body CRUDO con el client_secret de la app.
    const raw = req.rawBody || '';
    const sigHeader = String(req.get('x-linkedstore-hmac-sha256') || '');
    if (!raw || !sigHeader || !TN_CLIENT_SECRET) {
        return; // sin firma o sin secret → no confiamos; descartar.
    }
    const expected = crypto.createHmac('sha256', TN_CLIENT_SECRET).update(raw, 'utf8').digest('hex');
    const a = Buffer.from(expected);
    const b = Buffer.from(sigHeader);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        console.warn('[webhook] HMAC inválido — descartado');
        return;
    }

    // 3. Procesar fire-and-forget. Payload "thin" de TN: { store_id, event, id }.
    const body    = req.body || {};
    const storeId = body.store_id ? String(body.store_id) : '';
    const event   = String(body.event || '');
    const resId   = body.id != null ? String(body.id) : '';

    if (!storeId || !event) return;

    // Idempotencia por (store_id, event, id).
    const seenKey = `${storeId}:${event}:${resId}`;
    if (webhookSeen.has(seenKey)) return; // retry idéntico de TN — todo OK.
    webhookSeen.set(seenKey, Date.now() + WEBHOOK_SEEN_TTL_MS);

    const isProduct   = event.startsWith('product/');
    const isOrder     = event.startsWith('order/');
    const isUninstall = event === 'app/uninstalled' || event === 'app/suspended';
    if (!isProduct && !isOrder && !isUninstall) {
        return; // category, customer, etc. — fuera del scope actual.
    }
    if ((isProduct || isOrder) && !resId) return;

    (async () => {
        try {
            const acc = await dbQuery(
                `SELECT id FROM accounts WHERE store_id = $1 AND revoked_at IS NULL LIMIT 1`,
                [Number(storeId)]
            );
            if (!acc.rowCount) return; // tienda no registrada en este central.
            const accountId = acc.rows[0].id;

            if (isUninstall) {
                // La app fue desinstalada/suspendida: el token deja de ser válido.
                await dbQuery(
                    `UPDATE accounts SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`,
                    [accountId]
                );
                console.warn(`[webhook] ${event} — cuenta ${accountId} (store ${storeId}) revocada`);
                return;
            }
            if (isProduct) {
                await dbQuery(
                    `INSERT INTO webhook_events (account_id, tn_product_id, topic)
                     VALUES ($1, $2, $3)`,
                    [accountId, resId, event]
                );
            } else {
                await dbQuery(
                    `INSERT INTO order_events (account_id, tn_order_id)
                     VALUES ($1, $2)`,
                    [accountId, resId]
                );
            }
        } catch (e) {
            console.error('[webhook] enqueue error:', e.message);
        }
    })();
});

// ============================================================================
// GET / — pequeña landing informativa
// ============================================================================
app.get('/', (req, res) => {
    res.type('html').send(htmlPage('Forger Connect TiendaNube',
        `<h1>Forger · Connect TiendaNube</h1>
        <p>Microservicio OAuth bridge para clientes Forger TiendaNube.</p>
        <p>Si llegaste acá por error: este endpoint solo lo usan los plugins Forger instalados en tu WordPress.</p>
        <p><a href="https://forger.com.ar">forger.com.ar</a></p>`
    ));
});

// 404 fallback.
app.use((req, res) => {
    res.status(404).type('html').send(htmlPage('Not found',
        `<h1 class="err">404</h1><p>Ruta no encontrada.</p>`
    ));
});

// ============================================================================
// Util: escape HTML para inyectar valores en templates
// ============================================================================
function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

app.listen(PORT, () => {
    console.log(`[forger-connect-tn] listening on :${PORT}`);
    console.log(`[forger-connect-tn] BASE_URL = ${BASE_URL}`);
    console.log(`[forger-connect-tn] CALLBACK_URL = ${CALLBACK_URL}`);
    // Estado del enforcement de licencia (Fase 6). 'observe' es el default y NO
    // bloquea; 'off' (o pública faltante) tampoco. Solo 'enforce' + pública corta.
    const lic = licenseConfig();
    console.log(`[forger-connect-tn] LICENSE_ENFORCE = ${lic.mode} (active=${lic.active}, enforcing=${lic.enforcing}, pubkey=${lic.hasPublicKey}, grace=${lic.graceSec}s)`);
    // Cargar la denylist desde DB + refrescar cada 5 min (revokes entre réplicas
    // / persistidos sobreviven reinicios). Best-effort: si la DB no está, el
    // refresh siguiente la levanta.
    refreshDenylist().catch(() => {});
    setInterval(() => { refreshDenylist().catch(() => {}); }, 5 * 60 * 1000).unref();
    // Arranca el worker del Central Orchestrator (procesa jobs de sync).
    // Si la DB no está disponible, el worker logguea el error y reintenta
    // en el próximo tick — no tumba el proceso.
    startWorker();
    // Arranca el scheduler — encola jobs de sync automático periódicamente.
    startScheduler();
    // Cleanup periódico de oauth_states + nonces vencidos. Cada 10 min.
    cleanupOAuthStates().catch(() => {});
    setInterval(() => { cleanupOAuthStates().catch(() => {}); }, 10 * 60 * 1000);
});
