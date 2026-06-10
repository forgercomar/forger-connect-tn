/**
 * forger-connect-tn — Verificación del capability-token de licencia (Fase 6).
 *
 * GEMELO de forger-connect-ml/license-token.js — este módulo es AGNÓSTICO de
 * ML/TN: solo verifica la firma Ed25519 y los claims del token. La única
 * diferencia entre repos es quién lo invoca (header + expectProduct), no este
 * archivo. Mantener en sync byte-a-byte con el de ML salvo este encabezado.
 *
 * El license-api (api.goforger.com) emite tokens WFCAP1.<payload_b64url>.<sig_b64url>
 * firmados Ed25519. Este módulo los verifica con la pública del license-api para
 * decidir si una cuenta tiene licencia VIGENTE antes de servir sync/push/refresh.
 *
 * PURO: solo node:crypto, sin estado, sin deps. La denylist (revoke) y el binding
 * de cuenta/dominio los pasa el caller (routes-v1.js) desde la DB/contexto.
 *
 * Se firma la CADENA payload_b64url (no el JSON) → verificamos sobre la misma
 * cadena recibida, sin re-serializar (cero riesgo de canonicalización cross-runtime).
 *
 * Doc: docs/PHASE6_CAPABILITY_TOKEN.md
 */
import { verify } from 'node:crypto';

/** Normaliza un host a eTLD+1 aproximado: lowercase, sin esquema/puerto/path, sin 'www.'. */
export function normalizeDomain(host) {
  if (!host || typeof host !== 'string') return '';
  let h = host.trim().toLowerCase();
  h = h.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (h.startsWith('www.')) h = h.slice(4);
  return h;
}

/**
 * Verifica un capability-token. Pura, NO lanza. Devuelve { valid, reason?, payload? }.
 *
 * @param {string} token
 * @param {object} opts
 * @param {import('node:crypto').KeyObject} opts.publicKey  pública Ed25519 del license-api (obligatoria)
 * @param {number}  [opts.now]            unix sec (default: ahora)
 * @param {number}  [opts.skewSec]        margen de reloj para exp (default 30)
 * @param {Set<string>} [opts.denylist]   set de license_id revocados
 * @param {string}  [opts.expectDomain]   si se pasa, exige que coincida con claim.domain (eTLD+1)
 * @param {string}  [opts.expectProduct]  si se pasa, exige que esté en claim.product_slugs
 */
export function verifyCapabilityToken(token, opts = {}) {
  const now = typeof opts.now === 'number' ? opts.now : Math.floor(Date.now() / 1000);
  const skew = typeof opts.skewSec === 'number' ? opts.skewSec : 30;
  const pub = opts.publicKey;
  if (!pub) return { valid: false, reason: 'no_pubkey' };
  if (typeof token !== 'string' || token.length < 16) return { valid: false, reason: 'no_token' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'WFCAP1') return { valid: false, reason: 'bad_format' };
  const payloadB64 = parts[1];
  const sigB64 = parts[2];
  let sigOk = false;
  try {
    sigOk = verify(null, Buffer.from(payloadB64, 'utf8'), pub, Buffer.from(sigB64, 'base64url'));
  } catch {
    return { valid: false, reason: 'bad_sig' };
  }
  if (!sigOk) return { valid: false, reason: 'bad_sig' };
  let payload;
  try {
    payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'bad_payload' };
  }
  const exp = typeof payload.exp === 'number' ? payload.exp : 0;
  if (!exp || now > exp + skew) return { valid: false, reason: 'expired', payload };
  const iat = typeof payload.iat === 'number' ? payload.iat : 0;
  if (iat && iat > now + 300) return { valid: false, reason: 'future', payload };
  if (opts.denylist && payload.license_id && opts.denylist.has(payload.license_id)) {
    return { valid: false, reason: 'revoked', payload };
  }
  if (opts.expectDomain) {
    const want = normalizeDomain(opts.expectDomain);
    const got = normalizeDomain(String(payload.domain || ''));
    if (want && got && want !== got) return { valid: false, reason: 'domain_mismatch', payload };
  }
  if (opts.expectProduct) {
    const slugs = Array.isArray(payload.product_slugs) ? payload.product_slugs : [];
    if (!slugs.includes(opts.expectProduct)) return { valid: false, reason: 'product_not_in_token', payload };
  }
  return { valid: true, payload };
}
