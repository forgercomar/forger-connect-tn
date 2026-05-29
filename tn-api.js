/**
 * tn-api.js — Cliente de la API de TiendaNube (Nuvemshop) para el worker del central.
 *
 * Diferencias clave con la API de MercadoLibre (ver docs/ARQUITECTURA.md):
 *   - Los access_token NO expiran y NO hay refresh_token. El token se guarda una
 *     vez (cifrado AES-256-GCM en accounts.access_token_enc) y se usa siempre.
 *     → No hay getValidAccessToken con margen de expiración ni retry-on-401.
 *   - Header de auth NO estándar: `Authentication: bearer <token>` (header
 *     `Authentication`, palabra `bearer` en minúscula). Equivocarse = 401.
 *   - User-Agent OBLIGATORIO identificando la app con un email de contacto.
 *   - Base URL versionada por fecha: https://api.tiendanube.com/2025-03/{store_id}/
 *   - Los productos se listan completos y paginados (GET /products?page=&per_page=),
 *     NO hay multi-get tipo /items?ids= de ML.
 *   - Stock por variante, con endpoints dedicados (POST /variants/stock con delta,
 *     y PATCH /products/stock-price masivo hasta 50 variantes).
 *   - Rate limit por leaky-bucket (40 + 2/s por tienda). Headers x-rate-limit-*.
 *   - IDs son enteros que pueden exceder int32 → tratarlos como bigint/string.
 *
 * @module tn-api
 */

import { decryptToken } from './auth.js';

const TN_API_BASE    = process.env.TN_API_BASE    || 'https://api.tiendanube.com';
const TN_API_VERSION = process.env.TN_API_VERSION || '2025-03';
const TN_USER_AGENT  = process.env.TN_USER_AGENT  || 'Forger (info@forger.com.ar)';

// TiendaNube: PATCH /products/stock-price acepta hasta 50 variantes por request.
export const TN_BULK_SIZE = 50;
// Paginado de /products. Máximo permitido por TN suele ser 200.
export const TN_PAGE_SIZE = Number(process.env.TN_PAGE_SIZE) || 200;

// ----------------------------------------------------------------------------
// Tokens (TN: el token no expira, solo desencriptar el guardado)
// ----------------------------------------------------------------------------

/**
 * Devuelve el access_token de la cuenta. En TiendaNube el token no expira, así
 * que simplemente lo desencripta. Se mantiene el nombre genérico para paridad
 * con el contrato del worker.
 *
 * @param {object} account fila de la tabla accounts
 * @returns {Promise<string>} access_token
 * @throws si no hay token utilizable
 */
export async function getValidAccessToken(account) {
    const token = decryptToken(account.access_token_enc, account.access_token_iv);
    if (!token) {
        throw new Error(`account ${account.public_id}: sin access_token utilizable`);
    }
    return token;
}

// ----------------------------------------------------------------------------
// HTTP base
// ----------------------------------------------------------------------------

/**
 * Arma la URL absoluta de la API para esta cuenta:
 *   {base}/{version}/{store_id}{path}
 */
function apiUrl(account, path) {
    if (path.startsWith('http')) return path;
    return `${TN_API_BASE}/${TN_API_VERSION}/${account.store_id}${path}`;
}

/**
 * Headers de autenticación de TiendaNube. OJO: header `Authentication` (no
 * `Authorization`) y `bearer` en minúscula, más User-Agent obligatorio.
 */
function authHeaders(accessToken, extra = {}) {
    return {
        'Accept': 'application/json',
        'Authentication': `bearer ${accessToken}`,
        'User-Agent': TN_USER_AGENT,
        ...extra,
    };
}

/**
 * Extrae los headers de rate-limit de una respuesta para que el worker pueda
 * throttlear. x-rate-limit-reset viene en milisegundos.
 */
function rateInfo(resp) {
    const num = (h) => {
        const v = resp.headers.get(h);
        return v == null ? null : Number(v);
    };
    return {
        limit:     num('x-rate-limit-limit'),
        remaining: num('x-rate-limit-remaining'),
        resetMs:   num('x-rate-limit-reset'),
    };
}

/**
 * Request genérico a la API de TN. Devuelve { ok, status, data, raw, rate }.
 * NO reintenta on-401 (en TN un 401 significa token revocado/app desinstalada,
 * no expiración — reintentar no ayuda). El 429 se reporta para que el worker
 * haga back-off con rate.resetMs.
 */
export async function tnRequest(account, method, path, accessToken, body = null) {
    const url = apiUrl(account, path);
    const opts = {
        method,
        headers: authHeaders(
            accessToken,
            body != null ? { 'Content-Type': 'application/json' } : {}
        ),
    };
    if (body != null) opts.body = JSON.stringify(body);

    const resp = await fetch(url, opts);
    const raw = await resp.text();
    let data;
    try { data = raw ? JSON.parse(raw) : null; } catch (_) { data = null; }
    return { ok: resp.ok, status: resp.status, data, raw, rate: rateInfo(resp) };
}

export function tnGet(account, path, accessToken) {
    return tnRequest(account, 'GET', path, accessToken);
}

// ----------------------------------------------------------------------------
// Tienda
// ----------------------------------------------------------------------------

/**
 * GET /store — datos de la tienda (name, email, etc.). Sustituye al /users/me
 * de ML para obtener nombre/contacto de la cuenta.
 */
export async function tnGetStore(account, accessToken) {
    const r = await tnGet(account, '/store', accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`store falló: HTTP ${r.status}`);
    }
    return r.data;
}

// ----------------------------------------------------------------------------
// Productos (lectura) — TN devuelve objetos completos paginados, sin multi-get
// ----------------------------------------------------------------------------

/**
 * Lista productos completos de la tienda, paginado.
 *   GET /products?page=&per_page=[&updated_at_min=]
 *
 * A diferencia de ML (search de IDs + multi-get), TN devuelve el objeto completo
 * del producto (con sus variants) directamente. El sync incremental usa
 * updatedAtMin (ISO-8601) para traer solo lo modificado desde el watermark.
 *
 * @returns {Promise<{ products: object[], hasMore: boolean }>}
 *   hasMore se deriva de si la página vino llena (TN no devuelve total en el body;
 *   usa el header Link rel="next", que aproximamos por tamaño de página).
 */
export async function tnListProducts(account, accessToken, page, perPage, updatedAtMin = '') {
    let path = `/products?page=${page}&per_page=${perPage}`;
    if (updatedAtMin) path += `&updated_at_min=${encodeURIComponent(updatedAtMin)}`;
    const r = await tnGet(account, path, accessToken);
    if (r.status === 404) {
        // TN devuelve 404 cuando se pide una página más allá de la última.
        return { products: [], hasMore: false };
    }
    if (!r.ok || !Array.isArray(r.data)) {
        throw new Error(`products falló: HTTP ${r.status} ${(r.data && r.data.message) || ''}`);
    }
    return { products: r.data, hasMore: r.data.length >= perPage };
}

/**
 * GET /products/{id} — un producto completo con sus variants.
 */
export async function tnGetProduct(account, accessToken, productId) {
    const r = await tnGet(account, `/products/${encodeURIComponent(productId)}`, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`products/${productId} falló: HTTP ${r.status}`);
    }
    return r.data;
}

// ----------------------------------------------------------------------------
// Órdenes
// ----------------------------------------------------------------------------

/**
 * GET /orders/{id} — una orden completa (products[], status, payment_status,
 * contact_*, etc.).
 */
export async function tnGetOrder(account, accessToken, orderId) {
    const r = await tnGet(account, `/orders/${encodeURIComponent(orderId)}`, accessToken);
    if (!r.ok || !r.data) {
        throw new Error(`orders/${orderId} falló: HTTP ${r.status}`);
    }
    return r.data;
}

// ----------------------------------------------------------------------------
// Push de stock / precio
// ----------------------------------------------------------------------------

/**
 * PATCH /products/stock-price — actualización masiva de stock y/o precio de
 * hasta TN_BULK_SIZE (50) variantes, potencialmente de distintos productos.
 * Es la vía recomendada para el push masivo: minimiza requests y respeta el
 * leaky-bucket.
 *
 * @param {Array<{id:number, price?:number|string, stock?:number|string}>} items
 *        cada entry referencia una VARIANTE por su `id`. `stock` vacío ("")
 *        significa stock ilimitado en TN.
 * @returns {Promise<{ ok, status, data, rate }>}
 */
export async function tnBulkStockPrice(account, accessToken, items) {
    return tnRequest(account, 'PATCH', '/products/stock-price', accessToken, items);
}

/**
 * POST /products/{product_id}/variants/stock — setea (replace) o ajusta
 * (variation = delta) el stock de una variante puntual o de todas. Útil para
 * el flujo inverso de venta (delta negativo) y como fallback unitario.
 *
 * @param {object} payload  ej. { action:'variation', value:-1, id: variantId }
 *                          o { action:'replace', value: 10, id: variantId }
 */
export async function tnSetVariantStock(account, accessToken, productId, payload) {
    return tnRequest(
        account, 'POST',
        `/products/${encodeURIComponent(productId)}/variants/stock`,
        accessToken, payload
    );
}

/**
 * PUT /products/{product_id}/variants/{id} — edita una variante completa.
 * Fallback cuando hay que tocar campos que stock-price no cubre.
 */
export async function tnUpdateVariant(account, accessToken, productId, variantId, body) {
    return tnRequest(
        account, 'PUT',
        `/products/${encodeURIComponent(productId)}/variants/${encodeURIComponent(variantId)}`,
        accessToken, body
    );
}

// ----------------------------------------------------------------------------
// Webhooks
// ----------------------------------------------------------------------------

/**
 * POST /webhooks — registra un webhook { event, url }. Idempotencia: TN permite
 * listar (GET /webhooks) y borrar (DELETE /webhooks/{id}); el caller decide.
 */
export async function tnCreateWebhook(account, accessToken, event, url) {
    return tnRequest(account, 'POST', '/webhooks', accessToken, { event, url });
}

export async function tnListWebhooks(account, accessToken) {
    const r = await tnGet(account, '/webhooks', accessToken);
    if (!r.ok || !Array.isArray(r.data)) {
        throw new Error(`webhooks falló: HTTP ${r.status}`);
    }
    return r.data;
}

/**
 * Extrae un mensaje de error legible del shape de error de TN:
 *   { code, message, description } o un objeto de validación por campo.
 */
export function tnErrorMessage(data, status) {
    if (!data) return `HTTP ${status}`;
    if (typeof data === 'string') return data;
    if (data.message) return String(data.message);
    if (data.description) return String(data.description);
    if (data.error) return String(data.error);
    // Errores de validación de TN: { campo: ["msg", ...] }
    try {
        const parts = [];
        for (const [k, v] of Object.entries(data)) {
            parts.push(`${k}: ${Array.isArray(v) ? v.join(', ') : v}`);
        }
        if (parts.length) return parts.join(' | ');
    } catch (_) { /* noop */ }
    return `HTTP ${status}`;
}
