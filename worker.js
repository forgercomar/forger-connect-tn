/**
 * worker.js — Worker del Central Orchestrator (TiendaNube).
 *
 * Loop interno (setInterval) que procesa los jobs de sincronización:
 *
 *   1. Toma un job `pending` de tipo sync_* o push (lock con FOR UPDATE SKIP LOCKED).
 *   2. Resuelve la cuenta + su access_token (TN: no expira, solo se desencripta).
 *   3. Pagina GET /products (TN devuelve el objeto completo con variants; no hay
 *      multi-get tipo ML), arma el row para wf_tn_items y lo inserta en `synced_items`.
 *   4. Va actualizando jobs.steps_done para que el plugin vea el progreso.
 *   5. Marca el job `done` (o `failed` si algo explotó).
 *
 * Diferencias con el worker de ML:
 *   - Sin search+multiget: /products ya trae objetos completos paginados.
 *   - Incremental NATIVO via updated_at_min (TN lo soporta; ML no, requería el
 *     hack de paginar last_updated_desc y cortar al cruzar el watermark).
 *   - Sin cuotas/installments ni listing_type (no existen en TN).
 *   - Push de stock/precio por VARIANTE, agrupado en PATCH /products/stock-price
 *     (hasta 50 por request) para respetar el leaky-bucket de TN.
 *   - Throttle de rate-limit: TN permite ~2 req/s sostenido (bucket 40). El worker
 *     espacia las llamadas y hace back-off cuando x-rate-limit-remaining baja.
 *
 * Variables de entorno:
 *   WFTN_WORKER_ENABLED        '0' para apagar el worker (default: encendido)
 *   WFTN_WORKER_INTERVAL       ms entre ticks (default 5000)
 *   WFTN_RATE_MIN_INTERVAL_MS  espaciado mínimo entre requests a TN (default 500 = 2/s)
 *
 * @module worker
 */

import { query } from './db.js';
import {
    getValidAccessToken,
    tnListProducts,
    tnGetProduct,
    tnBulkStockPrice,
    tnSetVariantStock,
    tnUpdateVariant,
    tnErrorMessage,
    TN_PAGE_SIZE,
    TN_BULK_SIZE,
} from './tn-api.js';

const WORKER_ENABLED  = process.env.WFTN_WORKER_ENABLED !== '0';
const WORKER_INTERVAL = Math.max(2000, Number(process.env.WFTN_WORKER_INTERVAL) || 5000);
const RATE_MIN_INTERVAL_MS = Math.max(0, Number(process.env.WFTN_RATE_MIN_INTERVAL_MS) || 500);

// Margen de seguridad del sync incremental: al watermark se le restan estos ms
// antes de filtrar por updated_at_min. Sobre-traer items sin cambios es inofensivo
// (upsert idempotente del lado del plugin); perder uno por desfasaje de reloj, no.
const INCREMENTAL_MARGIN_MS = 60 * 60 * 1000; // 1 hora

// Flag para evitar que dos ticks se solapen si un job tarda más que el intervalo.
let _busy = false;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Throttle de rate-limit. Espaciado base de RATE_MIN_INTERVAL_MS entre requests;
 * si la última respuesta avisó que quedan pocas requests en el bucket, espera a
 * que se vacíe (x-rate-limit-reset viene en ms).
 */
async function throttle(lastRate) {
    if (lastRate && lastRate.remaining != null && lastRate.remaining <= 2 && lastRate.resetMs) {
        await sleep(Math.min(lastRate.resetMs + 100, 30000));
        return;
    }
    if (RATE_MIN_INTERVAL_MS) await sleep(RATE_MIN_INTERVAL_MS);
}

// ----------------------------------------------------------------------------
// Construcción del row para wf_tn_items
// ----------------------------------------------------------------------------

/**
 * TN guarda name/description multilenguaje como objeto { es: "...", pt: "..." }.
 * Devuelve el primer valor útil (preferencia es → pt → cualquier).
 */
function flattenI18n(val) {
    if (val == null) return '';
    if (typeof val === 'string') return val;
    if (typeof val === 'object') {
        if (val.es) return String(val.es);
        if (val.pt) return String(val.pt);
        const first = Object.values(val).find((v) => v);
        return first ? String(first) : '';
    }
    return String(val);
}

/**
 * URL de imagen de una variante: TN referencia images por image_id dentro de
 * product.images[]. Fallback a la primera imagen del producto.
 */
function variantThumb(variant, product) {
    const images = Array.isArray(product.images) ? product.images : [];
    if (variant && variant.image_id) {
        const img = images.find((im) => im && String(im.id) === String(variant.image_id));
        if (img && img.src) return String(img.src);
    }
    return images[0] && images[0].src ? String(images[0].src) : '';
}

/**
 * Etiqueta legible de una variante: nombre del producto + los valores de atributo
 * (Color/Talle/etc), p.ej. "Remera Lisa — Negro / M". TN guarda los valores en
 * variant.values[] como objetos i18n.
 */
function variantLabel(product, variant) {
    const base = flattenI18n(product.name);
    const values = Array.isArray(variant.values) ? variant.values : [];
    const parts = values.map((v) => flattenI18n(v).trim()).filter(Boolean);
    return parts.length ? (base + ' — ' + parts.join(' / ')) : base;
}

/**
 * Stock de una variante TN: '' o null = ilimitado → lo guardamos como null.
 */
function variantStock(variant) {
    const s = variant.stock;
    if (s === '' || s == null) return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
}

/**
 * Estado de publicación de un producto TN: TN no tiene status de marketplace,
 * solo el booleano `published`. Lo normalizamos a 'published' / 'unpublished'
 * para que el plugin tenga una columna `status` análoga a la de ML.
 */
function productStatus(product) {
    return product.published ? 'published' : 'unpublished';
}

/**
 * Arma el row para wf_tn_items. `variant` != null → row de esa variante;
 * `variant` == null → row del producto padre.
 */
function buildItemRow(product, variant, hasMultipleVariants) {
    const status = productStatus(product);
    const permalink = String(product.canonical_url || product.permalink || '');
    if (variant) {
        return {
            tn_product_id:      String(product.id),
            parent_product_id:  String(product.id),
            variant_id:         Number(variant.id),
            title:              variantLabel(product, variant),
            sku:                String(variant.sku || ''),
            price:              variant.price != null ? Number(variant.price) : 0,
            promotional_price:  variant.promotional_price != null ? Number(variant.promotional_price) : null,
            available_quantity: variantStock(variant),
            status,
            permalink,
            thumbnail:          variantThumb(variant, product),
            has_variants:       0,
            variants_json:      null,
            category_id:        Array.isArray(product.categories) && product.categories[0]
                                  ? String(product.categories[0].id || product.categories[0]) : '',
        };
    }
    const variants = Array.isArray(product.variants) ? product.variants : [];
    return {
        tn_product_id:      String(product.id),
        parent_product_id:  null,
        variant_id:         null,
        title:              flattenI18n(product.name),
        sku:                '',
        price:              variants[0] && variants[0].price != null ? Number(variants[0].price) : 0,
        promotional_price:  null,
        available_quantity: null, // el agregado se deriva de las variantes en el plugin
        status,
        permalink,
        thumbnail:          Array.isArray(product.images) && product.images[0] && product.images[0].src
                              ? String(product.images[0].src) : '',
        has_variants:       hasMultipleVariants ? 1 : 0,
        variants_json:      hasMultipleVariants ? JSON.stringify(variants) : null,
        category_id:        Array.isArray(product.categories) && product.categories[0]
                              ? String(product.categories[0].id || product.categories[0]) : '',
    };
}

// ----------------------------------------------------------------------------
// Persistencia de items en staging
// ----------------------------------------------------------------------------

/**
 * Inserta en synced_items un batch de rows ya armados.
 * Cada `row` = { tn_product_id, variant_id, item_data }.
 */
async function insertSyncedItems(accountId, jobId, rows) {
    if (!rows.length) return;
    const placeholders = [];
    const values = [];
    let p = 1;
    for (const r of rows) {
        placeholders.push(`($${p++}, $${p++}, $${p++}, $${p++}, $${p++})`);
        values.push(accountId, jobId, r.tn_product_id, r.variant_id, JSON.stringify(r.item_data));
    }
    await query(
        `INSERT INTO synced_items (account_id, job_id, tn_product_id, variant_id, item_data)
         VALUES ${placeholders.join(',')}`,
        values
    );
}

/**
 * Convierte una página de productos TN en rows de synced_items (padre + variantes).
 * En TN todo producto tiene al menos una variante por defecto; consideramos
 * "con variantes reales" cuando hay más de una.
 */
function expandProductsToRows(products) {
    const rows = [];
    for (const product of products) {
        const variants = Array.isArray(product.variants) ? product.variants : [];
        const hasMultiple = variants.length > 1;
        // Padre.
        rows.push({
            tn_product_id: String(product.id),
            variant_id:    null,
            item_data:     buildItemRow(product, null, hasMultiple),
        });
        // Variantes (siempre, incluso la única por defecto — porta el stock/sku).
        for (const v of variants) {
            if (!v || !v.id) continue;
            rows.push({
                tn_product_id: String(product.id),
                variant_id:    Number(v.id),
                item_data:     buildItemRow(product, v, hasMultiple),
            });
        }
    }
    return rows;
}

// ----------------------------------------------------------------------------
// Procesamiento de un job de sync
// ----------------------------------------------------------------------------

async function jobIsActive(jobId) {
    const r = await query(`SELECT status FROM jobs WHERE id = $1`, [jobId]);
    return r.rowCount > 0 && r.rows[0].status === 'running';
}

/**
 * Procesa un job "targeted": una lista explícita de tn_product_ids (típicamente
 * originada por webhooks product/updated). Trae cada producto con GET /products/{id}.
 */
async function processTargetedSync(job, account, token, ids) {
    const unique = [...new Set(ids.map(String))];
    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0, message = $3 WHERE id = $1`,
        [job.id, unique.length, `Actualizando ${unique.length} producto(s) modificado(s)...`]
    );

    let processed = 0, stepsDone = 0;
    let lastRate = null;
    for (const pid of unique) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        await throttle(lastRate);
        let product = null;
        try {
            product = await tnGetProduct(account, token, pid);
        } catch (err) {
            // Producto borrado / inaccesible: no lo actualizamos, seguimos.
            console.warn(`[worker] producto ${pid} no traído: ${err.message}`);
        }
        if (product) {
            await insertSyncedItems(account.id, job.id, expandProductsToRows([product]));
            processed++;
        }
        stepsDone++;
        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, stepsDone, `Actualizados ${processed} de ${unique.length}...`]
        );
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, total: unique.length, mode: 'targeted' }),
         `Actualización completa: ${processed} producto(s).`]
    );
    console.log(`[worker] job ${job.public_id} done (targeted) — ${processed} productos`);
}

/**
 * Procesa un job de tipo sync_full / sync_incremental.
 */
async function processSyncJob(job) {
    const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [job.account_id]);
    if (!accR.rowCount) throw new Error('cuenta no encontrada');
    const account = accR.rows[0];
    if (account.revoked_at) throw new Error('cuenta revocada');

    const token = await getValidAccessToken(account);

    const input = (job.input && typeof job.input === 'object') ? job.input : {};
    const targetIds = Array.isArray(input.tn_product_ids)
        ? input.tn_product_ids.map(String).filter(Boolean)
        : [];
    if (targetIds.length > 0) {
        return await processTargetedSync(job, account, token, targetIds);
    }

    // Incremental nativo: TN soporta updated_at_min. Sin watermark (primer sync)
    // cae a full (updatedAtMin vacío → trae todo).
    const incremental = job.type === 'sync_incremental' && account.last_sync_at;
    const updatedAtMin = incremental
        ? new Date(new Date(account.last_sync_at).getTime() - INCREMENTAL_MARGIN_MS).toISOString()
        : '';

    await query(
        `UPDATE jobs SET steps_total = 0, steps_done = 0, message = $2 WHERE id = $1`,
        [job.id, incremental ? 'Buscando productos modificados...' : 'Sincronizando catálogo...']
    );

    let processed = 0, pages = 0;
    let lastRate = null;
    for (let page = 1; ; page++) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        await throttle(lastRate);
        const { products, hasMore } = await tnListProducts(account, token, page, TN_PAGE_SIZE, updatedAtMin);
        if (products.length) {
            await insertSyncedItems(account.id, job.id, expandProductsToRows(products));
            processed += products.length;
        }
        pages++;
        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, pages, `Sincronizados ${processed} producto(s)...`]
        );
        if (!hasMore) break;
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ items_synced: processed, pages_scanned: pages, mode: incremental ? 'incremental' : 'full' }),
         incremental
            ? (processed > 0 ? `Sync incremental: ${processed} producto(s) actualizado(s).` : 'Sync incremental: catálogo al día.')
            : `Sync completo: ${processed} producto(s).`]
    );
    await advanceWatermark(account.id, job.started_at);
    console.log(`[worker] job ${job.public_id} done (${incremental ? 'incremental' : 'full'}) — ${processed} productos, ${pages} página(s)`);
}

/**
 * Avanza accounts.last_sync_at al `started_at` del job (no al fin) para no dejar
 * afuera nada que haya cambiado mientras el sync corría.
 */
async function advanceWatermark(accountId, startedAt) {
    if (!startedAt) return;
    await query(`UPDATE accounts SET last_sync_at = $2 WHERE id = $1`, [accountId, startedAt]);
}

// ----------------------------------------------------------------------------
// Procesamiento de un job de push (push masivo Web → TN)
// ----------------------------------------------------------------------------

/**
 * Procesa un job `push`: actualiza stock (y opcionalmente precio) de variantes
 * en TiendaNube. El plugin calcula cada valor con sus datos de WooCommerce/wfw;
 * el central los manda agrupados en PATCH /products/stock-price (50 por request)
 * para respetar el rate-limit, y reporta el resultado por variante.
 *
 * input.pushes = [{ tn_product_id, variant_id, stock, price?, promotional_price?, apply? }]
 *   variant_id          → variante TN a actualizar (clave del bulk).
 *   stock               → cantidad; null/'' = ilimitado en TN.
 *   price               → opcional; si viene, se actualiza también.
 *   promotional_price   → opcional (>0); precio de OFERTA. El bulk stock-price NO
 *                         lo soporta → se aplica por variante con PUT /variants/{id}.
 *   apply      → blob opaco que el plugin usa para sincronizar su cache; el
 *                central no lo interpreta, lo devuelve tal cual en el result.
 *
 * Estrategia: batch optimista. Si el PATCH del batch sale 2xx, todas sus
 * variantes quedan OK. Si falla, se reintenta cada variante por separado
 * (POST /variants/stock replace + PUT variante para precio) para aislar el error.
 */
async function processPushJob(job) {
    const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [job.account_id]);
    if (!accR.rowCount) throw new Error('cuenta no encontrada');
    const account = accR.rows[0];
    if (account.revoked_at) throw new Error('cuenta revocada');
    const token = await getValidAccessToken(account);

    const input  = (job.input && typeof job.input === 'object') ? job.input : {};
    const pushes = Array.isArray(input.pushes) ? input.pushes : [];
    const total  = pushes.length;

    await query(
        `UPDATE jobs SET steps_total = $2, steps_done = 0, message = $3 WHERE id = $1`,
        [job.id, total, `Pusheando ${total} variante(s) a TiendaNube...`]
    );

    const results = [];
    let pushed = 0, failed = 0, done = 0;
    let lastRate = null;

    // Normaliza el valor de stock para TN: null → '' (ilimitado).
    const stockVal = (s) => (s === null || s === undefined || s === '' ? '' : Number(s));

    // Agrupar en batches de TN_BULK_SIZE.
    for (let i = 0; i < pushes.length; i += TN_BULK_SIZE) {
        if (!(await jobIsActive(job.id))) {
            console.log(`[worker] job ${job.public_id} cancelado a mitad — corto.`);
            return;
        }
        const batch = pushes.slice(i, i + TN_BULK_SIZE)
            .filter((pu) => pu && pu.variant_id != null);

        // Armar items del PATCH masivo.
        const bulkItems = batch.map((pu) => {
            const it = { id: Number(pu.variant_id), stock: stockVal(pu.stock) };
            if (pu.price !== undefined && pu.price !== null && pu.price !== '') {
                it.price = Number(pu.price);
            }
            return it;
        });

        let batchOk = false;
        if (bulkItems.length) {
            await throttle(lastRate);
            try {
                const res = await tnBulkStockPrice(account, token, bulkItems);
                lastRate = res.rate;
                batchOk = res.ok;
            } catch (err) {
                console.warn(`[worker] batch stock-price falló, fallback por variante: ${err.message}`);
            }
        }

        if (batchOk) {
            for (const pu of batch) {
                const r = { variant_id: Number(pu.variant_id), tn_product_id: pu.tn_product_id, ok: true, http_code: 200, error: null };
                if (pu.apply !== undefined) r.apply = pu.apply;
                results.push(r); pushed++; done++;
            }
        } else {
            // Fallback por variante para aislar el fallo.
            for (const pu of batch) {
                await throttle(lastRate);
                let r;
                try {
                    const stockRes = await tnSetVariantStock(account, token, pu.tn_product_id, {
                        action: 'replace', value: stockVal(pu.stock), id: Number(pu.variant_id),
                    });
                    lastRate = stockRes.rate;
                    let ok = stockRes.ok;
                    let httpCode = stockRes.status;
                    let error = ok ? null : tnErrorMessage(stockRes.data, stockRes.status);
                    // Precio (si vino) via PUT de la variante.
                    if (ok && pu.price !== undefined && pu.price !== null && pu.price !== '') {
                        await throttle(lastRate);
                        const priceRes = await tnUpdateVariant(account, token, pu.tn_product_id, pu.variant_id, { price: Number(pu.price) });
                        lastRate = priceRes.rate;
                        if (!priceRes.ok) { ok = false; httpCode = priceRes.status; error = tnErrorMessage(priceRes.data, priceRes.status); }
                    }
                    r = { variant_id: Number(pu.variant_id), tn_product_id: pu.tn_product_id, ok, http_code: httpCode, error };
                } catch (err) {
                    r = { variant_id: Number(pu.variant_id), tn_product_id: pu.tn_product_id, ok: false, http_code: 0, error: err.message };
                }
                if (pu.apply !== undefined) r.apply = pu.apply;
                results.push(r);
                if (r.ok) pushed++; else failed++;
                done++;
            }
        }

        // Precio de OFERTA (promotional_price): el bulk PATCH /products/stock-price
        // NO lo soporta → lo aplicamos por variante con PUT /products/{id}/variants/{vid}.
        // Solo para las variantes del batch que traen promotional_price (>0).
        for (const pu of batch) {
            if (pu.promotional_price === undefined) continue;
            const promo = Number(pu.promotional_price);
            // promo > 0 → setear la oferta; promo == 0 → QUITARLA. TiendaNube IGNORA
            // null en el PUT (lo trata como "no cambiar"); para borrar hay que mandar
            // string vacío "" (verificado contra la API real 2026-05-30).
            const promoBody = promo > 0 ? promo : '';
            await throttle(lastRate);
            try {
                const pr = await tnUpdateVariant(account, token, pu.tn_product_id, pu.variant_id, { promotional_price: promoBody });
                lastRate = pr.rate;
                const rr = results.find((r) => r.variant_id === Number(pu.variant_id));
                if (!pr.ok) {
                    const msg = tnErrorMessage(pr.data, pr.status);
                    console.warn(`[worker] promo PUT falló variante ${pu.variant_id}: ${msg}`);
                    if (rr) { rr.promo_ok = false; rr.promo_error = msg; }
                } else if (rr) {
                    rr.promo_ok = true;
                }
            } catch (err) {
                console.warn(`[worker] promo PUT excepción variante ${pu.variant_id}: ${err.message}`);
                const rr = results.find((r) => r.variant_id === Number(pu.variant_id));
                if (rr) { rr.promo_ok = false; rr.promo_error = err.message; }
            }
        }

        await query(
            `UPDATE jobs SET steps_done = $2, message = $3, last_seen_at = NOW() WHERE id = $1`,
            [job.id, done, `Pusheadas ${done}/${total} — ${pushed} OK, ${failed} con error...`]
        );
    }

    await query(
        `UPDATE jobs SET status = 'done', finished_at = NOW(), result = $2, message = $3
         WHERE id = $1 AND status = 'running'`,
        [job.id,
         JSON.stringify({ mode: 'push', total, pushed, failed, items: results }),
         `Push masivo: ${pushed} OK, ${failed} con error (de ${total}).`]
    );
    console.log(`[worker] job ${job.public_id} done (push) — ${pushed} OK, ${failed} fail`);
}

// ----------------------------------------------------------------------------
// Loop principal
// ----------------------------------------------------------------------------

async function claimJob() {
    const r = await query(
        `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
         WHERE id = (
            SELECT id FROM jobs
            WHERE status = 'pending'
              AND type IN ('sync_full', 'sync_incremental', 'push')
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT 1
         )
         RETURNING id, public_id, account_id, type, input, started_at`
    );
    return r.rowCount ? r.rows[0] : null;
}

async function tick() {
    if (_busy) return;
    _busy = true;
    try {
        const job = await claimJob();
        if (!job) return;
        console.log(`[worker] tomando job ${job.public_id} (${job.type})`);
        try {
            await (job.type === 'push' ? processPushJob(job) : processSyncJob(job));
        } catch (err) {
            console.error(`[worker] job ${job.public_id} falló:`, err.message);
            await query(
                `UPDATE jobs SET status = 'failed', finished_at = NOW(), message = $2
                 WHERE id = $1 AND status = 'running'`,
                [job.id, 'Error: ' + err.message]
            );
        }
    } catch (err) {
        console.error('[worker] tick error:', err.message);
    } finally {
        _busy = false;
    }
}

export function startWorker() {
    if (!WORKER_ENABLED) {
        console.log('[worker] deshabilitado (WFTN_WORKER_ENABLED=0)');
        return;
    }
    console.log(`[worker] arrancando — intervalo ${WORKER_INTERVAL}ms, page ${TN_PAGE_SIZE}, rate-min ${RATE_MIN_INTERVAL_MS}ms`);
    setInterval(() => { tick().catch((e) => console.error('[worker] tick uncaught:', e)); }, WORKER_INTERVAL);
}
