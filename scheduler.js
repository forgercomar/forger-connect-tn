/**
 * scheduler.js — Cron de sincronización automática del Central Orchestrator.
 *
 * El servicio de fondo 24/7: cada cierto tiempo revisa TODAS las cuentas
 * activas y, para las que hace rato no se sincronizan, encola un job de
 * sync. El worker (worker.js) después lo procesa como cualquier otro job.
 *
 * Modelo:
 *
 *   [scheduler] cada CHECK_INTERVAL ms:
 *       busca cuentas activas SIN sync reciente y SIN job en curso
 *       → INSERT job sync_full (input.source = 'cron')
 *   [worker]    toma el job → pagina ML → llena synced_items
 *   [plugin]    en su próximo page-load pregunta GET /v1/sync/pending
 *               → baja los resultados que el cron dejó listos
 *
 * El scheduler NO sincroniza él mismo: solo CREA jobs. Así reusa todo el
 * worker y el lock SKIP LOCKED ya garantiza que no se doble-procesen.
 *
 * Auto-regulación: una cuenta se re-encola recién cuando su último job de
 * sync (de cualquier origen — manual o cron, exitoso o fallido) es más
 * viejo que INTERVAL_HOURS. Así un sync manual reciente "cuenta" y el cron
 * no duplica trabajo; y un job fallido no se reintenta en loop cerrado.
 *
 * El scheduler corre DOS loops independientes:
 *   - autosync:  cada cuenta sin sync reciente → job sync_incremental; cada
 *     FULL_HOURS uno de esos syncs es un sync_full de cobertura total (la red
 *     de seguridad que recupera lo que webhooks + incremental dejaron pasar).
 *   - webhook debouncer: agrupa los webhook_events pendientes por cuenta y
 *     encola un job sync_incremental targeted con la lista de items.
 *
 * Variables de entorno:
 *   WFTN_AUTOSYNC_ENABLED         '0' apaga el cron de autosync (default: on)
 *   WFTN_AUTOSYNC_INTERVAL_HOURS  cada cuántas horas resincronizar una cuenta
 *                                 (default 6)
 *   WFTN_AUTOSYNC_FULL_HOURS      cada cuántas horas el sync periódico es un
 *                                 sync_full de cobertura total (default 24);
 *                                 entre fulls el cron encola sync_incremental
 *   WFTN_AUTOSYNC_CHECK_INTERVAL  ms entre chequeos del autosync (default
 *                                 600000 = 10 min)
 *   WFTN_WEBHOOK_ENABLED          '0' apaga el debouncer de webhooks (default: on)
 *   WFTN_WEBHOOK_BATCH_INTERVAL   ms entre agrupaciones de webhooks (default
 *                                 60000 = 1 min). Más bajo = más "tiempo real"
 *                                 pero más jobs; el debounce existe para no
 *                                 disparar un job por cada webhook suelto.
 *
 * @module scheduler
 */

import { query } from './db.js';
import { generatePublicId } from './auth.js';
import { getValidAccessToken, tnGetOrder } from './tn-api.js';

const AUTOSYNC_ENABLED = process.env.WFTN_AUTOSYNC_ENABLED !== '0';
const INTERVAL_HOURS   = Math.max(1, Number(process.env.WFTN_AUTOSYNC_INTERVAL_HOURS) || 6);
const CHECK_INTERVAL   = Math.max(60000, Number(process.env.WFTN_AUTOSYNC_CHECK_INTERVAL) || 600000);
// Cada cuántas horas el sync periódico es un sync_full de cobertura total.
// Entre fulls el cron encola sync_incremental (mucho más liviano).
const FULL_HOURS       = Math.max(INTERVAL_HOURS, Number(process.env.WFTN_AUTOSYNC_FULL_HOURS) || 24);

const WEBHOOK_ENABLED        = process.env.WFTN_WEBHOOK_ENABLED !== '0';
const WEBHOOK_BATCH_INTERVAL = Math.max(15000, Number(process.env.WFTN_WEBHOOK_BATCH_INTERVAL) || 60000);

const ORDER_ENABLED  = process.env.WFTN_ORDER_ENABLED !== '0';
const ORDER_INTERVAL = Math.max(15000, Number(process.env.WFTN_ORDER_INTERVAL) || 60000);

// Janitor de jobs zombie: si el worker crashea a mitad de un job, queda en
// status='running' para siempre porque claimJob() filtra status='pending'. Este
// loop marca como 'failed' los jobs con last_seen_at viejo para que el plugin
// que estaba polleando vea el error y reintente si corresponde.
//
// Threshold conservador (15 min): worker.js updatea last_seen_at en CADA step
// (sync) o CADA PUT (push), o sea ~1-2s entre updates. 15 min sin update es
// señal inequívoca de crash. NO se rescata a 'pending' para evitar doble
// procesamiento (un PUT que ML ya recibió no debe re-PUT-earse).
const ZOMBIE_ENABLED         = process.env.WFTN_ZOMBIE_RECLAIM_ENABLED !== '0';
const ZOMBIE_TIMEOUT_MIN     = Math.max(5, Number(process.env.WFTN_ZOMBIE_TIMEOUT_MIN) || 15);
const ZOMBIE_CHECK_INTERVAL  = Math.max(60000, Number(process.env.WFTN_ZOMBIE_CHECK_INTERVAL) || 5 * 60_000);

// Delay del primer chequeo — le da tiempo a la DB y al worker a estar listos
// después de un deploy antes de empezar a encolar.
const FIRST_RUN_DELAY = 30000;

// Evita que dos chequeos del mismo loop se solapen si la DB está lenta.
let _busy = false;
let _webhookBusy = false;
let _orderBusy = false;
let _zombieBusy = false;

/**
 * Busca las cuentas activas que necesitan un sync automático y encola un job
 * para cada una. Por defecto encola sync_incremental; si la cuenta no tuvo un
 * sync_full exitoso en las últimas FULL_HOURS, encola sync_full (red de
 * seguridad). Devuelve cuántos jobs creó.
 */
async function scheduleDueAccounts() {
    // Cuentas activas que:
    //   (a) no tienen un job de sync pending/running (no pisar trabajo en curso), y
    //   (b) no tuvieron NINGÚN job de sync en las últimas INTERVAL_HOURS
    //       (ni manual ni de cron) — o nunca tuvieron uno.
    // `needs_full` = no hubo un sync_full exitoso en las últimas FULL_HOURS
    //   (incluye la cuenta que nunca se sincronizó) → toca un full.
    const due = await query(
        `SELECT a.id, a.public_id,
                NOT EXISTS (
                    SELECT 1 FROM jobs j
                    WHERE j.account_id = a.id
                      AND j.type = 'sync_full'
                      AND j.status = 'done'
                      AND j.created_at > NOW() - ($2 || ' hours')::interval
                ) AS needs_full
         FROM accounts a
         WHERE a.revoked_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM jobs j
               WHERE j.account_id = a.id
                 AND j.type IN ('sync_full', 'sync_incremental')
                 AND j.status IN ('pending', 'running')
           )
           AND NOT EXISTS (
               SELECT 1 FROM jobs j
               WHERE j.account_id = a.id
                 AND j.type IN ('sync_full', 'sync_incremental')
                 AND j.created_at > NOW() - ($1 || ' hours')::interval
           )`,
        [String(INTERVAL_HOURS), String(FULL_HOURS)]
    );

    if (!due.rowCount) return 0;

    let created = 0;
    for (const acc of due.rows) {
        const type = acc.needs_full ? 'sync_full' : 'sync_incremental';
        try {
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, $3, 'pending', $4, 0)`,
                [jobPublic, acc.id, type, JSON.stringify({ source: 'cron' })]
            );
            created++;
            console.log(`[scheduler] encolado ${type} automático ${jobPublic} para cuenta ${acc.public_id}`);
        } catch (err) {
            console.error(`[scheduler] no se pudo encolar para cuenta ${acc.public_id}:`, err.message);
        }
    }
    return created;
}

async function tick() {
    if (_busy) return;
    _busy = true;
    try {
        const n = await scheduleDueAccounts();
        if (n > 0) console.log(`[scheduler] ${n} job(s) de sync automático encolado(s)`);
    } catch (err) {
        console.error('[scheduler] tick error:', err.message);
    } finally {
        _busy = false;
    }
}

// ----------------------------------------------------------------------------
// Webhook debouncer
// ----------------------------------------------------------------------------

/**
 * Agrupa los webhook_events pendientes por cuenta y encola un job
 * sync_incremental targeted (input.tn_product_ids) por cada cuenta con cambios.
 *
 * Orden seguro: leemos los pendientes, creamos el job y RECIÉN ahí marcamos
 * esos eventos como procesados. Si la creación del job falla, los eventos
 * quedan sin marcar y se reintentan en el próximo tick — sin pérdida. Un
 * webhook que llega entre el SELECT y el UPDATE no estaba en el batch, así
 * que tampoco se pierde: lo toma la próxima vuelta.
 *
 * @returns {Promise<number>} cantidad de jobs encolados.
 */
async function processWebhookBatch() {
    const pend = await query(
        `SELECT id, account_id, tn_product_id
         FROM webhook_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 5000`
    );
    if (!pend.rowCount) return 0;

    // Agrupar por cuenta: items únicos + ids de evento a marcar.
    const byAccount = new Map();
    for (const row of pend.rows) {
        let g = byAccount.get(row.account_id);
        if (!g) { g = { itemIds: new Set(), eventIds: [] }; byAccount.set(row.account_id, g); }
        g.itemIds.add(row.tn_product_id);
        g.eventIds.push(row.id);
    }

    let jobs = 0;
    for (const [accountId, g] of byAccount) {
        const itemIds = [...g.itemIds];
        try {
            const jobPublic = generatePublicId('job');
            await query(
                `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                 VALUES ($1, $2, 'sync_incremental', 'pending', $3, 0)`,
                [jobPublic, accountId, JSON.stringify({ source: 'webhook', tn_product_ids: itemIds })]
            );
            // Job creado OK → marcar SOLO esos eventos como procesados.
            await query(
                `UPDATE webhook_events SET processed_at = NOW() WHERE id = ANY($1::bigint[])`,
                [g.eventIds]
            );
            jobs++;
            console.log(`[scheduler] webhook batch → job ${jobPublic} (cuenta ${accountId}, ${itemIds.length} item(s))`);
        } catch (err) {
            console.error(`[scheduler] no se pudo encolar webhook batch cuenta ${accountId}:`, err.message);
            // No marcamos processed → se reintenta en el próximo tick.
        }
    }
    return jobs;
}

async function webhookTick() {
    if (_webhookBusy) return;
    _webhookBusy = true;
    try {
        await processWebhookBatch();
    } catch (err) {
        console.error('[scheduler] webhook tick error:', err.message);
    } finally {
        _webhookBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Procesador de órdenes (ledger de stock)
// ----------------------------------------------------------------------------

/**
 * Extrae los items vendidos de una orden TN en el shape que consume el plugin.
 * Los line items de TN están en order.products[] con product_id + variant_id.
 * OJO: un mismo (product_id, variant_id) puede aparecer en varios line items
 * (cuando difieren propiedades/custom fields); el plugin suma por variant_id.
 */
function extractOrderItems(order) {
    const items = Array.isArray(order.products) ? order.products : [];
    return items.map((p) => ({
        sku:           String(p.sku || ''),
        quantity:      Number(p.quantity) || 0,
        tn_product_id: String(p.product_id || ''),
        variant_id:    p.variant_id != null ? Number(p.variant_id) : null,
    }));
}

/**
 * Toma las order_events sin procesar, baja cada orden de ML y guarda en la
 * fila su estado + items vendidos. El plugin después las baja y las aplica a
 * su ledger de stock.
 *
 * Dedup: varios webhooks de la misma orden (la orden cambia de estado varias
 * veces) se procesan bajando la orden UNA vez — todas las filas de ese
 * tn_order_id se completan juntas. La idempotencia real (no descontar dos
 * veces) la garantiza el plugin con el tn_order_id como clave en su log.
 *
 * Si bajar la orden falla, la fila queda sin procesar y se reintenta en el
 * próximo tick — no se pierde la venta.
 */
async function processOrderEvents() {
    const pend = await query(
        `SELECT id, account_id, tn_order_id
         FROM order_events
         WHERE processed_at IS NULL
         ORDER BY account_id, id
         LIMIT 500`
    );
    if (!pend.rowCount) return 0;

    // Agrupar por cuenta; dentro de cada cuenta, dedup por tn_order_id.
    const byAccount = new Map();
    for (const row of pend.rows) {
        let orders = byAccount.get(row.account_id);
        if (!orders) { orders = new Map(); byAccount.set(row.account_id, orders); }
        let evIds = orders.get(row.tn_order_id);
        if (!evIds) { evIds = []; orders.set(row.tn_order_id, evIds); }
        evIds.push(row.id);
    }

    let processed = 0;
    for (const [accountId, orders] of byAccount) {
        let account, token;
        try {
            const accR = await query(`SELECT * FROM accounts WHERE id = $1`, [accountId]);
            if (!accR.rowCount || accR.rows[0].revoked_at) continue;
            account = accR.rows[0];
            token = await getValidAccessToken(account);
        } catch (err) {
            console.error(`[scheduler] orders: cuenta ${accountId} sin token — se reintenta:`, err.message);
            continue;
        }
        for (const [tnOrderId, evIds] of orders) {
            try {
                const order = await tnGetOrder(account, token, tnOrderId);
                // En TN el disparador de stock es payment_status (paid → descuenta,
                // refunded/voided → restaura). order.status (open/closed/cancelled)
                // es ortogonal; guardamos payment_status como el status accionable.
                const status = String(order.payment_status || order.status || '');
                const items = extractOrderItems(order);
                await query(
                    `UPDATE order_events
                     SET processed_at = NOW(), order_status = $2, items_json = $3, error = NULL
                     WHERE id = ANY($1::bigint[])`,
                    [evIds, status, JSON.stringify(items)]
                );
                processed++;
                console.log(`[scheduler] orden ${tnOrderId} procesada — status=${status}, ${items.length} item(s)`);
            } catch (err) {
                // No marcamos processed_at → se reintenta el próximo tick.
                console.error(`[scheduler] orden ${tnOrderId} falló (se reintenta):`, err.message);
            }
        }
    }
    return processed;
}

async function orderTick() {
    if (_orderBusy) return;
    _orderBusy = true;
    try {
        const n = await processOrderEvents();
        if (n > 0) console.log(`[scheduler] ${n} orden(es) procesada(s)`);
    } catch (err) {
        console.error('[scheduler] order tick error:', err.message);
    } finally {
        _orderBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Janitor de jobs zombie
// ----------------------------------------------------------------------------

/**
 * Marca como 'failed' los jobs en status='running' cuyo last_seen_at quedó
 * desfasado por más de ZOMBIE_TIMEOUT_MIN minutos. Esto pasa cuando el worker
 * crashea/reinicia a mitad de un job: claimJob() solo toma 'pending', así que
 * el job queda colgado y el plugin pollea infinitamente.
 *
 * Conservador a propósito:
 *   - No revive a 'pending' (evita doble PUT a ML).
 *   - Requiere last_seen_at IS NOT NULL para no matar jobs que recién empezaron
 *     y todavía no escribieron el campo (los `claimJob` setea started_at pero
 *     NOT last_seen_at hasta el primer step).
 *   - Threshold ≥ 5min (clamp) — operación normal updatea last_seen_at cada PUT.
 *
 * @returns {Promise<number>} cantidad de jobs marcados.
 */
async function reclaimZombieJobs() {
    const r = await query(
        `UPDATE jobs
         SET status = 'failed',
             finished_at = NOW(),
             message = COALESCE(NULLIF(message, ''), 'Worker timeout') || ' [reclaimed: sin actividad >${ZOMBIE_TIMEOUT_MIN}min]'
         WHERE status = 'running'
           AND last_seen_at IS NOT NULL
           AND last_seen_at < NOW() - ($1 || ' minutes')::interval
         RETURNING public_id, type`,
        [String(ZOMBIE_TIMEOUT_MIN)]
    );
    if (r.rowCount) {
        const ids = r.rows.map((j) => `${j.public_id}(${j.type})`).join(', ');
        console.warn(`[scheduler] zombie reclaim — ${r.rowCount} job(s) marcados failed: ${ids}`);
    }
    return r.rowCount;
}

async function zombieTick() {
    if (_zombieBusy) return;
    _zombieBusy = true;
    try {
        await reclaimZombieJobs();
    } catch (err) {
        console.error('[scheduler] zombie tick error:', err.message);
    } finally {
        _zombieBusy = false;
    }
}

// ----------------------------------------------------------------------------
// Arranque
// ----------------------------------------------------------------------------

/**
 * Arranca los loops del scheduler. Llamado una vez desde server.js.
 */
export function startScheduler() {
    // Loop 1 — autosync periódico.
    if (AUTOSYNC_ENABLED) {
        console.log(`[scheduler] autosync — resync cada ${INTERVAL_HOURS}h, chequeo cada ${Math.round(CHECK_INTERVAL / 1000)}s`);
        setTimeout(() => {
            tick().catch((e) => console.error('[scheduler] first autosync tick uncaught:', e));
            setInterval(() => { tick().catch((e) => console.error('[scheduler] autosync tick uncaught:', e)); }, CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] autosync deshabilitado (WFTN_AUTOSYNC_ENABLED=0)');
    }

    // Loop 2 — webhook debouncer.
    if (WEBHOOK_ENABLED) {
        console.log(`[scheduler] webhook debouncer — agrupando cada ${Math.round(WEBHOOK_BATCH_INTERVAL / 1000)}s`);
        setTimeout(() => {
            webhookTick().catch((e) => console.error('[scheduler] first webhook tick uncaught:', e));
            setInterval(() => { webhookTick().catch((e) => console.error('[scheduler] webhook tick uncaught:', e)); }, WEBHOOK_BATCH_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] webhook debouncer deshabilitado (WFTN_WEBHOOK_ENABLED=0)');
    }

    // Loop 3 — procesador de órdenes (ledger de stock).
    if (ORDER_ENABLED) {
        console.log(`[scheduler] procesador de órdenes — cada ${Math.round(ORDER_INTERVAL / 1000)}s`);
        setTimeout(() => {
            orderTick().catch((e) => console.error('[scheduler] first order tick uncaught:', e));
            setInterval(() => { orderTick().catch((e) => console.error('[scheduler] order tick uncaught:', e)); }, ORDER_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] procesador de órdenes deshabilitado (WFTN_ORDER_ENABLED=0)');
    }

    // Loop 4 — janitor de jobs zombie.
    if (ZOMBIE_ENABLED) {
        console.log(`[scheduler] zombie reclaim — chequeo cada ${Math.round(ZOMBIE_CHECK_INTERVAL / 1000)}s, timeout ${ZOMBIE_TIMEOUT_MIN}min`);
        setTimeout(() => {
            zombieTick().catch((e) => console.error('[scheduler] first zombie tick uncaught:', e));
            setInterval(() => { zombieTick().catch((e) => console.error('[scheduler] zombie tick uncaught:', e)); }, ZOMBIE_CHECK_INTERVAL);
        }, FIRST_RUN_DELAY);
    } else {
        console.log('[scheduler] zombie reclaim deshabilitado (WFTN_ZOMBIE_RECLAIM_ENABLED=0)');
    }
}
