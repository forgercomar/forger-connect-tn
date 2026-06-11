/**
 * routes-v1.js — API REST del Central Orchestrator (v1).
 *
 * Todos los endpoints viven bajo /v1/* y se autentican con HMAC shared-secret
 * por cuenta (ver auth.js). La única excepción es /v1/handshake que se
 * autentica con el HUB_SECRET global (mismo que el OAuth bridge), porque es
 * por definición el primer contacto antes de tener un secret de cuenta.
 *
 * Endpoints:
 *
 *   POST /v1/handshake          → registra cuenta (o rota su secret). Auth: HUB.
 *   POST /v1/jobs               → crea un job + sus steps. Auth: cuenta.
 *   GET  /v1/jobs/:job_id       → status + progress. Auth: cuenta.
 *   POST /v1/jobs/:job_id/next-batch → siguiente step (o "done"). Auth: cuenta.
 *   POST /v1/jobs/:job_id/report     → resultado de un step. Auth: cuenta.
 *   POST /v1/jobs/:job_id/cancel     → aborta el job. Auth: cuenta.
 *
 * Convenciones:
 *   - Toda fecha sale como ISO8601 UTC.
 *   - Errores: { ok: false, error: '<code>', message: '<human>' } + status code.
 *   - Éxitos:  { ok: true,  ...data }.
 */

import crypto from 'node:crypto';
import { query, tx } from './db.js';
import {
    verifyRequest,
    generateSecret,
    generatePublicId,
    encryptToken,
} from './auth.js';
import {
    evaluateToken,
    isRevoked,
    licenseConfig,
    LICENSE_TOKEN_HEADER,
} from './license-enforce.js';

// =============================================================================
// Constantes del job runtime
// =============================================================================

// Lease default cuando un plugin "toma" un step (next-batch). Si no reporta
// dentro de este tiempo, el step queda disponible para que otro plugin/worker
// lo tome. 90s es suficiente para batches de 50 items.
const STEP_LEASE_SEC = 90;

// Cantidad máxima de steps por job (anti-explosion: si el cliente pide 1M
// de items, rechazamos en vez de matar Postgres).
const MAX_STEPS_PER_JOB = 5000;

// Job types válidos. Cualquier otro string se rechaza al crear job.
const VALID_JOB_TYPES = new Set([
    'sync_incremental',
    'sync_full',
    'auto_link_sku',
    'push',
]);

// =============================================================================
// Helpers internos
// =============================================================================

function nowIso() { return new Date().toISOString(); }

/**
 * Acceso al body crudo (string). Lo necesitamos para verificar el HMAC, que
 * incluye el sha256 del body original. Express ya lo parseó a req.body, pero
 * el express.json() option `verify` nos permite stashearlo crudo en req.rawBody.
 *
 * (Esa configuración se hace en server.js — acá solo lo leemos.)
 */
function getRawBody(req) {
    return req.rawBody || '';
}

// =============================================================================
// Enforcement del capability-token de licencia (Fase 6) — capa ADICIONAL.
//
// El token viaja en el header X-Wftn-License-Token (independiente de la firma
// HMAC de cuenta, que sigue intacta). Estas helpers deciden si negar el acceso
// según LICENSE_ENFORCE (off | observe | enforce) y la gracia.
// =============================================================================

const GENERIC_LICENSE_ERROR = { ok: false, error: 'license_invalid' };

/** Lee el capability-token crudo del request (case-insensitive vía req.get). */
function getLicenseToken(req) {
    return req.get(LICENSE_TOKEN_HEADER) || '';
}

/**
 * Evalúa el token para un endpoint SIN gracia (handshake).
 *
 * Devuelve { decision: 'allow'|'deny', verdict, cfg }.
 *   - off / observe          → SIEMPRE allow (observe loguea).
 *   - enforce + token válido  → allow.
 *   - enforce + token inválido → deny.
 *
 * NO escribe DB. El caller decide el 403 genérico.
 */
function checkLicenseNoGrace(req, { expectDomain, label } = {}) {
    const token = getLicenseToken(req);
    const { verdict, cfg } = evaluateToken(token, { expectDomain });
    if (!cfg.active) {
        return { decision: 'allow', verdict, cfg };
    }
    if (verdict.valid) {
        if (!cfg.enforcing) console.log(`[license][observe] ${label || 'handshake'} token OK`);
        return { decision: 'allow', verdict, cfg };
    }
    // Inválido. En observe NO bloqueamos: solo medimos quién no manda token OK.
    const lic = verdict.payload && verdict.payload.license_id ? verdict.payload.license_id : '-';
    console.warn(`[license] ${label || 'request'} token inválido reason=${verdict.reason} license_id=${lic} mode=${cfg.mode} -> ${cfg.enforcing ? 'DENY' : 'observe(allow)'}`);
    return { decision: cfg.enforcing ? 'deny' : 'allow', verdict, cfg };
}

/**
 * Evalúa el token para /v1/jobs (sync/push) CON gracia.
 *
 * @param {object} account  fila accounts (necesita id + last_valid_license_token_at).
 *
 * Reglas:
 *   - off / observe → allow (observe loguea); igual sella el watermark si el
 *     token es válido, para que la gracia tenga datos el día que se prenda enforce.
 *   - token válido → allow + sella accounts.last_valid_license_token_at = NOW().
 *   - token inválido + dentro de gracia → allow (no romper por caída de infra).
 *     EXCEPTO si está revocado: el revoke gana SIEMPRE sobre la gracia.
 *   - token inválido + fuera de gracia → deny (solo si enforcing).
 *
 * Devuelve { decision, verdict, cfg, sealed }.
 */
async function checkLicenseWithGrace(req, account, { expectDomain, label } = {}) {
    const token = getLicenseToken(req);
    const { verdict, cfg } = evaluateToken(token, { expectDomain });

    // Token válido: sellar watermark de gracia (fire-and-forget) en cualquier
    // modo activo. No bloquea nada.
    if (cfg.active && verdict.valid) {
        query('UPDATE accounts SET last_valid_license_token_at = NOW() WHERE id = $1', [account.id])
            .catch((e) => console.warn('[license] sello watermark falló:', e.message));
        // En observe logueamos el OK → confirmación visible de que el token llega
        // y verifica (en enforce queda silencioso para no hacer ruido).
        if (!cfg.enforcing) {
            const _lic = String((verdict.payload && verdict.payload.license_id) || '').slice(0, 8);
            const _exp = verdict.payload && typeof verdict.payload.exp === 'number' ? (verdict.payload.exp - Math.floor(Date.now() / 1000)) : '?';
            console.log(`[license][observe] ${label || 'jobs'} token OK license=${_lic} exp_in=${_exp}s`);
        }
        return { decision: 'allow', verdict, cfg, sealed: true };
    }

    if (!cfg.active) {
        return { decision: 'allow', verdict, cfg, sealed: false };
    }

    // Token inválido. El revoke explícito gana SIEMPRE — sin gracia.
    const revoked = isRevoked(verdict);
    let withinGrace = false;
    if (!revoked && cfg.graceSec > 0) {
        const lastTs = account.last_valid_license_token_at
            ? new Date(account.last_valid_license_token_at).getTime()
            : 0;
        if (lastTs > 0) {
            const ageSec = (Date.now() - lastTs) / 1000;
            withinGrace = ageSec <= cfg.graceSec;
        }
    }

    const lic = verdict.payload && verdict.payload.license_id ? verdict.payload.license_id : '-';
    if (revoked) {
        console.warn(`[license] ${label || 'jobs'} REVOCADO license_id=${lic} mode=${cfg.mode} -> ${cfg.enforcing ? 'DENY' : 'observe(allow)'}`);
        return { decision: cfg.enforcing ? 'deny' : 'allow', verdict, cfg, sealed: false };
    }
    if (withinGrace) {
        console.warn(`[license] ${label || 'jobs'} token inválido reason=${verdict.reason} license_id=${lic} mode=${cfg.mode} -> GRACIA(allow)`);
        return { decision: 'allow', verdict, cfg, sealed: false };
    }
    console.warn(`[license] ${label || 'jobs'} token inválido reason=${verdict.reason} license_id=${lic} mode=${cfg.mode} fuera_de_gracia -> ${cfg.enforcing ? 'DENY' : 'observe(allow)'}`);
    return { decision: cfg.enforcing ? 'deny' : 'allow', verdict, cfg, sealed: false };
}

/**
 * Middleware que verifica el HMAC + carga la cuenta en req.account.
 * Usar en las rutas que requieren auth de cuenta.
 */
async function authAccount(req, res, next) {
    const publicId = req.get('X-Wftn-Account') || '';
    const ts       = req.get('X-Wftn-Ts')      || '';
    const sig      = req.get('X-Wftn-Sig')     || '';
    if (!publicId || !ts || !sig) {
        return res.status(401).json({ ok: false, error: 'unauthorized', message: 'Faltan headers de auth.' });
    }
    let acc;
    try {
        const r = await query(
            `SELECT id, public_id, store_id, store_name, store_lang, site_url, shared_secret, revoked_at,
                    last_valid_license_token_at
             FROM accounts WHERE public_id = $1`,
            [publicId]
        );
        acc = r.rows[0];
    } catch (err) {
        return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
    }
    if (!acc || acc.revoked_at) {
        return res.status(401).json({ ok: false, error: 'unknown_account' });
    }
    const verdict = verifyRequest({
        secret: acc.shared_secret,
        method: req.method,
        path: req.originalUrl.split('?')[0], // sin query string
        ts,
        body: getRawBody(req),
        sigGiven: sig,
    });
    if (!verdict.ok) {
        return res.status(401).json({ ok: false, error: 'bad_signature', message: verdict.reason });
    }
    req.account = acc;
    // Bump last_seen para detección de actividad. Fire-and-forget + throttle.
    // Antes pegabamos a Postgres en CADA request /v1/* — con polling agresivo
    // de jobs + multicuenta llegaba a cientos/min y Postgres lo logueaba como
    // slow query. last_seen no necesita precisión sub-minuto, throttle 60s
    // baja el tráfico ~100x sin perder utilidad informativa.
    bumpAccountLastSeenThrottled(acc.id);
    next();
}

const _lastSeenCache = new Map(); // accountId → epoch ms del último bump
const LAST_SEEN_THROTTLE_MS = 60_000; // 1 min entre bumps por cuenta
function bumpAccountLastSeenThrottled(accountId) {
    const now = Date.now();
    const last = _lastSeenCache.get(accountId) || 0;
    if (now - last < LAST_SEEN_THROTTLE_MS) return; // ya bumpeado recientemente
    _lastSeenCache.set(accountId, now);
    query('SELECT bump_account_last_seen($1)', [accountId]).catch((e) =>
        console.warn('[v1] bump_account_last_seen failed:', e.message)
    );
}
// GC del cache cada 10 min: entries más viejas que 1h se pueden borrar para
// no acumular accountIds que ya no se usan. unref para no bloquear shutdown.
setInterval(() => {
    const cutoff = Date.now() - 60 * 60_000;
    for (const [k, v] of _lastSeenCache.entries()) {
        if (v < cutoff) _lastSeenCache.delete(k);
    }
}, 10 * 60_000).unref();

/**
 * Construye el array de steps a insertar según el tipo de job + input.
 *
 * Cada step describe un chunk concreto que el plugin sabe ejecutar.
 *
 * Devuelve `{ steps, totalCount }` donde steps es array de { seq, input }.
 */
function buildStepsForJob(type, params) {
    const chunkSize = Math.max(1, Math.min(500, Number(params.chunk_size) || 50));
    if (type === 'sync_full' || type === 'sync_incremental') {
        // Plugin nos dice cuántos items espera total. Creamos N steps con
        // offset/limit. El plugin va a usar esos params para llamar a ML.
        const total = Number(params.total) || 0;
        if (total <= 0) {
            return { steps: [{ seq: 0, input: { offset: 0, limit: chunkSize, since_ts: params.since_ts || null } }], totalCount: 1 };
        }
        const steps = [];
        let seq = 0;
        for (let offset = 0; offset < total; offset += chunkSize) {
            steps.push({
                seq,
                input: {
                    offset,
                    limit: Math.min(chunkSize, total - offset),
                    since_ts: params.since_ts || null,
                },
            });
            seq++;
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'auto_link_sku') {
        // Plugin nos manda la lista de candidatos (tn_product_id + sku) y los
        // partimos en chunks para procesar.
        const candidates = Array.isArray(params.candidates) ? params.candidates : [];
        const steps = [];
        for (let i = 0, seq = 0; i < candidates.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { candidates: candidates.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    if (type === 'push') {
        const items = Array.isArray(params.items) ? params.items : [];
        const steps = [];
        for (let i = 0, seq = 0; i < items.length; i += chunkSize, seq++) {
            steps.push({
                seq,
                input: { items: items.slice(i, i + chunkSize) },
            });
        }
        return { steps, totalCount: steps.length };
    }
    throw new Error(`Tipo de job desconocido: ${type}`);
}

// =============================================================================
// Mount
// =============================================================================

export function mountV1(app, opts = {}) {
    const HUB_SECRET = opts.hubSecret;
    if (!HUB_SECRET) {
        throw new Error('mountV1: hubSecret requerido');
    }
    // Hardening #25 (2026-05-25): rate-limit por IP. Si el llamador no pasa
    // limiters (compat con tests / standalone), no-op.
    const rlGeneral   = opts.rlGeneral   || ((req, res, next) => next());
    const rlHandshake = opts.rlHandshake || ((req, res, next) => next());
    // Registramos cada ruta con DOS paths: el "limpio" /v1/* y el prefijado
    // /connect-tn/v1/*. Esto es por el reverse proxy de EasyPanel: el dominio
    // forger.com.ar solo enruta /connect-tn/* hacia este container. Con ambas
    // formas registradas, no importa si el
    // proxy strippea o conserva el prefijo: la ruta siempre matchea.
    const p = (path) => [path, '/connect-tn' + path];

    // Rate-limit general aplicado a TODOS los /v1/* — handshake suma su propio
    // limiter más estricto encima (ambos deben pasar).
    app.use(['/v1', '/connect-tn/v1'], rlGeneral);

    // -------------------------------------------------------------------------
    // POST /v1/handshake
    // Body:
    //   {
    //     store_id: number,
    //     store_name: string,
    //     store_lang: string (idioma principal, ej. "es"),
    //     site_url: string,
    //     access_token: string (de TN; lo encriptamos al guardar; NO expira),
    //     scope: string (permisos otorgados al instalar la app),
    //     handshake_sig: base64 HMAC(HUB_SECRET, json sin handshake_sig)
    //   }
    // Respuesta:
    //   { ok: true, account_id: "acc_...", shared_secret: "base64" }
    //
    // Idempotente sobre store_id: si la tienda ya existe, rota el secret y
    // actualiza site_url + access_token.
    // -------------------------------------------------------------------------
    app.post(p('/v1/handshake'), rlHandshake, async (req, res) => {
        const body = req.body || {};
        const sigGiven = String(body.handshake_sig || '');
        if (!sigGiven) {
            return res.status(400).json({ ok: false, error: 'missing_sig' });
        }
        const payloadObj = { ...body };
        delete payloadObj.handshake_sig;
        const payloadStr = JSON.stringify(payloadObj);
        const expectedSig = crypto.createHmac('sha256', HUB_SECRET)
            .update(payloadStr, 'utf8')
            .digest('base64');
        try {
            const a = Buffer.from(expectedSig);
            const b = Buffer.from(sigGiven);
            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
                return res.status(403).json({ ok: false, error: 'bad_sig' });
            }
        } catch (_) {
            return res.status(403).json({ ok: false, error: 'bad_sig' });
        }

        // Hardening #23 (2026-05-25): anti-replay. El body firmado DEBE incluir
        // `ts` (unix seconds) dentro de window ±5min y `nonce` random one-use.
        // Sin esto, capturar UNA vez el body firmado (logs de proxy, MITM
        // histórico, backup) permitía rotar el shared_secret de la cuenta a
        // perpetuidad → robo de cuenta.
        const ts = Number(body.ts || 0);
        const reqNonce = String(body.nonce || '').trim();
        if (!ts || !reqNonce) {
            return res.status(400).json({ ok: false, error: 'missing_anti_replay', message: 'Falta ts o nonce en el body firmado.' });
        }
        const nowSec = Math.floor(Date.now() / 1000);
        if (Math.abs(nowSec - ts) > 300) {
            return res.status(400).json({ ok: false, error: 'ts_window', message: 'Timestamp fuera de la ventana ±5min.' });
        }
        try {
            const dup = await query(
                `INSERT INTO request_nonces (nonce, purpose, created_at) VALUES ($1, $2, $3)
                 ON CONFLICT (nonce, purpose) DO NOTHING RETURNING nonce`,
                [reqNonce, 'handshake', nowSec]
            );
            if (dup.rowCount === 0) {
                return res.status(409).json({ ok: false, error: 'replay', message: 'Este request ya se procesó.' });
            }
        } catch (e) {
            console.error('[handshake] nonce insert error:', e.message);
            return res.status(500).json({ ok: false, error: 'nonce_check_failed' });
        }

        const storeId  = Number(body.store_id);
        const siteUrl  = String(body.site_url || '').trim();
        const nick     = String(body.store_name || '').trim();
        const lang     = String(body.store_lang  || '').trim();
        const scope    = String(body.scope || '').trim();
        const accessT  = String(body.access_token || '').trim();
        if (!storeId || !siteUrl) {
            return res.status(400).json({ ok: false, error: 'missing_fields', message: 'store_id y site_url son obligatorios.' });
        }

        // Enforcement de licencia (Fase 6) — capa ADICIONAL sobre el HMAC del
        // HUB_SECRET ya verificado arriba. El handshake es "entrada nueva": NO
        // tiene gracia. Solo bloquea si LICENSE_ENFORCE=enforce; observe loguea.
        // 403 genérico al cliente; el reason detallado solo a log.
        const licCheck = checkLicenseNoGrace(req, { expectDomain: siteUrl, label: 'handshake' });
        if (licCheck.decision === 'deny') {
            return res.status(403).json(GENERIC_LICENSE_ERROR);
        }

        const newSecret = generateSecret();
        let enc = { ciphertext: '', iv: '' };
        if (accessT) {
            try {
                enc = encryptToken(accessT);
            } catch (err) {
                return res.status(500).json({ ok: false, error: 'crypto_failed', message: err.message });
            }
        }

        try {
            // Upsert sobre store_id (la unique partial index excluye revocadas).
            const existing = await query(
                `SELECT id, public_id FROM accounts WHERE store_id = $1 AND revoked_at IS NULL`,
                [storeId]
            );
            let accId, accPublic;
            if (existing.rowCount > 0) {
                accId = existing.rows[0].id;
                accPublic = existing.rows[0].public_id;
                await query(
                    `UPDATE accounts
                     SET store_name = $2,
                         store_lang  = $3,
                         site_url    = $4,
                         shared_secret = $5,
                         access_token_enc = COALESCE(NULLIF($6, ''), access_token_enc),
                         access_token_iv  = COALESCE(NULLIF($7, ''), access_token_iv),
                         scope            = COALESCE(NULLIF($8, ''), scope)
                     WHERE id = $1`,
                    [accId, nick, lang, siteUrl, newSecret, enc.ciphertext, enc.iv, scope]
                );
            } else {
                accPublic = generatePublicId('acc');
                const ins = await query(
                    `INSERT INTO accounts
                        (public_id, store_id, store_name, store_lang, site_url,
                         shared_secret, access_token_enc, access_token_iv, scope)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                     RETURNING id`,
                    [accPublic, storeId, nick, lang, siteUrl, newSecret, enc.ciphertext, enc.iv, scope]
                );
                accId = ins.rows[0].id;
            }

            return res.json({
                ok: true,
                account_id: accPublic,
                shared_secret: newSecret,
                rotated: existing.rowCount > 0,
            });
        } catch (err) {
            console.error('[handshake] db error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs
    // Body:
    //   {
    //     type: 'sync_full' | 'sync_incremental' | 'auto_link_sku' | 'push',
    //     params: {...}    // depende del tipo (ver buildStepsForJob)
    //   }
    // Respuesta:
    //   { ok: true, job_id: "job_...", steps_total: N, status: "pending" }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs'), authAccount, async (req, res) => {
        // Enforcement de licencia (Fase 6) CON gracia: si el token falta/expiró
        // pero la cuenta tuvo uno válido dentro de GRACE_PERIOD_SEC, se permite
        // (no romper operación por caída de infra). El revoke explícito gana
        // sobre la gracia. Solo bloquea si LICENSE_ENFORCE=enforce.
        let licJob;
        try {
            licJob = await checkLicenseWithGrace(req, req.account, {
                expectDomain: req.account.site_url,
                label: 'jobs',
            });
        } catch (e) {
            // fail-safe: si el chequeo de licencia explota, NO cortamos la
            // operación (la auth HMAC ya pasó). Logueamos y seguimos.
            console.warn('[license] checkLicenseWithGrace error (allow):', e.message);
            licJob = { decision: 'allow' };
        }
        if (licJob.decision === 'deny') {
            return res.status(403).json(GENERIC_LICENSE_ERROR);
        }

        const body = req.body || {};
        const type = String(body.type || '');
        if (!VALID_JOB_TYPES.has(type)) {
            return res.status(400).json({ ok: false, error: 'bad_type', message: `type debe ser uno de: ${[...VALID_JOB_TYPES].join(', ')}` });
        }
        const params = body.params && typeof body.params === 'object' ? body.params : {};
        const jobPublic = generatePublicId('job');

        // Jobs ejecutados por el worker del central (sync_* y push): NO pre-crean
        // steps — el worker los procesa solo (pagina ML, o ejecuta los PUT del
        // push masivo). auto_link_sku sigue siendo modelo A: pre-crea steps que
        // el plugin ejecuta.
        const isWorkerJob = (type === 'sync_full' || type === 'sync_incremental' || type === 'push');

        if (isWorkerJob) {
            try {
                await query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, 0)`,
                    [jobPublic, req.account.id, type, JSON.stringify(params)]
                );
            } catch (err) {
                console.error('[v1/jobs] create sync error:', err);
                return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
            }
            return res.json({
                ok: true,
                job_id: jobPublic,
                type,
                status: 'pending',
                steps_total: 0, // el worker lo va a setear al descubrir el total
            });
        }

        // Jobs con steps pre-calculados (push / auto_link_sku).
        let plan;
        try {
            plan = buildStepsForJob(type, params);
        } catch (err) {
            return res.status(400).json({ ok: false, error: 'bad_params', message: err.message });
        }
        if (plan.totalCount > MAX_STEPS_PER_JOB) {
            return res.status(400).json({ ok: false, error: 'too_many_steps', message: `El job genera ${plan.totalCount} steps; máximo permitido: ${MAX_STEPS_PER_JOB}. Usá un chunk_size más grande.` });
        }
        if (plan.totalCount === 0) {
            return res.status(400).json({ ok: false, error: 'empty_job', message: 'El job no tiene work — nada que procesar.' });
        }

        try {
            await tx(async (client) => {
                const ins = await client.query(
                    `INSERT INTO jobs (public_id, account_id, type, status, input, steps_total)
                     VALUES ($1, $2, $3, 'pending', $4, $5)
                     RETURNING id`,
                    [jobPublic, req.account.id, type, JSON.stringify(params), plan.totalCount]
                );
                const jobId = ins.rows[0].id;
                const values = [];
                const placeholders = [];
                let p = 1;
                for (const s of plan.steps) {
                    const stepPublic = generatePublicId('stp');
                    placeholders.push(`($${p++}, $${p++}, $${p++}, 'queued', $${p++})`);
                    values.push(stepPublic, jobId, s.seq, JSON.stringify(s.input));
                }
                await client.query(
                    `INSERT INTO job_steps (public_id, job_id, seq, status, input)
                     VALUES ${placeholders.join(',')}`,
                    values
                );
            });
        } catch (err) {
            console.error('[v1/jobs] create error:', err);
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }

        return res.json({
            ok: true,
            job_id: jobPublic,
            type,
            status: 'pending',
            steps_total: plan.totalCount,
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id
    // Respuesta:
    //   { ok: true, job: { id, type, status, steps_total, steps_done, steps_failed,
    //                      created_at, started_at, finished_at, message, result } }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT public_id, type, status, steps_total, steps_done, steps_failed,
                    input, result, created_at, started_at, finished_at, message
             FROM jobs
             WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const j = r.rows[0];
        return res.json({
            ok: true,
            job: {
                id: j.public_id,
                type: j.type,
                status: j.status,
                steps_total: j.steps_total,
                steps_done: j.steps_done,
                steps_failed: j.steps_failed,
                input: j.input,
                result: j.result,
                created_at: j.created_at,
                started_at: j.started_at,
                finished_at: j.finished_at,
                message: j.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/next-batch
    // Devuelve el próximo step disponible (queued) y lo marca como leased.
    // Si no hay más → ok: true, done: true.
    //
    // El plugin debe procesar el step y luego llamar /report. Si tarda más del
    // lease (STEP_LEASE_SEC), otro pull puede tomarlo de nuevo (idempotencia).
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/next-batch'), authAccount, async (req, res) => {
        // 1) Validar que el job pertenece a esta cuenta y no está finalizado.
        const j = await query(
            `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobRow = j.rows[0];
        if (['done', 'failed', 'cancelled'].includes(jobRow.status)) {
            return res.json({ ok: true, done: true, status: jobRow.status });
        }

        // 2) Tomar el primer step disponible (queued) o leased-expirado.
        //    UPDATE ... RETURNING para atomicidad sin race condition.
        const leaseUntil = new Date(Date.now() + STEP_LEASE_SEC * 1000);
        const upd = await query(
            `UPDATE job_steps SET
                status = 'leased',
                leased_until = $2,
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW())
             WHERE id = (
                SELECT id FROM job_steps
                WHERE job_id = $1
                  AND (status = 'queued' OR (status = 'leased' AND leased_until < NOW()))
                ORDER BY seq ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
             )
             RETURNING public_id, seq, input`,
            [jobRow.id, leaseUntil]
        );

        if (!upd.rowCount) {
            // No quedan steps. Marcar el job como done si todo finalizó.
            await query(
                `UPDATE jobs SET status = 'done', finished_at = NOW(),
                                 message = COALESCE(message, 'Job completado.')
                 WHERE id = $1 AND status NOT IN ('done','failed','cancelled')
                   AND NOT EXISTS (
                       SELECT 1 FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')
                   )`,
                [jobRow.id]
            );
            return res.json({ ok: true, done: true });
        }

        // 3) Marcar job como running si era pending (primer step tomado).
        if (jobRow.status === 'pending') {
            await query(
                `UPDATE jobs SET status = 'running', started_at = COALESCE(started_at, NOW())
                 WHERE id = $1 AND status = 'pending'`,
                [jobRow.id]
            );
        }

        const step = upd.rows[0];
        return res.json({
            ok: true,
            done: false,
            step: {
                id: step.public_id,
                seq: step.seq,
                input: step.input,
                lease_expires_at: leaseUntil.toISOString(),
            },
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/report
    // Body:
    //   {
    //     step_id: "stp_...",
    //     result: 'done' | 'failed' | 'skipped',
    //     output: {...},
    //     error?: string
    //   }
    // Respuesta:
    //   { ok: true, job: { steps_done, steps_failed, status, message } }
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/report'), authAccount, async (req, res) => {
        const body = req.body || {};
        const stepId = String(body.step_id || '');
        const result = String(body.result  || '');
        const output = body.output || {};
        const errorMsg = body.error ? String(body.error).slice(0, 1024) : null;

        if (!stepId || !['done','failed','skipped'].includes(result)) {
            return res.status(400).json({ ok: false, error: 'bad_params' });
        }

        let updated;
        try {
            updated = await tx(async (client) => {
                // Cargar job + step + chequear ownership.
                const j = await client.query(
                    `SELECT id, status FROM jobs WHERE public_id = $1 AND account_id = $2 FOR UPDATE`,
                    [req.params.job_id, req.account.id]
                );
                if (!j.rowCount) throw new Error('job_not_found');
                const job = j.rows[0];

                const s = await client.query(
                    `SELECT id, status FROM job_steps
                     WHERE public_id = $1 AND job_id = $2 FOR UPDATE`,
                    [stepId, job.id]
                );
                if (!s.rowCount) throw new Error('step_not_found');
                const step = s.rows[0];
                if (['done','failed','skipped'].includes(step.status)) {
                    // Idempotente: si ya está finalizado, no re-procesamos.
                    // Devolvemos el job actualizado sin cambios.
                } else {
                    await client.query(
                        `UPDATE job_steps SET
                            status = $2,
                            output = $3,
                            last_error = $4,
                            finished_at = NOW()
                         WHERE id = $1`,
                        [step.id, result, JSON.stringify(output), errorMsg]
                    );
                    // Actualizar counters del job.
                    if (result === 'done' || result === 'skipped') {
                        await client.query(`UPDATE jobs SET steps_done = steps_done + 1 WHERE id = $1`, [job.id]);
                    } else if (result === 'failed') {
                        await client.query(`UPDATE jobs SET steps_failed = steps_failed + 1, message = $2 WHERE id = $1`, [job.id, errorMsg]);
                    }
                }

                // ¿Quedan steps pendientes?
                const pending = await client.query(
                    `SELECT COUNT(*) AS n FROM job_steps WHERE job_id = $1 AND status IN ('queued','leased')`,
                    [job.id]
                );
                const remaining = Number(pending.rows[0].n);
                if (remaining === 0) {
                    // Job terminado. Decidir done vs failed.
                    const counts = await client.query(
                        `SELECT steps_total, steps_done, steps_failed FROM jobs WHERE id = $1`,
                        [job.id]
                    );
                    const c = counts.rows[0];
                    const allOk = c.steps_failed === 0;
                    await client.query(
                        `UPDATE jobs SET status = $2, finished_at = NOW(),
                                         message = COALESCE(message, $3)
                         WHERE id = $1`,
                        [job.id, allOk ? 'done' : 'failed', allOk ? 'Job completado.' : 'Job completado con errores.']
                    );
                }
                const fin = await client.query(
                    `SELECT status, steps_total, steps_done, steps_failed, message FROM jobs WHERE id = $1`,
                    [job.id]
                );
                return fin.rows[0];
            });
        } catch (err) {
            const code = (err.message === 'job_not_found' || err.message === 'step_not_found') ? 404 : 500;
            return res.status(code).json({ ok: false, error: err.message });
        }

        return res.json({
            ok: true,
            job: {
                status: updated.status,
                steps_total: updated.steps_total,
                steps_done: updated.steps_done,
                steps_failed: updated.steps_failed,
                message: updated.message,
            },
        });
    });

    // -------------------------------------------------------------------------
    // GET /v1/jobs/:job_id/results?offset=&limit=
    // Devuelve los items que el worker sincronizó para este job, paginados.
    // El plugin los baja en lotes y los aplica a su wf_ml_items local.
    //
    // Idempotente: no marca nada al leer. El plugin puede re-bajar sin riesgo
    // (su upsert local es idempotente). Para liberar espacio, cuando el plugin
    // termina de bajar todo llama a POST /v1/jobs/:id/ack.
    //
    // Respuesta:
    //   { ok: true, items: [ <item_data>, ... ], total: N, offset, limit }
    // -------------------------------------------------------------------------
    app.get(p('/v1/jobs/:job_id/results'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const jobId = j.rows[0].id;

        const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
        const limit  = Math.max(1, Math.min(1000, parseInt(req.query.limit, 10) || 500));

        const totalR = await query(
            `SELECT COUNT(*) AS n FROM synced_items WHERE job_id = $1`,
            [jobId]
        );
        const total = Number(totalR.rows[0].n);

        const rowsR = await query(
            `SELECT item_data FROM synced_items
             WHERE job_id = $1
             ORDER BY id ASC
             LIMIT $2 OFFSET $3`,
            [jobId, limit, offset]
        );
        return res.json({
            ok: true,
            items: rowsR.rows.map((r) => r.item_data),
            total,
            offset,
            limit,
        });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/ack
    // El plugin confirma que bajó y aplicó todos los resultados. Marcamos los
    // synced_items como delivered para que el cron de retención los limpie.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/ack'), authAccount, async (req, res) => {
        const j = await query(
            `SELECT id FROM jobs WHERE public_id = $1 AND account_id = $2`,
            [req.params.job_id, req.account.id]
        );
        if (!j.rowCount) return res.status(404).json({ ok: false, error: 'not_found' });
        const r = await query(
            `UPDATE synced_items SET delivered_at = NOW()
             WHERE job_id = $1 AND delivered_at IS NULL`,
            [j.rows[0].id]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // GET /v1/sync/pending
    // ¿Hay resultados de sync sin bajar para esta cuenta? Lo usa el plugin al
    // cargar el admin para detectar los syncs que dejó el cron automático
    // mientras el operador no estaba.
    //
    // Devuelve la lista de jobs con synced_items pendientes (delivered_at NULL),
    // del más viejo al más nuevo, para que el plugin los baje en orden.
    //
    // Solo se reportan jobs en estado 'done': mientras el worker todavía está
    // paginando ('running') va insertando synced_items, y si el plugin drenara
    // + ack en ese momento marcaría como entregadas filas que el worker
    // todavía no terminó de escribir. Esperando a 'done' la descarga es segura.
    //
    // Respuesta:
    //   { ok: true, pending: bool, jobs: [{ job_id, count, synced_at }], total }
    // -------------------------------------------------------------------------
    app.get(p('/v1/sync/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT j.public_id AS job_id,
                    COUNT(si.id)::int AS count,
                    MAX(si.synced_at) AS synced_at
             FROM synced_items si
             JOIN jobs j ON j.id = si.job_id
             WHERE si.account_id = $1
               AND si.delivered_at IS NULL
               AND j.status = 'done'
             GROUP BY j.public_id
             ORDER BY MAX(si.synced_at) ASC`,
            [req.account.id]
        );
        const jobs = r.rows.map((row) => ({
            job_id: row.job_id,
            count: row.count,
            synced_at: row.synced_at,
        }));
        const total = jobs.reduce((s, j) => s + j.count, 0);
        return res.json({ ok: true, pending: jobs.length > 0, jobs, total });
    });

    // -------------------------------------------------------------------------
    // GET /v1/orders/pending
    // Órdenes ML ya procesadas (el central bajó la orden de ML) que el plugin
    // todavía no aplicó a su ledger de stock. Una fila por orden — la más
    // reciente procesada, porque una orden puede generar varios webhooks. El
    // plugin descuenta/repone stock según el status.
    //
    // Respuesta:
    //   { ok: true, orders: [{ tn_order_id, status, items: [...] }] }
    // -------------------------------------------------------------------------
    app.get(p('/v1/orders/pending'), authAccount, async (req, res) => {
        const r = await query(
            `SELECT DISTINCT ON (tn_order_id)
                    tn_order_id, order_status, items_json
             FROM order_events
             WHERE account_id = $1
               AND processed_at IS NOT NULL
               AND delivered_at IS NULL
               AND error IS NULL
             ORDER BY tn_order_id, processed_at DESC`,
            [req.account.id]
        );
        const orders = r.rows.map((row) => ({
            tn_order_id: row.tn_order_id,
            status:      row.order_status,
            items:       Array.isArray(row.items_json) ? row.items_json : [],
        }));
        return res.json({ ok: true, orders });
    });

    // -------------------------------------------------------------------------
    // POST /v1/orders/ack
    // Body: { tn_order_ids: ["123", ...] }   (acepta ml_order_ids como fallback legacy)
    // El plugin confirma que aplicó esas órdenes a su ledger. Marcamos todas
    // las order_events de esas órdenes como delivered.
    // -------------------------------------------------------------------------
    app.post(p('/v1/orders/ack'), authAccount, async (req, res) => {
        const rawIds = (req.body && (req.body.tn_order_ids || req.body.ml_order_ids)) || null;
        const ids = Array.isArray(rawIds)
            ? rawIds.map(String).filter(Boolean)
            : [];
        if (!ids.length) return res.json({ ok: true, marked: 0 });
        const r = await query(
            `UPDATE order_events SET delivered_at = NOW()
             WHERE account_id = $1 AND tn_order_id = ANY($2::text[]) AND delivered_at IS NULL`,
            [req.account.id, ids]
        );
        return res.json({ ok: true, marked: r.rowCount });
    });

    // -------------------------------------------------------------------------
    // POST /v1/jobs/:job_id/cancel
    // Marca el job y todos sus steps queued/leased como cancelled.
    // -------------------------------------------------------------------------
    app.post(p('/v1/jobs/:job_id/cancel'), authAccount, async (req, res) => {
        try {
            const r = await query(
                `UPDATE jobs SET status = 'cancelled', finished_at = NOW(),
                                 message = COALESCE(message, 'Cancelado por el usuario.')
                 WHERE public_id = $1 AND account_id = $2
                   AND status IN ('pending','running')
                 RETURNING id`,
                [req.params.job_id, req.account.id]
            );
            if (!r.rowCount) return res.status(404).json({ ok: false, error: 'not_cancelable' });
            await query(
                `UPDATE job_steps SET status = 'skipped', last_error = 'cancelled', finished_at = NOW()
                 WHERE job_id = $1 AND status IN ('queued','leased')`,
                [r.rows[0].id]
            );
            return res.json({ ok: true, cancelled: true });
        } catch (err) {
            return res.status(500).json({ ok: false, error: 'db_error', message: err.message });
        }
    });
}
