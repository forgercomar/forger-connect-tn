-- =============================================================================
-- WooForger Central Orchestrator — Schema inicial.
--
-- Este schema vive en wf-postgres (mismo Docker que el connect-tn).
-- Provee la base para coordinar jobs de sync/push entre múltiples plugins
-- WordPress clientes y el motor central que vive en forger.com.ar.
--
-- Modelo conceptual:
--
--   accounts          → una fila por cada conexión OAuth de TiendaNube de cada cliente.
--                       Acá vive el shared_secret (HMAC) que firma todo lo que
--                       el plugin manda al central, y un puntero al site_url
--                       del cliente para webhooks de vuelta.
--
--   jobs              → un trabajo (sync incremental, sync completo, auto-link,
--                       push masivo) con su estado de máquina (pending → running
--                       → done|failed|cancelled). Asociado a 1 account.
--
--   job_steps         → cada job se parte en N pasos (chunks). El plugin pide
--                       "siguiente paso", lo procesa, reporta el resultado.
--                       Cada step es atómico, retryable, e idempotente.
--
-- Convenciones:
--   - Todos los timestamps son TIMESTAMPTZ (UTC).
--   - IDs públicos son TEXT con prefijo legible (acc_, job_, stp_) generados
--     desde Node, para facilitar troubleshooting en logs.
--   - El access_token de TiendaNube (no expira) se guarda encriptado con
--     AES-256-GCM. La key vive en env var WFTN_TOKEN_KEY (rotable), nunca en la DB.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- accounts: mapping tienda TiendaNube ↔ cliente WP
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
    id               BIGSERIAL PRIMARY KEY,
    public_id        TEXT NOT NULL UNIQUE,         -- ej. "acc_a3f9..."
    -- Datos de la tienda TiendaNube (store_id la identifica unívocamente; no se
    -- duplica si la misma tienda se conecta desde dos sitios WP distintos).
    store_id         BIGINT NOT NULL,
    store_name       TEXT,
    store_lang       TEXT,                          -- idioma principal (ej. "es", "pt")
    -- TiendaNube: el access_token NO expira y NO hay refresh_token. El token se
    -- guarda cifrado (AES-256-GCM) en access_token_enc/_iv (ver 002). `scope`
    -- son los permisos otorgados al instalar la app.
    scope            TEXT,
    -- Cliente WP que tiene esta tienda conectada.
    site_url         TEXT NOT NULL,                 -- ej. "https://cliente.com"
    -- Shared secret HMAC que firma TODO request plugin↔central.
    -- También en base64. NUNCA se loguea ni se devuelve después del handshake.
    shared_secret    TEXT NOT NULL,
    -- Métricas y housekeeping.
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ,                   -- último request del plugin
    revoked_at       TIMESTAMPTZ,                   -- soft delete; si != NULL no se usa
    notes            TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS accounts_store_idx
    ON accounts (store_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS accounts_site_url_idx ON accounts (site_url);


-- -----------------------------------------------------------------------------
-- jobs: trabajos orquestados por el central
-- -----------------------------------------------------------------------------
-- type:
--   'sync_incremental'  → trae items modificados desde last_sync_at
--   'sync_full'         → trae TODOS los items del seller
--   'auto_link_sku'     → vincula items ML con productos WC por SKU exacto
--   'push'              → pushea price/stock a ML para items con cambios pendientes
--
-- status flow:
--   pending  → recién creado, esperando workerOR plugin para arrancar
--   running  → al menos un step se está procesando
--   done     → todos los steps completos
--   failed   → uno o más steps fallaron sin recuperación posible
--   cancelled→ el cliente lo abortó voluntariamente
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,          -- ej. "job_b8e2..."
    account_id      BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    -- Payload de input (parámetros del job, ej. cuenta a sincronizar, modo, etc.).
    -- Lo necesitamos para reanudar después de un crash sin perder contexto.
    input           JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Resumen acumulado de resultados (steps_done, items_pushed, errors_count).
    -- Se actualiza atómicamente desde report_step. Permite GET /jobs/:id rápido.
    result          JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Progress counters (denormalizados para queries rápidas; las cuentas reales
    -- siempre se pueden derivar de job_steps).
    steps_total     INTEGER NOT NULL DEFAULT 0,
    steps_done      INTEGER NOT NULL DEFAULT 0,
    steps_failed    INTEGER NOT NULL DEFAULT 0,
    -- Timeline.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    -- Quién hizo el último change (audit). Útil cuando hay dashboard.
    last_seen_at    TIMESTAMPTZ,
    -- Mensaje user-facing del último estado (last error, último step, etc.).
    message         TEXT,
    -- Constraint blando: status válidos.
    CHECK (status IN ('pending','running','done','failed','cancelled')),
    CHECK (type IN ('sync_incremental','sync_full','auto_link_sku','push'))
);

CREATE INDEX IF NOT EXISTS jobs_account_idx ON jobs (account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs (status) WHERE status IN ('pending','running');
-- Búsqueda "último job de tipo X de la cuenta Y": muy frecuente en UI.
CREATE INDEX IF NOT EXISTS jobs_account_type_idx ON jobs (account_id, type, created_at DESC);


-- -----------------------------------------------------------------------------
-- job_steps: unidades de trabajo individuales
-- -----------------------------------------------------------------------------
-- Cada step es un chunk (ej. "traer items 0..49 de ML para account 5").
-- El plugin pide siguiente step via /v1/jobs/:id/next-batch y reporta su
-- ejecución con /v1/jobs/:id/report. El step queda en la cola hasta que se
-- procesa con éxito o agota retries.
--
-- status flow:
--   queued   → listo para ser tomado
--   leased   → un plugin lo "tomó" y está procesando (con expiry → vuelve a queued)
--   done     → completado OK
--   failed   → falló todos los retries (job entero podría seguir o marcarse failed)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS job_steps (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,
    job_id          BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    -- Orden lógico dentro del job (chunk 0, chunk 1, ...). El central elige
    -- el step con menor seq y status='queued' al servir next-batch.
    seq             INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'queued',
    -- Input del step (qué tiene que hacer el plugin). Ejemplos:
    --   sync_full:     { "offset": 0, "limit": 50 }
    --   auto_link_sku: { "ml_item_ids": ["MLA1","MLA2",...] }
    --   push:          { "items": [{"tn_product_id":"MLA1","mode":"all"}, ...] }
    input           JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Output reportado por el plugin (counts, errors, etc.).
    output          JSONB,
    -- Retry counters y errores.
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    -- Lease: cuando un plugin toma el step, lockeamos hasta `leased_until`.
    -- Si el plugin no reporta antes del timeout, otro puede tomarlo.
    leased_until    TIMESTAMPTZ,
    -- Timeline.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    CHECK (status IN ('queued','leased','done','failed','skipped')),
    UNIQUE (job_id, seq)
);

CREATE INDEX IF NOT EXISTS job_steps_next_idx
    ON job_steps (job_id, status, seq) WHERE status = 'queued';
-- Para reclaim de leases expirados (worker que pollea steps "abandonados").
CREATE INDEX IF NOT EXISTS job_steps_leased_idx
    ON job_steps (leased_until) WHERE status = 'leased';


-- -----------------------------------------------------------------------------
-- Función helper: bump_account_last_seen
-- -----------------------------------------------------------------------------
-- Cada request autenticado del plugin pasa por acá para actualizar la
-- "última vez que vimos" la cuenta. Es informativo (dashboard) y permite
-- detectar plugins instalados-pero-inactivos para limpieza eventual.
CREATE OR REPLACE FUNCTION bump_account_last_seen(p_account_id BIGINT)
RETURNS VOID AS $$
BEGIN
    UPDATE accounts SET last_seen_at = NOW() WHERE id = p_account_id;
END;
$$ LANGUAGE plpgsql;


-- -----------------------------------------------------------------------------
-- View: jobs_summary
-- -----------------------------------------------------------------------------
-- Vista de conveniencia para el dashboard. Trae jobs con info de la cuenta.
CREATE OR REPLACE VIEW jobs_summary AS
SELECT
    j.public_id        AS job_id,
    j.type             AS job_type,
    j.status           AS job_status,
    j.steps_total,
    j.steps_done,
    j.steps_failed,
    j.created_at,
    j.started_at,
    j.finished_at,
    j.message,
    a.public_id        AS account_id,
    a.store_name,
    a.store_lang,
    a.site_url
FROM jobs j
INNER JOIN accounts a ON a.id = j.account_id;
