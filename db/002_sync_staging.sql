-- =============================================================================
-- 002_sync_staging.sql — Staging de items sincronizados + cache de access_token.
--
-- Modelo B-pull: el worker del central trae productos de TN y los deja acá. El
-- plugin después los baja vía GET /v1/jobs/:id/results y los aplica a su
-- wf_tn_items local. Una vez bajados se marcan delivered_at y un cron los
-- limpia pasados unos días.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- accounts: columnas para el access_token de TiendaNube.
-- -----------------------------------------------------------------------------
-- El worker necesita el access_token para llamar a la API de TN. En TiendaNube
-- el token NO expira: se guarda una vez (cifrado AES-256-GCM) al conectar y se
-- reusa siempre. No hay refresh ni expiración.
ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS access_token_enc  TEXT,
    ADD COLUMN IF NOT EXISTS access_token_iv   TEXT;

-- -----------------------------------------------------------------------------
-- synced_items: items traídos de ML, esperando que el plugin los baje.
-- -----------------------------------------------------------------------------
-- item_data es un JSONB con el row COMPLETO listo para upsert en wf_tn_items
-- del plugin. El worker lo arma en Node; el plugin lo aplica tal cual sin
-- tener que re-mapear campo por campo. Flexible ante cambios de schema.
CREATE TABLE IF NOT EXISTS synced_items (
    id            BIGSERIAL PRIMARY KEY,
    account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    job_id        BIGINT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    -- Identidad del producto TN (para dedup + orden estable al paginar resultados).
    tn_product_id VARCHAR(32) NOT NULL,
    variant_id    BIGINT,                       -- NULL = fila del producto padre
    -- Row completo para wf_tn_items, serializado.
    item_data     JSONB NOT NULL,
    -- Timeline.
    synced_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at  TIMESTAMPTZ                   -- NULL = pendiente de bajar
);

-- -----------------------------------------------------------------------------
-- Índices de synced_items
-- -----------------------------------------------------------------------------
-- Bajar resultados de un job, ordenados y paginables.
CREATE INDEX IF NOT EXISTS synced_items_job_idx
    ON synced_items (job_id, id);
-- Buscar lo no entregado de una cuenta (cuando el plugin pregunta "¿hay algo
-- nuevo para mí?" sin un job_id específico).
CREATE INDEX IF NOT EXISTS synced_items_pending_idx
    ON synced_items (account_id, delivered_at) WHERE delivered_at IS NULL;
-- Cleanup de entregados viejos.
CREATE INDEX IF NOT EXISTS synced_items_delivered_idx
    ON synced_items (delivered_at) WHERE delivered_at IS NOT NULL;
