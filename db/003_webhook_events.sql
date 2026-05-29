-- =============================================================================
-- 003_webhook_events.sql — Cola de eventos de webhooks de TiendaNube (product/*).
--
-- TN manda webhooks (event 'product/created|updated|deleted') cada vez que cambia
-- algo en un producto. El central NO los forwardea al WP del cliente — eso
-- exigiría que el WordPress sea públicamente accesible. En su lugar los guarda
-- acá; el debouncer del scheduler los agrupa por cuenta y encola UN job
-- sync_incremental con la lista de productos afectados.
--
-- Modelo pull: el plugin baja el resultado, igual que el sync automático.
-- El debounce (agrupar) absorbe las ráfagas de webhooks que manda TN cuando
-- el operador edita muchos productos de una.
-- =============================================================================

CREATE TABLE IF NOT EXISTS webhook_events (
    id           BIGSERIAL PRIMARY KEY,
    account_id   BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    -- Producto TN afectado (el `id` del payload del webhook).
    tn_product_id   VARCHAR(32) NOT NULL,
    -- Evento original de TN ('product/updated', ...). Informativo.
    topic        TEXT NOT NULL,
    -- Timeline. processed_at NULL = todavía no se agrupó en un job.
    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- El debouncer escanea lo pendiente por cuenta — índice parcial sobre eso.
CREATE INDEX IF NOT EXISTS webhook_events_pending_idx
    ON webhook_events (account_id, id) WHERE processed_at IS NULL;
-- Cleanup de procesados viejos.
CREATE INDEX IF NOT EXISTS webhook_events_processed_idx
    ON webhook_events (processed_at) WHERE processed_at IS NOT NULL;
