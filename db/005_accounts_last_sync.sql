-- =============================================================================
-- 005_accounts_last_sync.sql — Watermark de sincronización incremental.
--
-- `last_sync_at` marca hasta cuándo el catálogo de la cuenta está garantizado
-- al día. Un job `sync_incremental` trae solo los items de ML cuyo
-- `last_updated` es posterior a este timestamp (con un margen de seguridad);
-- al terminar un sync full o incremental, el worker lo avanza al `started_at`
-- del job — el INICIO, no el fin, para que nada modificado DURANTE el sync se
-- pierda (re-sincronizar un item sin cambios es idempotente del lado del plugin).
--
-- Los jobs `sync_incremental` "targeted" (lista explícita de items, originados
-- por webhooks) NO mueven el watermark: cubren items puntuales, no el catálogo
-- completo. Solo un barrido de cobertura total puede avanzar la marca.
--
-- Idempotente: ADD COLUMN IF NOT EXISTS. NULL = la cuenta nunca tuvo un sync de
-- cobertura total; el worker trata ese caso como un full.
-- =============================================================================

ALTER TABLE accounts ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ;
