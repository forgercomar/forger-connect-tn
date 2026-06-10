-- =============================================================================
-- 007_license_enforcement.sql — Enforcement del capability-token (Fase 6).
--
-- El plugin manda en cada request /v1/* un capability-token firmado Ed25519 por
-- el license-api (header X-Wftn-License-Token). El central lo verifica
-- (license-token.js) para negar sync/push/handshake a cuentas sin licencia
-- vigente. Esta migración agrega el estado mínimo para soportar GRACIA y
-- DENYLIST persistente.
--
-- Reglas (implementadas en routes-v1.js / server.js / worker.js):
--   - LICENSE_ENFORCE = off | observe (default) | enforce. Solo `enforce` bloquea.
--   - GRACIA en /v1/jobs (sync/push): si el token falta/expiró pero la cuenta
--     presentó uno válido dentro de GRACE_PERIOD_SEC (default 72h), se permite.
--     El handshake NO tiene gracia (entrada nueva).
--   - La DENYLIST (revoke explícito) gana SIEMPRE: ni la gracia ni un token
--     todavía-no-expirado salvan a un license_id revocado.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- accounts.last_valid_license_token_at — watermark de gracia.
-- Se sella con NOW() cada vez que la cuenta presenta un capability-token VÁLIDO
-- en /v1/jobs. Si más tarde el token falta/expiró, /v1/jobs sigue permitiendo
-- mientras NOW() - last_valid_license_token_at <= GRACE_PERIOD_SEC. Esto evita
-- cortar operaciones por una caída transitoria del license-api / del plugin.
-- -----------------------------------------------------------------------------
ALTER TABLE accounts
    ADD COLUMN IF NOT EXISTS last_valid_license_token_at TIMESTAMPTZ;

-- -----------------------------------------------------------------------------
-- license_denylist — license_ids revocados explícitamente (gana sobre la gracia).
-- El license-api (o un operador) puede revocar una licencia antes de su exp
-- natural; el central la recibe vía POST /internal/license-revoked y la persiste
-- acá. Persistente para sobrevivir reinicios y ser consistente entre réplicas.
-- El server cachea esta tabla en memoria (Set) y la refresca periódicamente.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS license_denylist (
    license_id   TEXT PRIMARY KEY,           -- claim.license_id del token revocado
    reason       TEXT,                        -- motivo (informativo)
    revoked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_license_denylist_revoked ON license_denylist(revoked_at);
