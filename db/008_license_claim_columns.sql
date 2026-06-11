-- =============================================================================
-- 008_license_claim_columns.sql — Copia del claim del capability-token (Fase 6).
--
-- Reconciliación ml↔tn (docs/PHASE6_CAPABILITY_TOKEN.md §9): el worker de TN
-- pasa a gatear por accounts.license_exp (vencimiento REAL del claim, igual que
-- connect-ml) en vez de inferirlo del watermark last_valid_license_token_at
-- (007). Para eso el central guarda, junto al watermark, una copia del último
-- claim VÁLIDO presentado (stampValidLicense en routes-v1.js):
--
--   - accounts.license_id : claim.license_id del último token válido. Lo usa el
--     worker para cortar por denylist (revoke explícito) sin tener el token.
--   - accounts.license_exp: claim.exp del último token válido. El worker corta
--     SOLO vencimientos confirmados (license_exp <= now Y fuera de gracia).
--
-- FAIL-OPEN: ambas columnas nacen NULL para las cuentas existentes. NULL = "sin
-- dato" → el worker NO corta (cuenta pre-Fase6 / pre-migración); se llenan a
-- medida que cada cuenta presenta un token válido en cualquier endpoint
-- account-authed (o en el handshake).
--
-- Idempotente: ADD COLUMN IF NOT EXISTS (mismo patrón que las previas).
-- =============================================================================

ALTER TABLE accounts ADD COLUMN IF NOT EXISTS license_id  TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS license_exp TIMESTAMPTZ;
