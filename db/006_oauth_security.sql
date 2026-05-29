-- Hardening OAuth 2026-05-25 — auditoría reveló 3 CRITICAL en el flow connect-tn.
--
-- 1) oauth_states: persistir cada state emitido en /connect-tn. Validar en
--    /connect-tn/callback que existe + no se usó + TTL OK. Cierra:
--    - #3 (state OAuth no validado server-side) — comment original admitía
--      "no confiamos en el contenido del state cuando vuelve"
--
-- 2) request_nonces: anti-replay genérico para endpoints /v1/* y /connect-tn.
--    Cierra:
--    - #2 (handshake replay) — body firmado sin ts/nonce permitía rotar
--      shared_secret y robar la cuenta vía replay
--    - #1 (open redirect) — el start del OAuth ahora requiere nonce one-use
--      firmado por el plugin, no se puede generar links arbitrarios sin tener
--      el HUB_SECRET ni reusar links viejos

CREATE TABLE IF NOT EXISTS oauth_states (
    state_id    text PRIMARY KEY,           -- random 32-byte hex
    site_url    text NOT NULL,
    return_to   text NOT NULL,
    nonce       text NOT NULL,              -- el nonce que el plugin pasó (informativo)
    created_at  bigint NOT NULL,            -- unix seconds
    consumed_at bigint                      -- NULL = todavía no consumido
);
CREATE INDEX IF NOT EXISTS idx_oauth_states_created ON oauth_states(created_at);

CREATE TABLE IF NOT EXISTS request_nonces (
    nonce       text NOT NULL,              -- random del plugin
    purpose     text NOT NULL,              -- 'oauth_start' | 'handshake' | ...
    created_at  bigint NOT NULL,            -- unix seconds
    PRIMARY KEY (nonce, purpose)
);
CREATE INDEX IF NOT EXISTS idx_request_nonces_created ON request_nonces(created_at);
