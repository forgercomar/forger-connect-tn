# forger-connect-tn

Microservicio OAuth bridge + Central Orchestrator entre los plugins Forger
TiendaNube y la API de TiendaNube (Nuvemshop). Node.js + Postgres.

## Qué hace

- Recibe el flow OAuth del plugin cliente y lo redirige al authorize de TiendaNube.
- Intercambia el `code` por el `access_token` (que en TN **no expira**) y lo
  guarda cifrado (AES-256-GCM).
- Devuelve el payload firmado (HMAC) al plugin para que registre la tienda.
- Orquesta jobs de sync (lectura de productos) y push (stock/precio) contra la
  API de TN, respetando su rate-limit (leaky-bucket 40 + 2/s por tienda).
- Recibe webhooks de TN (verificados por HMAC `x-linkedstore-hmac-sha256`) y los
  encola para que el plugin baje los cambios en su próximo poll.

## Diferencias clave con forger-connect-ml (del que es clon)

- Tokens de TN **no expiran** → sin lógica de refresh ni `/refresh-token`.
- Header de auth `Authentication: bearer <token>` (no `Authorization`) + User-Agent
  obligatorio.
- API versionada por fecha: `https://api.tiendanube.com/2025-03/{store_id}/`.
- Productos completos paginados (sin search+multiget); stock por variante con
  endpoints dedicados.

Ver `../docs/TIENDANUBE_PLAN.md` para el plan completo y `db/` para el schema.

Código propietario. Sin docs públicas de deployment ni integración.
