# forger-connect-tn — DB

Schema Postgres del Central Orchestrator. Vive en el container `wf-postgres`.

## Migraciones

Cada archivo `NNN_descripcion.sql` se ejecuta una vez, en orden.
El script `migrate.js` (en raíz del proyecto Node) las aplica idempotentemente
y guarda en la tabla `_migrations` cuál ya corrió.

### Aplicar

```bash
# Local (con el container corriendo):
docker exec -i wf-postgres psql -U wftn -d wftn < db/001_init.sql

# O desde el container del connect-tn:
node migrate.js
```

### Convenciones

- IDs públicos con prefijo legible (`acc_`, `job_`, `stp_`) generados en Node.
- Timestamps siempre `TIMESTAMPTZ` (UTC).
- Tokens encriptados con AES-256-GCM; la key vive en `WFTN_TOKEN_KEY`.
- Nunca guardar `access_token` ML — se deriva on-demand del `refresh_token`.

## Variables de entorno requeridas

```
PGHOST=wf-postgres
PGPORT=5432
PGUSER=wftn
PGPASSWORD=...
PGDATABASE=wftn
WFTN_TOKEN_KEY=<32 bytes base64>     # rotable cada 3-6 meses
WFTN_OAUTH_HUB_SECRET=<existing>     # shared con plugins viejos (compat)
```

## Roadmap

- [ ] `002_jobs_retention.sql` — cron de cleanup (jobs done > 30d, steps > 90d).
- [ ] `003_dashboard_indexes.sql` — índices extra cuando montemos UI admin.
- [ ] `004_audit_log.sql` — log de cambios sensibles (revoke account, rotate key).
