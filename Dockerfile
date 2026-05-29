FROM node:20-alpine AS base
WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

# Copiar fuentes — TODOS los .js de la raíz (incluye server, db, auth, routes-v1,
# migrate, tn-api, worker, scheduler, rate-limit, y cualquier futuro). El listado
# explícito anterior causó el bug 2026-05-25: agregamos rate-limit.js al repo y
# al deployar el container arrancaba con ERR_MODULE_NOT_FOUND porque el Dockerfile
# no lo conocía. El glob evita ese tipo de oversight a futuro.
COPY *.js ./
COPY db ./db
COPY entrypoint.sh ./
RUN chmod +x entrypoint.sh

# Crear /data con permisos para el user "node" ANTES del USER directive.
# Sin esto, EasyPanel monta el volume como root y el proceso node no puede
# escribir → EACCES en /data/mappings.json.
RUN mkdir -p /data && chown -R node:node /data
USER node

# Persistencia del archivo de mappings store_id → site_url.
# EasyPanel debe montar un volume en /data para que sobreviva rebuilds.
VOLUME ["/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

# entrypoint.sh corre las migraciones idempotentemente antes de arrancar el server.
# Si la DB todavía no está accesible (pg arrancando en paralelo), retry con backoff.
CMD ["./entrypoint.sh"]
