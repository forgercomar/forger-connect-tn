#!/bin/sh
# entrypoint.sh — corre migraciones Postgres y arranca el server.
#
# Estrategia para arranque cuando el container de Postgres todavía no terminó
# de levantar: reintenta migrate con backoff exponencial hasta MAX_TRIES. Si
# después de N intentos sigue fallando, arrancamos el server igual (el
# OAuth bridge no necesita DB; los /v1/* devolverán error hasta que la DB
# esté disponible).
set -e

MAX_TRIES=10
TRY=1
DELAY=1

while [ "$TRY" -le "$MAX_TRIES" ]; do
    echo "[entrypoint] migrate intento $TRY/$MAX_TRIES..."
    if node migrate.js; then
        echo "[entrypoint] ✓ migraciones aplicadas"
        break
    fi
    echo "[entrypoint] migrate falló; reintentando en ${DELAY}s..."
    sleep "$DELAY"
    TRY=$((TRY + 1))
    DELAY=$((DELAY * 2))
    if [ "$DELAY" -gt 30 ]; then DELAY=30; fi
done

if [ "$TRY" -gt "$MAX_TRIES" ]; then
    echo "[entrypoint] ⚠ no se pudo migrar después de $MAX_TRIES intentos; arrancando server igual (modo degradado)"
fi

echo "[entrypoint] iniciando server..."
exec node server.js
