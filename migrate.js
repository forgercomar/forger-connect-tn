/**
 * migrate.js — Runner idempotente de migraciones SQL.
 *
 * Lee `db/*.sql` en orden alfabético, ejecuta cada uno que no esté registrado
 * en la tabla `_migrations`, y guarda el hash + timestamp para no re-correrlo.
 *
 * Diseñado para correr al arrancar el container (en el Dockerfile o entrypoint)
 * o manualmente con `npm run migrate`.
 *
 * Cada archivo SQL debe ser idempotente por sí mismo (CREATE TABLE IF NOT EXISTS,
 * etc.) para que sea seguro re-correrlo si algo falla a mitad.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { query, close } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.join(__dirname, 'db');

async function ensureMigrationsTable() {
    await query(`
        CREATE TABLE IF NOT EXISTS _migrations (
            id          BIGSERIAL PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            sha256      TEXT NOT NULL,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);
}

async function appliedSet() {
    const r = await query('SELECT name, sha256 FROM _migrations');
    const map = new Map();
    r.rows.forEach((row) => map.set(row.name, row.sha256));
    return map;
}

async function main() {
    if (!fs.existsSync(MIGRATIONS_DIR)) {
        console.error(`[migrate] no existe directorio ${MIGRATIONS_DIR}`);
        process.exit(1);
    }
    const files = fs.readdirSync(MIGRATIONS_DIR)
        .filter((f) => f.endsWith('.sql'))
        .sort();
    if (!files.length) {
        console.log('[migrate] no hay archivos .sql en db/');
        return;
    }

    await ensureMigrationsTable();
    const applied = await appliedSet();

    let count = 0;
    for (const name of files) {
        const full = path.join(MIGRATIONS_DIR, name);
        const sql = fs.readFileSync(full, 'utf8');
        const sha = crypto.createHash('sha256').update(sql).digest('hex');

        if (applied.has(name)) {
            const prevSha = applied.get(name);
            if (prevSha !== sha) {
                console.warn(`[migrate] ⚠ ${name} cambió desde su aplicación previa (sha ${prevSha.slice(0,8)} → ${sha.slice(0,8)}). Edita el SQL solo si sabés lo que hacés; las migraciones aplicadas deberían ser inmutables.`);
            } else {
                console.log(`[migrate] = ${name} (ya aplicado)`);
            }
            continue;
        }

        console.log(`[migrate] → aplicando ${name}...`);
        try {
            await query(sql);
            await query('INSERT INTO _migrations (name, sha256) VALUES ($1, $2)', [name, sha]);
            console.log(`[migrate] ✓ ${name}`);
            count++;
        } catch (err) {
            console.error(`[migrate] ✗ ${name}: ${err.message}`);
            process.exit(1);
        }
    }
    console.log(`[migrate] listo. ${count} nueva(s) migración(es) aplicada(s).`);
}

main()
    .catch((err) => {
        console.error('[migrate] fatal:', err);
        process.exit(1);
    })
    .finally(async () => {
        await close();
    });
