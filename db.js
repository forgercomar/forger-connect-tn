/**
 * db.js — Pool Postgres + helpers de queries.
 *
 * Single source of truth para acceso a la DB. Resto del servidor importa `query`
 * o `tx` desde acá y no toca el pool directo.
 *
 * Variables de entorno requeridas (en docker-compose o EasyPanel):
 *
 *   PGHOST       host del container Postgres (ej. "wf-postgres")
 *   PGPORT       5432
 *   PGUSER       usuario
 *   PGPASSWORD   password
 *   PGDATABASE   nombre de DB (ej. "wftn")
 *
 * El módulo node-postgres lee estas envs automáticamente del entorno cuando se
 * llama a `new Pool()` sin args, así que no las parseamos a mano.
 */

import pg from 'pg';
const { Pool } = pg;

// Singleton de pool. Lazy: solo se crea al primer query, así un import accidental
// en un contexto sin DB (ej. tests) no falla al cargar el módulo.
let _pool = null;

function getPool() {
    if (_pool) return _pool;
    _pool = new Pool({
        // Defaults razonables para un VPS de 2-4GB con ~10 workers eventuales.
        max: 20,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 5000,
    });
    _pool.on('error', (err) => {
        // El pool reemite errores en conexiones idle (red caída, restart de pg,
        // etc.). Sin handler, el proceso explota. Loguear y seguir.
        console.error('[db] pool idle client error:', err.message);
    });
    return _pool;
}

/**
 * Ejecuta una query parametrizada. Devuelve el result completo de node-postgres.
 *
 *   const { rows } = await query('SELECT * FROM accounts WHERE id = $1', [42]);
 *
 * Nunca interpolar valores en el SQL — siempre usar $1, $2, etc.
 */
export async function query(text, params = []) {
    const pool = getPool();
    const start = Date.now();
    try {
        const res = await pool.query(text, params);
        const ms = Date.now() - start;
        if (ms > 250) {
            // Log de slow queries para diagnosticar índices faltantes.
            console.warn(`[db] slow query (${ms}ms): ${text.slice(0, 120)}`);
        }
        return res;
    } catch (err) {
        console.error(`[db] query error: ${err.message}\nSQL: ${text}`);
        throw err;
    }
}

/**
 * Ejecuta un bloque dentro de una transacción. Si el callback throw, ROLLBACK;
 * sino COMMIT. Devuelve lo que retorne el callback.
 *
 *   await tx(async (client) => {
 *       await client.query('UPDATE jobs ...');
 *       await client.query('INSERT INTO job_steps ...');
 *       return 'ok';
 *   });
 *
 * Importante: dentro del callback usar `client.query`, NO la `query` global,
 * sino las queries salen fuera de la transacción.
 */
export async function tx(fn) {
    const pool = getPool();
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        throw err;
    } finally {
        client.release();
    }
}

/**
 * Health check ligero: SELECT 1. Usado por el endpoint /healthz.
 */
export async function ping() {
    const r = await query('SELECT 1 AS ok');
    return r.rows[0]?.ok === 1;
}

/**
 * Cierre limpio del pool (para tests o shutdown). En prod no se llama nunca.
 */
export async function close() {
    if (_pool) {
        await _pool.end();
        _pool = null;
    }
}
