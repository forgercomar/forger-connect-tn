/**
 * Rate limiter in-memory por IP + bucket.
 *
 * Hardening 2026-05-25 (#25): los endpoints públicos del central no tenían rate
 * limit. Riesgos:
 *   - /connect-tn: un atacante podía spammar start de OAuth para gastar quota de
 *     ML, llenar oauth_states o intentar fuerza-bruta sobre la firma del plugin.
 *   - /v1/handshake: anti-replay ya está, pero sin RL podían martillarlo con
 *     payloads inválidos buscando colisiones de nonce o filtraciones de timing.
 *   - /refresh-token: refresh tokens son largos pero finitos; spam permite
 *     enumerar.
 *   - /v1/jobs/*: polling legítimo del plugin existe, pero sin techo un cliente
 *     malicioso puede saturar.
 *
 * NO usamos express-rate-limit como dep (queremos cero deps nuevas) ni Redis
 * (single-instance en EasyPanel hoy). In-memory + GC alcanza. Si en el futuro
 * escala a N réplicas, migrar a Redis con la misma signature.
 *
 * Trust proxy ya está habilitado (server.js trust proxy = true), así que req.ip
 * es la IP real del cliente, no la del reverse proxy.
 */

export function createRateLimiter({ bucket, windowMs, max, label }) {
    const entries = new Map();

    // GC: cada 60s barre entries expiradas. Sin esto, en uso normal la Map
    // crecería sin límite (1 entry por IP única que llega en su vida).
    const gc = setInterval(() => {
        const now = Date.now();
        for (const [k, v] of entries.entries()) {
            if (v.resetAt < now) entries.delete(k);
        }
    }, 60_000);
    gc.unref(); // no bloquea shutdown del proceso

    return function rateLimitMiddleware(req, res, next) {
        // req.ip viene de trust-proxy. Fallback defensivo.
        const ip = (req.ip || req.connection?.remoteAddress || 'unknown').toString();
        const key = bucket + ':' + ip;
        const now = Date.now();
        let entry = entries.get(key);
        if (!entry || entry.resetAt <= now) {
            entry = { count: 0, resetAt: now + windowMs };
            entries.set(key, entry);
        }
        entry.count++;
        const remaining = Math.max(0, max - entry.count);
        res.set('X-RateLimit-Limit', String(max));
        res.set('X-RateLimit-Remaining', String(remaining));
        res.set('X-RateLimit-Reset', String(Math.ceil(entry.resetAt / 1000)));
        if (entry.count > max) {
            const retryAfter = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
            res.set('Retry-After', String(retryAfter));
            // Log discreto — sin spammear, solo cuando trippea.
            if (entry.count === max + 1) {
                console.warn(`[rate-limit] ${label || bucket} tripped for ip=${ip} (${entry.count}/${max} in ${windowMs}ms)`);
            }
            return res.status(429).json({
                error: 'rate_limit_exceeded',
                message: `Demasiados pedidos. Esperá ${retryAfter}s antes de reintentar.`,
                retry_after_seconds: retryAfter,
            });
        }
        next();
    };
}
