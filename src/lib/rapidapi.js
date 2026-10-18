/**
 * v0.8.0 RapidAPI gate for /rapidapi/* (pattern: MeetZone src/index.ts, hardened: constant-time compare, 503 when unset).
 * RapidAPI's proxy adds X-RapidAPI-Proxy-Secret (must equal the Worker secret RAPIDAPI_PROXY_SECRET), X-RapidAPI-Subscription
 * (BASIC/PRO) and X-RapidAPI-User. Monthly quotas + per-minute plan limits are enforced by RapidAPI; the Worker adds only a
 * generous per-user burst guard (RAPIDAPI_LIMITER, namespace, keyspace "rapidapi:"). /api/*, /mcp and Polar DNSG- keys are
 * untouched.
 */
export const RAPIDAPI_PREFIX = '/rapidapi';
export const RAPIDAPI_BURST_PER_MIN = 120; // = wrangler.toml RAPIDAPI_LIMITER simple.limit; 2x the PRO plan's 60/min
export const RAPIDAPI_TIERS = ['BASIC', 'PRO'];

export function isRapidApiPath(path) { return path === RAPIDAPI_PREFIX || path.startsWith(`${RAPIDAPI_PREFIX}/`); }

async function digest(s) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(s)))); }

/** Constant-time equality: compares fixed-length SHA-256 digests, so neither content nor length leaks via timing. */
export async function safeEqual(a, b) {
  const [x, y] = await Promise.all([digest(a), digest(b)]);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

export function rapidTier(request) {
  const t = String(request.headers.get('x-rapidapi-subscription') || '').trim().toUpperCase();
  return RAPIDAPI_TIERS.includes(t) ? t : 'BASIC';
}

/** Burst-guard key (16 hex): hashed X-RapidAPI-User (fallback: the caller bucket). Never stores the raw username. */
export async function rapidUserKey(request, fallback) {
  const u = String(request.headers.get('x-rapidapi-user') || '').trim().slice(0, 128);
  const src = u ? `u:${u}` : `ip:${fallback}`;
  const h = [...(await digest(src))].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
  return h; // rateLimited() prefixes the "rapidapi:" keyspace
}

/** Returns null when allowed, or { status, code, message } to reject. Never echoes the secret. */
export async function rapidGate(request, env) {
  const secret = typeof env.RAPIDAPI_PROXY_SECRET === 'string' ? env.RAPIDAPI_PROXY_SECRET : '';
  if (!secret) return { status: 503, code: 'rapidapi_not_configured', message: 'The RapidAPI route is not configured yet. Use /api/check directly.' };
  const presented = request.headers.get('x-rapidapi-proxy-secret');
  if (!presented || !(await safeEqual(presented, secret))) {
    return { status: 401, code: 'unauthorized', message: 'Missing or invalid RapidAPI proxy secret. Subscribe on RapidAPI, or use the free public API at /api/check.' };
  }
  return null;
}
