/**
 * Privacy-friendly daily unique-visitor counter (). Copied from LinkPulse src/lib/visitors.js, itself from SchemaGate/RichProof
 * src/lib/quota.js countVisitor incl. Key = uv:<UTC day>:<first 16 hex of SHA-256(salt | day | ipBucket)> in the KEYS KV namespace (prefix
 * uv:, separate from key:/user:), value "1", TTL 9 days. No IP, user agent, domain or key is stored. Fire-and-forget via ctx.waitUntil; KV
 * writes per isolate per UTC day are capped.
 */
export const VISITOR_TTL_S = 9 * 86400; // long enough for Monday weekly reports
export const DAILY_VISITOR_WRITES = 1000; // per isolate per UTC day
export const DEFAULT_MARKERS = 'fleet-bot,dnsguard-qc,dnsguard-smoke,qc-bot,smitherybot,cloudflare-healthchecks,uptime,cron';

const utcDay = (now) => new Date(now).toISOString().slice(0, 10);
let state = { day: '', writes: 0, seen: new Set() };
export function resetVisitors() { state = { day: '', writes: 0, seen: new Set() }; }

/** Rate/visitor bucket: IPv4 as is; IPv6 -> its /64 (same output as LinkPulse/WorkdayAPI ipBucket). */
export function ipBucket(ip) {
  const s = String(ip || 'unknown').trim().toLowerCase();
  if (!s.includes(':')) return s;
  if (s.includes('.')) return s.slice(s.lastIndexOf(':') + 1); // IPv4-mapped ::ffff:a.b.c.d
  const [h, t] = s.split('::'), head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const parts = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return parts.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, '') || '0').join(':') + '::/64';
}

export function isExcludedTraffic(request, env) {
  if (request.headers.get('x-fleet-traffic')) return true;
  if (request.headers.get('cf-worker')) return true; // Worker-to-Worker (cron jobs, other bots on Workers)
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const markers = String(env.FLEET_UA_MARKERS || DEFAULT_MARKERS).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  return markers.some((m) => ua.includes(m));
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** bucket = ipBucket(cf-connecting-ip). Returns the promise (tests await it). */
export function countVisitor(request, env, ctx, bucket, now = Date.now()) {
  const kv = env.KEYS;
  if (!kv || typeof kv.put !== 'function' || !env.VISITOR_SALT || isExcludedTraffic(request, env)) return undefined;
  const day = utcDay(now);
  if (state.day !== day) state = { day, writes: 0, seen: new Set() };
  const p = (async () => {
    const h = (await sha256hex(`${env.VISITOR_SALT}|${day}|${bucket}`)).slice(0, 16);
    if (state.seen.has(h)) return;
    if (state.seen.size > 20000) state.seen.clear();
    state.seen.add(h);
    const key = `uv:${day}:${h}`;
    if (await kv.get(key) !== null) return;
    if (state.writes >= DAILY_VISITOR_WRITES) return;
    state.writes++;
    await kv.put(key, '1', { expirationTtl: VISITOR_TTL_S });
  })().catch(() => {});
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p);
  return p;
}
