// Daily usage counters in a SQLite-backed Durable Object.
// - Per account: one instance per Google account (idFromName(quotaId)), POST /consume, exact (DO input gates
//   serialize get→put). Cheaper and exact compared with KV (KV writes: 1/sec per key; billed past 1M/month on Paid).
// - Shared daily pools: ONE instance named BUDGET_DO_NAME (see budget.js), POST /add with batched increments.
//   Same class, so no new DO migration is needed.
// Plain fetch()-style class (no `cloudflare:workers` import) so it is unit-testable in Node.

export const COUNTER_RETENTION_DAYS = 2;
// Shared daily pool counters kept by the budget instance: all uncached checks, anonymous ones, waitlist KV writes.
export const POOL_FIELDS = ['checks', 'anon', 'waitlist'];

export function utcDay(now = new Date()) { return now.toISOString().slice(0, 10); }

function dayMinus(day, n) {
  const d = new Date(`${day}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - n);
  return utcDay(d);
}

export class KeyQuota {
  constructor(state, env) {
    this.state = state;
    this.storage = state.storage;
    this.env = env;
    this.clock = () => Date.now(); // overridable in tests to simulate several days
  }

  async fetch(request) {
    const url = new URL(request.url);
    const day = url.searchParams.get('day') || utcDay();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return Response.json({ error: 'bad_request' }, { status: 400 });
    if (url.pathname === '/add') {
      if (request.method !== 'POST') return Response.json({ error: 'not_found' }, { status: 404 });
      const inc = {};
      for (const f of POOL_FIELDS) {
        const n = Number(url.searchParams.get(f) || 0);
        if (!Number.isInteger(n) || n < 0 || n > 100_000) return Response.json({ error: 'bad_request' }, { status: 400 });
        inc[f] = n;
      }
      return Response.json(await this.add(day, inc));
    }
    const limit = Number(url.searchParams.get('limit') || 0);
    if (!Number.isFinite(limit) || limit < 1) return Response.json({ error: 'bad_request' }, { status: 400 });
    if (url.pathname === '/peek') {
      const used = (await this.storage.get(`d:${day}`)) || 0;
      return Response.json({ ok: used < limit, used, limit, day });
    }
    if (url.pathname !== '/consume' || request.method !== 'POST') return Response.json({ error: 'not_found' }, { status: 404 });
    return Response.json(await this.consume(day, limit));
  }

  async consume(day, limit) {
    const key = `d:${day}`;
    const used = (await this.storage.get(key)) || 0;
    if (used >= limit) return { ok: false, used, limit, day }; // denied requests write nothing
    const next = used + 1;
    await this.storage.put(key, next);
    // First use today: schedule cleanup so counters are kept ~2 days, then deleted.
    if (used === 0) await this.ensureCleanup(day);
    return { ok: true, used: next, limit, day };
  }

  /** Shared-pool counters: add batched increments, return today's totals. Zero increments only read. */
  async add(day, inc) {
    const totals = { day };
    let first = false;
    for (const f of POOL_FIELDS) {
      const key = `d:${day}:${f}`;
      const cur = (await this.storage.get(key)) || 0;
      if (inc[f] > 0) {
        if (cur === 0) first = true;
        await this.storage.put(key, cur + inc[f]);
      }
      totals[f] = cur + inc[f];
    }
    if (first) await this.ensureCleanup(day);
    return totals;
  }

  // One alarm per object. Keep the EARLIEST pending time: never push an armed alarm later, otherwise daily
  // first-use calls would keep moving it 3 days out and it would never fire.
  async ensureCleanup(day) {
    const at = Date.parse(`${day}T00:00:00Z`) + (COUNTER_RETENTION_DAYS + 1) * 86400_000;
    const cur = await this.storage.getAlarm();
    if (!cur || cur > at) await this.storage.setAlarm(at);
  }

  // Delete every day older than yesterday (keys "d:<day>" and "d:<day>:<pool>"), then re-arm for the next
  // 00:00 UTC while anything remains, so retention is today + yesterday and nothing older survives a day.
  async alarm() {
    const now = this.clock();
    const keepFrom = dayMinus(utcDay(new Date(now)), COUNTER_RETENTION_DAYS - 1); // keep today + yesterday
    const all = await this.storage.list({ prefix: 'd:' });
    const old = [...all.keys()].filter((k) => k.slice(2, 12) < keepFrom);
    if (old.length) await this.storage.delete(old);
    if (all.size > old.length) {
      const d = new Date(now);
      await this.storage.setAlarm(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1));
    }
  }
}

export class QuotaUnavailable extends Error {
  constructor(message) { super(message); this.code = 'quota_unavailable'; }
}

// Per-isolate memo of accounts already at their daily cap ("quotaId|limit" → UTC day). Once the DO has said
// "no" for today, further requests in this isolate get the 429 without another billed DO request.
const exhausted = new Map();
export function clearQuotaMemo() { exhausted.clear(); }

/** Consume one check from the account's daily quota. Throws QuotaUnavailable if the DO can't be reached. */
export async function consumeDailyQuota(ns, quotaId, limit, now = new Date()) {
  if (!ns) throw new QuotaUnavailable('QUOTA binding missing');
  const day = utcDay(now);
  const memoKey = `${quotaId}|${limit}`;
  if (exhausted.get(memoKey) === day) return { ok: false, used: limit, limit, day, memo: true };
  let out;
  try {
    const stub = ns.get(ns.idFromName(quotaId));
    const res = await stub.fetch(`https://quota/consume?day=${day}&limit=${limit}`, { method: 'POST' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    out = await res.json();
  } catch (e) {
    throw new QuotaUnavailable(`quota counter unavailable: ${e.message}`);
  }
  if (out && out.ok === false) {
    exhausted.set(memoKey, day);
    if (exhausted.size > 5000) exhausted.delete(exhausted.keys().next().value);
  }
  return out;
}
