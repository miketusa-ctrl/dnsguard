// Shared daily pools: a cost backstop so DnsGuard stays inside its share of the account's Workers Paid
// allowance, however many IPs or API keys show up.
//
// - checks:   all uncached checks (anonymous + keyed), capped at limits.checksPerDay
// - anon:     the anonymous share of that, capped at limits.anonPerDay (the rest is kept for key holders)
// - waitlist: waitlist join/remove KV operations, capped at limits.waitlistPerDay
//
// Counting is APPROXIMATE on purpose: each isolate batches its increments and flushes them to ONE
// KeyQuota Durable Object instance (BUDGET_DO_NAME) at most every FLUSH_EVERY_N events or FLUSH_EVERY_MS,
// so the pools cost about 1 DO request per FLUSH_EVERY_N checks under load instead of 1 per check.
// Overshoot is bounded by (active isolates × FLUSH_EVERY_N). If the DO is unreachable we fail open:
// the per-minute limiters and the per-key daily cap still apply. No IPs, keys or domains are sent or stored.
import { utcDay, POOL_FIELDS } from './quota.js';

export const BUDGET_DO_NAME = 'global:budget';
export const FLUSH_EVERY_N = 25;
export const FLUSH_EVERY_MS = 60_000;

const zero = () => Object.fromEntries(POOL_FIELDS.map((f) => [f, 0]));
const state = { day: null, seen: zero(), pending: zero(), lastFlush: 0, inflight: null };

export function resetBudgetState() {
  Object.assign(state, { day: null, seen: zero(), pending: zero(), lastFlush: 0, inflight: null });
}
export function budgetSnapshot() { return { day: state.day, seen: { ...state.seen }, pending: { ...state.pending } }; }

function roll(day) {
  if (state.day !== day) Object.assign(state, { day, seen: zero(), pending: zero(), lastFlush: 0 });
}
const used = (f) => state.seen[f] + state.pending[f];

/** Seconds until the next 00:00 UTC (for Retry-After on pool exhaustion). */
export function secondsToUtcMidnight(now = new Date()) {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

/**
 * Is there room in today's shared pool? kind: 'anon' | 'key' | 'waitlist'.
 * @returns {{ok:boolean, pool?:string}}
 */
export function budgetAllows(kind, limits, now = new Date()) {
  roll(utcDay(now));
  if (kind === 'waitlist') return used('waitlist') < limits.waitlistPerDay ? { ok: true } : { ok: false, pool: 'waitlist' };
  if (used('checks') >= limits.checksPerDay) return { ok: false, pool: 'checks' };
  if (kind === 'anon' && used('anon') >= limits.anonPerDay) return { ok: false, pool: 'anon' };
  return { ok: true };
}

/** Count one event and flush the batch to the budget DO when it is due (in ctx.waitUntil when available). */
export function budgetRecord(kind, ns, ctx, now = new Date()) {
  roll(utcDay(now));
  if (kind === 'waitlist') state.pending.waitlist++;
  else {
    state.pending.checks++;
    if (kind === 'anon') state.pending.anon++;
  }
  const n = state.pending.checks + state.pending.waitlist; // events (anon is a subset of checks)
  const due = n >= FLUSH_EVERY_N || now.getTime() - state.lastFlush >= FLUSH_EVERY_MS;
  if (!ns || !due || state.inflight) return null;
  const p = flushBudget(ns, now);
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p);
  return p;
}

/** Send pending increments; on success adopt the DO's totals (which include this isolate's counts). */
export async function flushBudget(ns, now = new Date()) {
  const day = utcDay(now);
  roll(day);
  const batch = { ...state.pending };
  state.pending = zero();
  state.lastFlush = now.getTime();
  const qs = POOL_FIELDS.map((f) => `${f}=${batch[f]}`).join('&');
  const p = (async () => {
    try {
      const stub = ns.get(ns.idFromName(BUDGET_DO_NAME));
      const res = await stub.fetch(`https://quota/add?day=${day}&${qs}`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const t = await res.json();
      if (state.day === day) for (const f of POOL_FIELDS) state.seen[f] = Math.max(state.seen[f], Number(t[f]) || 0);
      return t;
    } catch {
      // Fail open, but keep the counts so the next flush carries them.
      if (state.day === day) for (const f of POOL_FIELDS) state.pending[f] += batch[f];
      return null;
    }
  })();
  state.inflight = p;
  p.finally(() => { if (state.inflight === p) state.inflight = null; });
  return p;
}
