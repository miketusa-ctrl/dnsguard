/** API key generate / hash / lookup / mint / rotate helpers for the free tier. */

export const KEY_PREFIX = 'dg_live_';
export const FREE_CHECKS_PER_MIN = 120; // raised from 60 on Workers Paid (v0.3.0); the daily cap bounds cost
export const FREE_CHECKS_PER_DAY = 1000;

const KEY_BODY_RE = /^[a-f0-9]{64}$/;

/** Thrown when Workers KV can't be read or written (e.g. the account's free daily write budget is used up). */
export class StorageError extends Error {
  constructor(op, key, cause) {
    super(`KV ${op} failed${cause && cause.message ? `: ${cause.message}` : ''}`);
    this.code = 'storage_unavailable';
    this.op = op;
    this.key = key;
  }
}

export async function kvGet(kv, key, type) {
  try { return await kv.get(key, type); } catch (e) { throw new StorageError('get', key, e); }
}
export async function kvPut(kv, key, value, opts) {
  try { return await kv.put(key, value, opts); } catch (e) { throw new StorageError('put', key, e); }
}
export async function kvDelete(kv, key) {
  try { return await kv.delete(key); } catch (e) { throw new StorageError('delete', key, e); }
}

/** Raw key: dg_live_ + 32 random bytes as hex (64 chars). */
export function generateApiKey() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return KEY_PREFIX + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function isKeyFormat(raw) {
  if (!raw || typeof raw !== 'string') return false;
  if (!raw.startsWith(KEY_PREFIX)) return false;
  return KEY_BODY_RE.test(raw.slice(KEY_PREFIX.length));
}

export async function hashApiKey(raw) {
  const data = new TextEncoder().encode(raw);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Short stable id derived from the hash (first 16 hex chars). Never the raw key. */
export function keyIdFromHash(hash) {
  return hash.slice(0, 16);
}

export function extractApiKey(request) {
  const auth = request.headers.get('authorization');
  if (auth) {
    const m = auth.match(/^Bearer\s+(\S+)/i);
    if (m) return m[1].trim();
  }
  const x = request.headers.get('x-api-key');
  if (x) return x.trim();
  return null;
}

// Per-isolate positive cache of key lookups (60 s) to keep KV reads low on the hot path.
// A rotated/deleted key may keep working for up to ~60 s in an isolate (KV edge caching is similar).
const lookupCache = new Map();
const LOOKUP_TTL_MS = 60_000;
export function clearKeyLookupCache() { lookupCache.clear(); }

/**
 * Look up a key record by raw key. Returns null if missing/invalid. READ-ONLY (no KV writes).
 * Record shape: { keyId, googleSub, email, createdAt }
 */
export async function lookupKey(kv, raw) {
  if (!kv || !isKeyFormat(raw)) return null;
  const hash = await hashApiKey(raw);
  const c = lookupCache.get(hash);
  if (c && Date.now() - c.t < LOOKUP_TTL_MS) return c.rec;
  const stored = await kvGet(kv, `key:${hash}`, 'json');
  if (!stored || typeof stored !== 'object') { lookupCache.delete(hash); return null; }
  const rec = { ...stored, keyHash: hash, keyId: stored.keyId || keyIdFromHash(hash) };
  lookupCache.set(hash, { t: Date.now(), rec });
  if (lookupCache.size > 2000) lookupCache.delete(lookupCache.keys().next().value);
  return rec;
}

/** Daily-quota / rate-limit identity: per Google account, so rotating a key doesn't reset the counters. */
export function quotaIdFor(keyRec) {
  return keyRec.googleSub ? `sub:${keyRec.googleSub}` : `key:${keyRec.keyId}`;
}

async function writeNewKey(kv, { sub, mail, now }) {
  const rawKey = generateApiKey();
  const keyHash = await hashApiKey(rawKey);
  const keyId = keyIdFromHash(keyHash);
  const createdAt = now().toISOString();
  await kvPut(kv, `key:${keyHash}`, JSON.stringify({ keyId, googleSub: sub, email: mail, createdAt }));
  try {
    await kvPut(kv, `user:${sub}`, JSON.stringify({ googleSub: sub, email: mail, keyId, keyHash, createdAt }));
  } catch (e) {
    // Don't leave an orphan key record that nobody was shown.
    try { await kv.delete(`key:${keyHash}`); } catch { /* best effort */ }
    throw e;
  }
  return { rawKey, keyHash, keyId };
}

function normalizeIdentity(googleSub, email) {
  const sub = String(googleSub || '').trim();
  const mail = String(email || '').trim().toLowerCase();
  if (!sub) throw new Error('missing_google_sub');
  return { sub, mail };
}

/**
 * Upsert Google user and mint (or return existing) a free key.
 * Stores: key:<hash>, user:<googleSub>. Never stores raw key.
 * Returns { rawKey | null, keyId, created: boolean, email, googleSub }
 */
export async function mintOrGetFreeKey(kv, { googleSub, email, now = () => new Date() }) {
  if (!kv) throw new Error('keys_kv_missing');
  const { sub, mail } = normalizeIdentity(googleSub, email);
  const existing = await kvGet(kv, `user:${sub}`, 'json');
  if (existing && existing.keyHash) {
    const rec = await kvGet(kv, `key:${existing.keyHash}`, 'json');
    if (rec) {
      if (mail && mail !== existing.email) {
        await kvPut(kv, `user:${sub}`, JSON.stringify({ ...existing, email: mail }));
        await kvPut(kv, `key:${existing.keyHash}`, JSON.stringify({ ...rec, email: mail }));
      }
      return { rawKey: null, keyId: existing.keyId || keyIdFromHash(existing.keyHash), created: false, email: mail || existing.email, googleSub: sub };
    }
  }
  const k = await writeNewKey(kv, { sub, mail, now });
  return { rawKey: k.rawKey, keyId: k.keyId, created: true, email: mail, googleSub: sub };
}

/**
 * Only call after a fresh OAuth round trip whose state was bound to the rotate intent.
 */
export async function rotateFreeKey(kv, { googleSub, email, now = () => new Date() }) {
  if (!kv) throw new Error('keys_kv_missing');
  const { sub, mail } = normalizeIdentity(googleSub, email);
  const existing = await kvGet(kv, `user:${sub}`, 'json');
  const k = await writeNewKey(kv, { sub, mail, now });
  let oldKeyId = null;
  if (existing && existing.keyHash && existing.keyHash !== k.keyHash) {
    oldKeyId = existing.keyId || keyIdFromHash(existing.keyHash);
    await kvDelete(kv, `key:${existing.keyHash}`);
    lookupCache.delete(existing.keyHash);
  }
  return { rawKey: k.rawKey, keyId: k.keyId, oldKeyId, rotated: Boolean(oldKeyId), email: mail, googleSub: sub };
}
