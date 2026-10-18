// Request router. Kept free of Worker-only imports so it can be unit-tested in Node.
import { normalizeDomain } from './lib/domain.js';
import { checkDomain, CheckError, VERSION } from './lib/check.js';
import { Resolver } from './lib/dns.js';
import {
  extractApiKey, lookupKey, mintOrGetFreeKey, rotateFreeKey, quotaIdFor, kvPut, kvDelete, StorageError,
  FREE_CHECKS_PER_MIN, FREE_CHECKS_PER_DAY,
} from './lib/keys.js';
import { consumeDailyQuota, QuotaUnavailable } from './lib/quota.js';
import { budgetAllows, budgetRecord, secondsToUtcMidnight } from './lib/budget.js';
import { guidePage, GUIDE_PATHS } from './lib/guides.js';
import { generatorPage, GENERATOR_PATHS } from './lib/generators.js';
import { validateFleetLicense } from './lib/fleet-license.js';
import { handleMcp, MCP_CORS } from './lib/mcp.js';
import { llmsTxt, openApiSpec } from './lib/agentdocs.js';
import { countVisitor, ipBucket } from './lib/visitors.js';
import { isRapidApiPath, rapidGate, rapidTier, rapidUserKey, RAPIDAPI_BURST_PER_MIN } from './lib/rapidapi.js';
import {
  PRO_CHECKOUT_URL, PRO_PRODUCT_SLUG, PRO_CHECKS_PER_MIN, PRO_CHECKS_PER_DAY,
  isFreeKeyPresented, proQuotaIdFor,
} from './lib/pro.js';
import {
  oauthConfigured, randomToken, stateCookieHeader, readStateCookie,
  buildAuthorizeUrl, callbackRedirectUri, exchangeCode, fetchGoogleUser,
  ROTATE_STATE_PREFIX, intentFromState,
} from './lib/oauth.js';

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, authorization, x-api-key',
  'access-control-max-age': '86400',
};
const SECURITY = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
// The "already have a key" page POSTs to /api/auth/google, which 303s to Google; form-action must allow that redirect target.
const CSP_ROTATE = CSP.replace("form-action 'self'", "form-action 'self' https://accounts.google.com");
const STORAGE_MSG = 'Storage is temporarily unavailable. Please try again later.';
export const SELECTOR_RE = /^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63}){0,3}$/i;
const JOIN_MSG = "You're on the list. We'll email you about weekly digests and higher plans when they launch.";
const REMOVE_MSG = 'If that address was on the waitlist, it has been removed. Nothing else is stored about it.';
const EMAIL_RE = /^[^\s@<>()"',;:]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$/i;
const CONTACT = 'digitalpromohub.support+dnsguard@gmail.com';
export const GLAMA_CLAIM = JSON.stringify({ $schema: 'https://glama.ai/mcp/schemas/connector.json', claim: '<GLAMA_CLAIM_TOKEN>' });

// Defaults match wrangler.toml [vars]; the per-minute numbers must also match the ratelimit bindings' simple.limit.
export const DEFAULT_LIMITS = {
  anonPerMin: 20, // CHECK_LIMIT_PER_MIN / CHECK_LIMITER
  keyPerMin: FREE_CHECKS_PER_MIN, // KEY_CHECK_LIMIT_PER_MIN / KEY_CHECK_LIMITER
  keyPerDay: FREE_CHECKS_PER_DAY, // KEY_CHECK_LIMIT_PER_DAY (KeyQuota DO, exact)
  proPerMin: PRO_CHECKS_PER_MIN, // PRO_CHECK_LIMIT_PER_MIN / PRO_CHECK_LIMITER
  proPerDay: PRO_CHECKS_PER_DAY, // PRO_CHECK_LIMIT_PER_DAY (KeyQuota DO, exact; id pro:<hash>)
  checksPerDay: 8000, // DAILY_CHECK_POOL: all uncached checks, all users (budget.js, approximate)
  anonPerDay: 5000, // DAILY_ANON_CHECK_POOL: anonymous share of the pool; the rest is kept for key holders
  waitlistPerDay: 1000, // DAILY_WAITLIST_WRITES: waitlist KV puts + deletes
};
function num(v, d) { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.floor(n) : d; }
export function limitsFor(env = {}) {
  const L = DEFAULT_LIMITS;
  return {
    anonPerMin: num(env.CHECK_LIMIT_PER_MIN, L.anonPerMin),
    keyPerMin: num(env.KEY_CHECK_LIMIT_PER_MIN, L.keyPerMin),
    keyPerDay: num(env.KEY_CHECK_LIMIT_PER_DAY, L.keyPerDay),
    proPerMin: num(env.PRO_CHECK_LIMIT_PER_MIN, L.proPerMin),
    proPerDay: num(env.PRO_CHECK_LIMIT_PER_DAY, L.proPerDay),
    checksPerDay: num(env.DAILY_CHECK_POOL, L.checksPerDay),
    anonPerDay: num(env.DAILY_ANON_CHECK_POOL, L.anonPerDay),
    waitlistPerDay: num(env.DAILY_WAITLIST_WRITES, L.waitlistPerDay),
  };
}
const fmt = (n) => n.toLocaleString('en-US');

// Per-isolate fallbacks (best effort; the Workers Rate Limiting binding is authoritative when bound).
const memLimits = new Map();
const resultCache = new Map();
const CACHE_TTL_MS = 120_000;

function memLimit(key, limit, periodMs) {
  const now = Date.now();
  const e = memLimits.get(key);
  if (!e || now - e.start > periodMs) { memLimits.set(key, { start: now, n: 1 }); return true; }
  e.n++;
  if (memLimits.size > 5000) memLimits.clear();
  return e.n <= limit;
}

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...SECURITY, ...extra },
  });
}
const apiError = (status, code, message, extra) => json({ error: { code, message } }, status, extra);
const storageError = () => apiError(503, 'storage_unavailable', STORAGE_MSG, { 'retry-after': '3600' });

function staging(env) { return String(env.PUBLIC_LAUNCH || 'false') !== 'true'; }
function freeApiEnabled(env) { return String(env.FREE_API || 'true') === 'true'; }
function keysKv(env) { return env.KEYS || env.DNSGUARD_KEYS || null; }

async function rateLimited(env, ip, bucket, limit) {
  const binding = bucket === 'waitlist' ? env.WAITLIST_LIMITER
    : bucket === 'key' ? env.KEY_CHECK_LIMITER
    : bucket === 'pro' ? env.PRO_CHECK_LIMITER
    : bucket === 'rapidapi' ? env.RAPIDAPI_LIMITER // own namespace: never eats the anonymous IP pool
    : env.CHECK_LIMITER; // join + remove share one bucket
  if (binding && typeof binding.limit === 'function') {
    try { const { success } = await binding.limit({ key: `${bucket}:${ip}` }); return !success; } catch { /* fall through */ }
  }
  return !memLimit(`${bucket}:${ip}`, limit, 60_000);
}

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function keyRevealHtml({ rawKey, created, origin, limits = limitsFor() }) {
  const title = created ? 'Your free DnsGuard API key' : 'You already have a free API key';
  const note = created
    ? 'Copy it now — we only show the raw key once. Store it somewhere safe.'
    : 'For security we never show a key again after it is issued. If you lost it, rotate it below: you get a new key and the old one stops working within about a minute.';
  const keyBlock = created
    ? `<pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow:auto;word-break:break-all">${escapeHtml(rawKey)}</pre>
       <p class="small">Example:</p>
       <pre style="background:#0f172a;color:#e2e8f0;padding:14px;border-radius:8px;overflow:auto">curl -H "Authorization: Bearer ${escapeHtml(rawKey)}" \\
  "${escapeHtml(origin)}/api/check?domain=example.com"</pre>`
    : `<p>Your account already has a free key (limits: about ${limits.keyPerMin} checks/min and ${fmt(limits.keyPerDay)} checks/day). We store only its hash.</p>
       <form method="post" action="/api/auth/google">
         <input type="hidden" name="intent" value="rotate">
         <button type="submit">Rotate key: sign in with Google again and get a new key</button>
       </form>
       <p class="small">Rotating needs one more Google sign-in to confirm it's you. Your old key is deleted when the new one is shown and stops working within about a minute. Daily usage carries over.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} – DnsGuard</title>
<meta name="robots" content="noindex">
<link rel="stylesheet" href="/style.css">
</head><body>
<main class="wrap" style="padding:40px 18px;max-width:720px">
  <h1>${escapeHtml(title)}</h1>
  <p>${escapeHtml(note)}</p>
  ${keyBlock}
  <p><a href="/#api">Back to API docs</a> · Free tier: about ${limits.keyPerMin} checks/min · ${fmt(limits.keyPerDay)} checks/day (UTC).</p>
</main></body></html>`;
}

/**
 * Key gate shared by GET /api/check and POST /mcp (identical behaviour = auth parity).
 * No key → anonymous. dg_live_… → free tier (KEYS KV). Anything else → Pro via LICENSES KV (no Polar HTTP).
 * Returns { ok:true, tier, keyRec, proQid } or { ok:false, status, code, message, headers }. Never echoes the key.
 */
export async function authenticate(request, env = {}) {
  const presented = extractApiKey(request);
  if (!presented) return { ok: true, tier: null, keyRec: null, proQid: null };
  const fail = (status, code, message, headers = {}) => ({ ok: false, status, code, message, headers });
  if (isFreeKeyPresented(presented)) {
    if (!freeApiEnabled(env)) return fail(503, 'free_api_disabled', 'API key auth is temporarily disabled.');
    const kv = keysKv(env);
    if (!kv) return fail(503, 'keys_unavailable', 'API key storage is not configured yet.');
    let keyRec;
    try { keyRec = await lookupKey(kv, presented); } catch (e) { if (e instanceof StorageError) return fail(503, 'storage_unavailable', STORAGE_MSG, { 'retry-after': '3600' }); throw e; }
    if (!keyRec) return fail(401, 'invalid_api_key', 'Invalid or unknown API key.');
    return { ok: true, tier: 'free', keyRec, proQid: null };
  }
  // Non-free key: validate against shared LICENSES KV. Invalid → same 401; do not leak the reason.
  const lic = await validateFleetLicense(env.LICENSES, presented, PRO_PRODUCT_SLUG);
  if (!lic.valid) return fail(401, 'invalid_api_key', 'Invalid or unknown API key.');
  return { ok: true, tier: 'pro', keyRec: null, proQid: await proQuotaIdFor(presented) };
}

/**
 * One check, with the result cache and every per-minute / per-day / shared-pool limit applied exactly like /api/check.
 * Used by /api/check and by the MCP tools/call handler, so one MCP tool call = one check against the same counters.
 * Returns { ok:true, body, headers, cached } or { ok:false, status, code, message, headers }.
 */
export async function runCheck({ domain, selector, auth, env = {}, ctx = {}, ip = 'local', doFetch }) {
  const { tier, keyRec, proQid } = auth;
  const err = (status, code, message, headers = {}) => ({ ok: false, status, code, message, headers });
  const cacheKey = `${domain}|${selector || ''}`;
  const hit = resultCache.get(cacheKey);
  if (hit && Date.now() - hit.t < CACHE_TTL_MS) {
    const extra = { 'x-cache': 'HIT' };
    if (tier === 'free') extra['x-dnsguard-tier'] = 'free';
    if (tier === 'pro') extra['x-dnsguard-tier'] = 'pro';
    if (tier === 'rapidapi') extra['x-dnsguard-tier'] = `rapidapi-${auth.rapidTier.toLowerCase()}`;
    return { ok: true, body: hit.body, headers: extra, cached: true }; // cache hits use no rate/quota/KV budget
  }

  const tierHeaders = {};
  const L = limitsFor(env);
  const poolFull = (pool) => err(429, 'daily_capacity_reached', pool === 'anon'
    ? `Today's shared allowance of free anonymous checks (about ${fmt(L.anonPerDay)} per UTC day across all visitors) is used up. Try again after 00:00 UTC, or use a free API key.`
    : `DnsGuard's free capacity for today (about ${fmt(L.checksPerDay)} checks per UTC day across all users) is used up. Try again after 00:00 UTC.`,
  { 'retry-after': String(secondsToUtcMidnight()), ...tierHeaders });
  if (tier === 'rapidapi') {
    // RapidAPI: monthly quota + plan per-minute limit live in RapidAPI. Worker adds a per-user burst guard only.
    // Does not consume the free shared daily pools (paid marketplace traffic) or the anonymous IP limiter.
    tierHeaders['x-dnsguard-tier'] = `rapidapi-${auth.rapidTier.toLowerCase()}`;
    if (await rateLimited(env, auth.rapidKey, 'rapidapi', RAPIDAPI_BURST_PER_MIN)) {
      return err(429, 'rate_limited', `Burst limit: about ${RAPIDAPI_BURST_PER_MIN} checks per minute per RapidAPI user. Try again shortly.`, { 'retry-after': '60', ...tierHeaders });
    }
  } else if (tier === 'pro') {
    // Pro: per-license minute + day caps. Does NOT consume free shared anon/key daily pools.
    tierHeaders['x-dnsguard-tier'] = 'pro';
    if (await rateLimited(env, proQid, 'pro', L.proPerMin)) {
      return err(429, 'rate_limited', `Pro limit: about ${L.proPerMin} checks per minute per license. Try again shortly.`, { 'retry-after': '60', ...tierHeaders });
    }
    try {
      const quota = await consumeDailyQuota(env.QUOTA, proQid, L.proPerDay);
      if (!quota.ok) {
        return err(429, 'daily_quota_exceeded', `Pro daily cap of ${fmt(L.proPerDay)} checks reached for today (UTC ${quota.day}). Try again after 00:00 UTC.`, { 'retry-after': String(secondsToUtcMidnight()), ...tierHeaders });
      }
      tierHeaders['x-dnsguard-quota-remaining'] = String(Math.max(0, quota.limit - quota.used));
    } catch (e) {
      if (!(e instanceof QuotaUnavailable)) throw e;
      tierHeaders['x-dnsguard-quota'] = 'unavailable';
    }
  } else if (tier === 'free') {
    // Hot path: zero KV writes. Per-minute = Rate Limiting binding; per-day = SQLite Durable Object.
    tierHeaders['x-dnsguard-tier'] = 'free';
    const qid = quotaIdFor(keyRec);
    if (await rateLimited(env, qid, 'key', L.keyPerMin)) {
      return err(429, 'rate_limited', `Free tier limit: about ${L.keyPerMin} checks per minute per key. Try again shortly.`, { 'retry-after': '60', ...tierHeaders });
    }
    const pool = budgetAllows('key', L);
    if (!pool.ok) return poolFull(pool.pool); // checked before the per-key DO so a full pool costs no DO request
    try {
      const quota = await consumeDailyQuota(env.QUOTA, qid, L.keyPerDay);
      if (!quota.ok) {
        return err(429, 'daily_quota_exceeded', `Free tier daily cap of ${fmt(L.keyPerDay)} checks reached for today (UTC ${quota.day}). Try again after 00:00 UTC, or upgrade to DnsGuard Pro for higher limits.`, { 'retry-after': String(secondsToUtcMidnight()), ...tierHeaders });
      }
      tierHeaders['x-dnsguard-quota-remaining'] = String(Math.max(0, quota.limit - quota.used));
    } catch (e) {
      if (!(e instanceof QuotaUnavailable)) throw e;
      // Fail open: the per-minute limit still applies; better to serve the check than error out.
      tierHeaders['x-dnsguard-quota'] = 'unavailable';
    }
    budgetRecord('key', env.QUOTA, ctx);
  } else {
    if (await rateLimited(env, ip, 'check', L.anonPerMin)) {
      return err(429, 'rate_limited', `Too many checks from your IP (about ${L.anonPerMin} per minute without a key). Try again in a minute, or use a free API key for higher limits.`, { 'retry-after': '60' });
    }
    const pool = budgetAllows('anon', L);
    if (!pool.ok) return poolFull(pool.pool);
    budgetRecord('anon', env.QUOTA, ctx);
  }

  try {
    const resolver = new Resolver({ fetchImpl: doFetch, timeoutMs: 2500 });
    let timer;
    const body = await Promise.race([
      checkDomain(domain, { selector, resolver, fetchImpl: doFetch }),
      new Promise((_, rej) => { timer = setTimeout(() => rej(new CheckError('timeout', 'The check took too long (DNS servers slow to answer). Please retry.', 504)), 9000); }),
    ]).finally(() => clearTimeout(timer));
    resultCache.set(cacheKey, { t: Date.now(), body });
    if (resultCache.size > 500) resultCache.delete(resultCache.keys().next().value);
    return { ok: true, body, headers: { 'x-cache': 'MISS', ...tierHeaders }, cached: false };
  } catch (e) {
    if (e instanceof CheckError) return err(e.httpStatus, e.code, e.message, tierHeaders);
    return err(500, 'internal_error', 'Unexpected error while checking the domain.', tierHeaders);
  }
}

export function createApp({ html, js, css, genJs = '', fetchImpl } = {}) {
  const route = createRouter({ html, js, css, genJs, fetchImpl });
  return async function handle(request, env = {}, ctx = {}) {
    let res;
    try {
      res = await route(request, env, ctx);
    } catch (e) {
      // Safety net: never let an exception become a Workers 1101 page. Always JSON + CORS.
      res = e instanceof StorageError ? storageError()
        : apiError(500, 'internal_error', 'Unexpected server error. Please retry.');
    }
    // While PUBLIC_LAUNCH !== "true", every response (pages, API, errors, preflight) carries noindex.
    if (staging(env)) res.headers.set('x-robots-tag', 'noindex, nofollow');
    else res.headers.delete('x-robots-tag');
    return res;
  };
}

function createRouter({ html, js, css, genJs, fetchImpl }) {
  return async function route(request, env = {}, ctx = {}) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const ip = request.headers.get('cf-connecting-ip') || 'local';
    // Never pass bare `fetch` as a value — Workers throws Illegal invocation. Wrap or leave undefined.
    const doFetch = fetchImpl || ((...a) => fetch(...a));

    if (request.method === 'OPTIONS' && path.startsWith('/api/')) return new Response(null, { status: 204, headers: { ...CORS } });

    // v0.8.0 daily unique visitors (LinkPulse pattern): human/API entry points only; off unless VISITOR_SALT is set.
    if ((request.method === 'GET' && (path === '/' || path === '/api/check')) || (request.method === 'POST' && path === '/mcp')) {
      countVisitor(request, env, ctx, ipBucket(ip));
    }

    // v0.8.0 RapidAPI marketplace route. Gate first (secret, constant time), then the same check as /api/check.
    if (isRapidApiPath(path)) {
      const denied = await rapidGate(request, env);
      if (denied) return apiError(denied.status, denied.code, denied.message);
      if (request.method !== 'GET') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET' });
      const tierName = rapidTier(request);
      if (path === '/rapidapi/v1/health') return json({ ok: true, version: VERSION, tier: tierName });
      if (path === '/rapidapi/v1/check') {
        let domain;
        try { domain = normalizeDomain(url.searchParams.get('domain') || ''); } catch (e) { return apiError(400, 'invalid_domain', e.message); }
        const selector = (url.searchParams.get('selector') || '').trim().toLowerCase() || undefined;
        if (selector && !SELECTOR_RE.test(selector)) return apiError(400, 'invalid_selector', 'selector may contain only letters, digits, "-", "_" and dots.');
        const auth = { tier: 'rapidapi', keyRec: null, proQid: null, rapidTier: tierName, rapidKey: await rapidUserKey(request, ipBucket(ip)) };
        const r = await runCheck({ domain, selector, auth, env, ctx, ip, doFetch });
        if (!r.ok) return apiError(r.status, r.code, r.message, r.headers);
        return json(r.body, 200, r.headers);
      }
      return apiError(404, 'not_found', 'Unknown RapidAPI endpoint. Use /rapidapi/v1/check or /rapidapi/v1/health.');
    }

    // v0.8.0 Glama connector claim (public).
    if (path === '/.well-known/glama.json') {
      if (request.method !== 'GET' && request.method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, HEAD' });
      return new Response(request.method === 'HEAD' ? null : GLAMA_CLAIM, { headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'public, max-age=3600', ...CORS, ...SECURITY } });
    }

    // --- Google OAuth (secret-gated; no Google JS SDK) ---
    if (path === '/api/auth/google') {
      if (request.method !== 'GET' && request.method !== 'POST') return apiError(405, 'method_not_allowed', 'Use GET (sign in) or POST intent=rotate.', { allow: 'GET, POST' });
      let rotate = false;
      if (request.method === 'POST') {
        // Rotation intent is accepted only from a same-origin form POST (never a bare GET or a cross-site form).
        const origin = request.headers.get('origin');
        const site = request.headers.get('sec-fetch-site');
        if ((origin && origin !== url.origin) || (!origin && site !== 'same-origin') || (site && site !== 'same-origin')) {
          return apiError(403, 'cross_site_request', 'Key rotation must be started from the DnsGuard page.');
        }
        let intent = '';
        try { const fd = await request.formData(); intent = String(fd.get('intent') || ''); } catch { /* ignore */ }
        if (intent !== 'rotate') return apiError(400, 'bad_request', 'Unknown intent.');
        rotate = true;
      }
      if (!oauthConfigured(env)) {
        return apiError(503, 'oauth_not_configured', 'Google sign-in is not configured yet. Free API key minting will turn on once GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are set. See the Pro section on the homepage for higher paid limits.');
      }
      const state = (rotate ? ROTATE_STATE_PREFIX : '') + randomToken(24);
      const redirectUri = callbackRedirectUri(url.origin);
      const authorize = buildAuthorizeUrl({ clientId: env.GOOGLE_CLIENT_ID, redirectUri, state });
      const secure = url.protocol === 'https:';
      return new Response(null, {
        status: rotate ? 303 : 302,
        headers: {
          location: authorize,
          'set-cookie': stateCookieHeader(state, { secure }),
          'cache-control': 'no-store',
          ...SECURITY,
        },
      });
    }

    if (path === '/api/auth/google/callback') {
      if (request.method !== 'GET') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET' });
      if (!oauthConfigured(env)) {
        return apiError(503, 'oauth_not_configured', 'Google sign-in is not configured yet.');
      }
      const kv = keysKv(env);
      if (!kv) return apiError(503, 'keys_unavailable', 'API key storage is not configured yet.');
      const secure = url.protocol === 'https:';
      const clearCookie = stateCookieHeader('', { clear: true, secure });
      const errPage = (code, message, status = 400) => {
        const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Sign-in error – DnsGuard</title>
<link rel="stylesheet" href="/style.css"><meta name="robots" content="noindex"></head>
<body><main class="wrap" style="padding:40px 18px"><h1>Sign-in could not finish</h1>
<p>${escapeHtml(message)}</p><p><a href="/#api">Back to API docs</a></p></main></body></html>`;
        return new Response(body, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'content-security-policy': CSP, 'set-cookie': clearCookie, ...SECURITY } });
      };
      const oauthErr = url.searchParams.get('error');
      if (oauthErr) return errPage('oauth_denied', `Google returned: ${oauthErr}. You can try again from the API section.`);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const expected = readStateCookie(request);
      if (!code || !state || !expected || state !== expected) {
        return errPage('oauth_state_mismatch', 'Invalid or expired sign-in state. Please start again from Continue with Google.');
      }
      try {
        const redirectUri = callbackRedirectUri(url.origin);
        const tokens = await exchangeCode({
          code,
          clientId: env.GOOGLE_CLIENT_ID,
          clientSecret: env.GOOGLE_CLIENT_SECRET,
          redirectUri,
          fetchImpl: doFetch,
        });
        const user = await fetchGoogleUser(tokens.access_token, doFetch);
        if (!user.email) return errPage('oauth_no_email', 'Google did not return an email for this account.');
        if (!user.emailVerified) {
          return errPage('oauth_email_unverified', "Your Google account's email address isn't verified, so we can't issue an API key. Verify the address with Google, then try again.", 403);
        }
        const intent = intentFromState(state);
        const minted = intent === 'rotate'
          ? await rotateFreeKey(kv, { googleSub: user.googleSub, email: user.email })
          : await mintOrGetFreeKey(kv, { googleSub: user.googleSub, email: user.email });
        // Prefer fragment redirect so the raw key never hits referrer/server logs via query.
        if (minted.rawKey) {
          return new Response(null, {
            status: 302,
            headers: {
              location: `/#${minted.rotated ? 'api-key-rotated' : 'api-key'}=${encodeURIComponent(minted.rawKey)}`,
              'set-cookie': clearCookie,
              'cache-control': 'no-store',
              ...SECURITY,
            },
          });
        }
        // Existing key: show HTML (no raw key to reveal).
        return new Response(keyRevealHtml({ rawKey: null, created: false, origin: url.origin, limits: limitsFor(env) }), {
          status: 200,
          headers: {
            'content-type': 'text/html; charset=utf-8',
            'cache-control': 'no-store',
            'content-security-policy': CSP_ROTATE,
            'set-cookie': clearCookie,
            ...SECURITY,
          },
        });
      } catch (e) {
        if (e instanceof StorageError) return errPage('storage_unavailable', STORAGE_MSG, 503);
        return errPage(e.code || 'oauth_error', e.message || 'OAuth failed.', 502);
      }
    }

    if (path === '/api/auth/status') {
      if (request.method !== 'GET') return apiError(405, 'method_not_allowed', 'Use GET.');
      const L = limitsFor(env);
      return json({
        google: oauthConfigured(env),
        freeApi: freeApiEnabled(env),
        limits: {
          anonymousPerMin: L.anonPerMin,
          freePerMin: L.keyPerMin,
          freePerDay: L.keyPerDay,
          proPerMin: L.proPerMin,
          proPerDay: L.proPerDay,
          // Shared daily pools across ALL users (UTC day, approximate): keep DnsGuard inside its hosting budget.
          // Pro licenses do not consume these free pools.
          sharedChecksPerDay: L.checksPerDay,
          sharedAnonymousChecksPerDay: L.anonPerDay,
        },
        proCheckout: true,
        proCheckoutUrl: PRO_CHECKOUT_URL,
        dailyCounter: env.QUOTA ? 'durable_object' : 'unavailable',
      });
    }

    if (path === '/api/check') {
      if (request.method !== 'GET') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, OPTIONS' });
      const raw = url.searchParams.get('domain');
      let domain;
      try { domain = normalizeDomain(raw || ''); } catch (e) { return apiError(400, 'invalid_domain', e.message); }
      const selector = (url.searchParams.get('selector') || '').trim().toLowerCase() || undefined;
      if (selector && !SELECTOR_RE.test(selector)) return apiError(400, 'invalid_selector', 'selector may contain only letters, digits, "-", "_" and dots.');
      // Auth runs before cache so invalid keys never get a free HIT.
      const auth = await authenticate(request, env);
      if (!auth.ok) return apiError(auth.status, auth.code, auth.message, auth.headers);
      const r = await runCheck({ domain, selector, auth, env, ctx, ip, doFetch });
      if (!r.ok) return apiError(r.status, r.code, r.message, r.headers);
      return json(r.body, 200, r.headers);
    }

    // v0.7.0: remote MCP server (Streamable HTTP, stateless, JSON responses). Same key gate + limits as /api/check.
    if (path === '/mcp') {
      return handleMcp(request, env, ctx, {
        authenticate, runCheck, ip, doFetch, origin: url.origin, memLimit,
        cors: MCP_CORS, security: SECURITY, allowedOrigins: env.MCP_ALLOWED_ORIGINS, anonPerMin: limitsFor(env).anonPerMin,
      });
    }

    // v0.7.0: agent discovery documents (plain text / JSON, no HTML, so no CSP needed beyond the default).
    if (path === '/llms.txt' || path === '/openapi.json' || path === '/.well-known/mcp-registry-auth') {
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...CORS } });
      if (request.method !== 'GET' && request.method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, HEAD' });
      const head = request.method === 'HEAD';
      const doc = (body, type, cache = 'public, max-age=3600') => new Response(head ? null : body, { headers: { 'content-type': type, 'cache-control': cache, ...CORS, ...SECURITY } });
      if (path === '/llms.txt') return doc(llmsTxt(url.origin, limitsFor(env)), 'text/plain; charset=utf-8');
      if (path === '/openapi.json') return doc(JSON.stringify(openApiSpec(url.origin, limitsFor(env)), null, 2), 'application/json; charset=utf-8');
      // Official MCP Registry HTTP namespace proof. Only the PUBLIC key lives in a wrangler var; 404 until it is set.
      const proof = String(env.MCP_REGISTRY_AUTH || '').trim();
      if (/^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/.test(proof)) return doc(`${proof}\n`, 'text/plain; charset=utf-8', 'no-store');
      return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain', ...SECURITY } });
    }

    if (path === '/api/health') return json({ ok: true, version: VERSION });

    if (path === '/api/waitlist' || path === '/api/waitlist/remove') {
      const removing = path === '/api/waitlist/remove';
      if (request.method !== 'POST') return apiError(405, 'method_not_allowed', 'Use POST.', { allow: 'POST' });
      if (!env.WAITLIST) return apiError(503, 'waitlist_unavailable', 'The waitlist is not configured yet.');
      if (await rateLimited(env, ip, 'waitlist', 5)) return apiError(429, 'rate_limited', 'Too many requests. Try again later.', { 'retry-after': '60' });
      let data = {};
      try {
        const ct = request.headers.get('content-type') || '';
        if (ct.includes('application/json')) data = await request.json();
        else { const fd = await request.formData(); data = Object.fromEntries(fd); }
        if (!data || typeof data !== 'object') data = {};
      } catch { return apiError(400, 'bad_request', 'Could not read the request body.'); }
      const okMsg = removing ? REMOVE_MSG : JOIN_MSG;
      if (data.website) return json({ ok: true, message: okMsg }); // honeypot field: silently accept bots, store/delete nothing
      const email = String(data.email || '').trim().toLowerCase();
      if (!EMAIL_RE.test(email) || email.length > 254) return apiError(400, 'invalid_email', 'Please enter a valid email address.');
      const key = `email:${email}`;
      // KV writes/deletes are billed past the account's monthly allowance on Workers Paid: cap them per UTC day.
      const L = limitsFor(env);
      if (!budgetAllows('waitlist', L).ok) {
        return apiError(429, 'daily_capacity_reached', `The waitlist has had too many requests today. Please try again after 00:00 UTC, or email ${CONTACT}.`, { 'retry-after': String(secondsToUtcMidnight()) });
      }
      budgetRecord('waitlist', env.QUOTA, ctx);
      if (removing) {
        // Always the same response whether or not the address was on the list (no enumeration).
        try { await kvDelete(env.WAITLIST, key); } catch { return storageError(); }
        return json({ ok: true, message: REMOVE_MSG });
      }
      try { await kvPut(env.WAITLIST, key, JSON.stringify({ email, joinedAt: new Date().toISOString() })); } catch { return storageError(); }
      return json({ ok: true, message: JOIN_MSG });
    }

    if (path.startsWith('/api/')) return apiError(404, 'not_found', 'Unknown API endpoint. See /#api for docs.');

    if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method not allowed', { status: 405 });
    const page = (body, type, cache = 'public, max-age=300') => new Response(body, { headers: { 'content-type': type, 'cache-control': cache, ...SECURITY, 'content-security-policy': CSP } });
    if (path === '/') return page(html, 'text/html; charset=utf-8');
    if (path === '/app.js') return page(js, 'text/javascript; charset=utf-8');
    if (path === '/generators.js') return page(genJs, 'text/javascript; charset=utf-8'); // v0.9.0 SPF/DMARC generators (client-side only)
    if (path === '/style.css') return page(css, 'text/css; charset=utf-8');
    if (path === '/robots.txt') return page(staging(env) ? 'User-agent: *\nDisallow: /\n' : `User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${url.origin}/sitemap.xml\n`, 'text/plain; charset=utf-8');
    if (path === '/sitemap.xml' && !staging(env)) return page(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${['/', ...GUIDE_PATHS, ...GENERATOR_PATHS].map((p) => `  <url><loc>${url.origin}${p}</loc></url>\n`).join('')}</urlset>\n`, 'application/xml; charset=utf-8');
    if (path === '/guides' || path.startsWith('/guides/')) {
      const g = guidePage(path, url.origin) || generatorPage(path, url.origin);
      if (g) return page(g, 'text/html; charset=utf-8');
    }
    if (path === '/favicon.ico' || path === '/favicon.svg') return page('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0f766e"/><path d="M16 6l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V9z" fill="#fff"/></svg>', 'image/svg+xml', 'public, max-age=86400');
    return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain', ...SECURITY, 'content-security-policy': CSP } });
  };
}
