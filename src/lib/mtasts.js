// MTA-STS (RFC 8461): TXT at _mta-sts.<domain> + policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt
// SSRF care: the policy URL is built ONLY from an already-normalized domain (normalizeDomain: no IP literals,
// valid labels, alphabetic TLD). We also refuse special-use TLDs, refuse to fetch when the policy host resolves
// (via DoH) to a private/reserved address, never follow redirects, cap time (3 s) and body size (64 KB), and
// only accept text.
import { DnsError } from './dns.js';

export const MAX_AGE_LIMIT = 31557600; // RFC 8461 §3.2
export const MAX_AGE_WEAK = 86400; // below one day: policy expires from sender caches quickly (weak)
export const MAX_AGE_RECOMMENDED = 604800; // RFC 8461 recommends weeks or more
export const POLICY_TIMEOUT_MS = 3000;
export const POLICY_MAX_BYTES = 65536;

export function isStsRecord(txt) { return /^v=STSv1\s*(;|$)/.test(String(txt).trim()); }

/** Parse "v=STSv1; id=..." (RFC 8461 §3.1). */
export function parseStsRecord(record) {
  const errors = [];
  const warnings = [];
  const tags = {};
  const parts = String(record).split(';').map((p) => p.trim()).filter(Boolean);
  parts.forEach((p, i) => {
    const eq = p.indexOf('=');
    if (eq < 1) { errors.push(`Malformed field "${p}" (expected key=value).`); return; }
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (i === 0 && (k !== 'v' || v !== 'STSv1')) errors.push('Record must start with "v=STSv1".');
    if (tags[k] !== undefined) warnings.push(`Field "${k}" appears more than once.`);
    else tags[k] = v;
  });
  const id = tags.id;
  if (id === undefined) errors.push('Missing required id= field.');
  else if (!/^[A-Za-z0-9]{1,32}$/.test(id)) errors.push(`Invalid id=${id.slice(0, 40)} (must be 1-32 letters or digits).`);
  return { record, tags, id: id && /^[A-Za-z0-9]{1,32}$/.test(id) ? id : null, errors, warnings };
}

/**
 *  Parse the policy file body (RFC 8461 §3.2). Lines are "key: value", CRLF or LF.
 * Caps: at most MAX_LINES read, MAX_MX patterns kept, MAX_MSGS errors/warnings returned.
 */
export function parseStsPolicy(text) {
  const MAX_LINES = 200, MAX_MX = 50, MAX_MSGS = 10;
  const errors = [];
  const warnings = [];
  const fields = {};
  const mx = [];
  let tooManyMx = 0;
  const lines = String(text).split(/\r?\n/);
  if (lines.length > MAX_LINES) errors.push(`Policy has ${lines.length} lines; only the first ${MAX_LINES} were read.`);
  for (const raw of lines.slice(0, MAX_LINES)) {
    const line = raw.trim();
    if (!line) continue;
    const c = line.indexOf(':');
    if (c < 1) { errors.push(`Malformed line "${line.slice(0, 60)}" (expected key: value).`); continue; }
    const k = line.slice(0, c).trim();
    const v = line.slice(c + 1).trim();
    if (k === 'mx') {
      if (v.length > 253) { errors.push('mx pattern longer than 253 characters.'); continue; }
      if (mx.length >= MAX_MX) { tooManyMx++; continue; }
      mx.push(v.toLowerCase().replace(/\.$/, '')); continue;
    }
    if (fields[k] !== undefined) { warnings.push(`Field "${k}" appears more than once; the first value is used.`); continue; }
    fields[k] = v;
  }
  if (tooManyMx) warnings.push(`${tooManyMx} more mx lines ignored (only the first ${MAX_MX} are checked).`);
  if (fields.version === undefined) errors.push('Missing "version: STSv1".');
  else if (fields.version !== 'STSv1') errors.push(`Unsupported version "${fields.version.slice(0, 20)}" (expected STSv1).`);
  let mode = null;
  if (fields.mode === undefined) errors.push('Missing "mode" (enforce, testing or none).');
  else if (['enforce', 'testing', 'none'].includes(fields.mode)) mode = fields.mode;
  else errors.push(`Invalid mode "${fields.mode.slice(0, 20)}" (must be enforce, testing or none).`);
  let maxAge = null;
  if (fields.max_age === undefined) errors.push('Missing "max_age".');
  else if (!/^\d{1,10}$/.test(fields.max_age)) errors.push(`Invalid max_age "${fields.max_age.slice(0, 20)}" (must be a whole number of seconds).`);
  else {
    maxAge = Number(fields.max_age);
    if (maxAge > MAX_AGE_LIMIT) errors.push(`max_age ${maxAge} is out of range (RFC 8461 allows at most ${MAX_AGE_LIMIT} seconds, about one year).`);
  }
  const badMx = mx.filter((p) => !isValidMxPattern(p));
  for (const p of badMx) errors.push(`Invalid mx pattern "${p.slice(0, 80)}".`);
  if (mode && mode !== 'none' && mx.length === 0) errors.push('No "mx" lines: a policy in enforce or testing mode must list the allowed MX hosts.');
  const cap = (a) => (a.length > MAX_MSGS ? [...a.slice(0, MAX_MSGS), `…and ${a.length - MAX_MSGS} more.`] : a);
  return { version: fields.version || null, mode, maxAge, mx, fields, errors: cap(errors), warnings: cap(warnings) };
}

const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
export function isValidMxPattern(p) {
  const s = String(p).toLowerCase().replace(/\.$/, '');
  const rest = s.startsWith('*.') ? s.slice(2) : s;
  const labels = rest.split('.');
  return labels.length >= 2 && labels.every((l) => LABEL.test(l));
}

/** RFC 8461 §4.1: "*.example.com" matches exactly one extra leftmost label; otherwise exact, case-insensitive. */
export function mxMatches(host, pattern) {
  const h = String(host).toLowerCase().replace(/\.$/, '');
  const p = String(pattern).toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    if (!h.endsWith(suffix)) return false;
    const first = h.slice(0, h.length - suffix.length);
    return first.length > 0 && !first.includes('.');
  }
  return h === p;
}

export function mxCoverage(mxHosts, patterns) {
  const covered = [];
  const uncovered = [];
  for (const h of mxHosts) (patterns.some((p) => mxMatches(h, p)) ? covered : uncovered).push(h);
  return { covered, uncovered };
}

// Special-use / internal-only TLDs that must never be fetched (normalizeDomain already blocks IP literals
// and single-label names like "localhost").
const BLOCKED_TLDS = new Set(['localhost', 'local', 'internal', 'test', 'invalid', 'example', 'onion', 'arpa', 'lan', 'home', 'corp', 'intranet', 'private', 'localdomain', 'alt']);
export function isFetchableHost(host) {
  const h = String(host).toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(h) || h.length > 253) return false;
  if (/^[\d.]+$/.test(h)) return false;
  const labels = h.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL.test(l))) return false;
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return false; // same TLD rule as normalizeDomain (no numeric TLDs)
  return !BLOCKED_TLDS.has(tld);
}

/** True for loopback, private, link-local, CGNAT, documentation, multicast and other non-public addresses. */
export function isPrivateAddress(ip) {
  const s = String(ip).trim().toLowerCase();
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (v4) {
    const [a, b, c] = v4.slice(1).map(Number);
    if (v4.slice(1).some((x) => Number(x) > 255)) return true;
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 192 && b === 0 && (c === 0 || c === 2)) || (a === 198 && (b === 18 || b === 19))
      || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
  }
  if (!s.includes(':')) return true; // not an IP we understand → treat as unsafe
  const mapped = /(?:^|:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s); // ::ffff:a.b.c.d, 64:ff9b::a.b.c.d
  if (mapped) return isPrivateAddress(mapped[1]);
  const full = expandV6(s);
  if (!full) return true;
  const w = full.map((x) => parseInt(x, 16));
  if (w.every((x) => x === 0)) return true; // ::
  if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return true; // ::1
  if (w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0)) return true; // mapped/compat v4 in hex form
  if (w[0] === 0x64 && w[1] === 0xff9b) return true; // NAT64
  if ((w[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((w[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((w[0] & 0xff00) === 0xff00) return true; // multicast
  if (w[0] === 0x2001 && w[1] === 0x0db8) return true; // documentation
  if (w[0] === 0x2002) return true; // 2002::/16 6to4
  if (w[0] === 0x2001 && w[1] === 0) return true; // 2001::/32 Teredo
  if ((w[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if (w[0] === 0x0100 && w[1] === 0) return true; // 100::/64 discard-only
  return false;
}
function expandV6(s) {
  const parts = s.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(':') : [];
  const fill = parts.length === 2 ? 8 - head.length - tail.length : 0;
  const all = [...head, ...Array(Math.max(0, fill)).fill('0'), ...tail];
  if (all.length !== 8 || !all.every((x) => /^[0-9a-f]{1,4}$/.test(x))) return null;
  return all;
}

/**
 * Fetch the policy file. Never throws; returns { ok, status, error, text, contentType, location }.
 * `fetchImpl` is injectable for tests.
 */
export async function fetchStsPolicy(domain, { fetchImpl, timeoutMs = POLICY_TIMEOUT_MS, maxBytes = POLICY_MAX_BYTES } = {}) {
  const host = `mta-sts.${domain}`;
  const url = `https://${host}/.well-known/mta-sts.txt`;
  const out = { url, ok: false, status: null, error: null, text: null, contentType: null, location: null };
  if (!isFetchableHost(host)) { out.error = 'blocked_host'; return out; }
  const doFetch = fetchImpl || ((...a) => fetch(...a));
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res;
  try {
    res = await doFetch(url, { method: 'GET', redirect: 'manual', signal: ctrl.signal, headers: { accept: 'text/plain' } });
    out.status = res.status;
    if (res.status >= 300 && res.status < 400) {
      out.error = 'redirect';
      out.location = (res.headers.get('location') || '').slice(0, 200) || null;
      return out;
    }
    if (res.status !== 200) { out.error = 'http_status'; return out; }
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    out.contentType = ct || null;
    if (ct && !ct.startsWith('text/')) { out.error = 'not_text'; return out; }
    const len = Number(res.headers.get('content-length'));
    if (Number.isFinite(len) && len > maxBytes) { out.error = 'too_large'; return out; }
    if (!res.body) { out.text = ''; out.ok = true; return out; }
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { out.error = 'too_large'; try { await reader.cancel(); } catch {} return out; }
      chunks.push(value);
    }
    const buf = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
    out.text = new TextDecoder('utf-8').decode(buf);
    out.ok = true;
    return out;
  } catch (e) {
    out.error = e && e.name === 'AbortError' ? 'timeout' : 'network';
    return out;
  } finally {
    clearTimeout(timer);
    if (res && res.body && !out.ok && !res.bodyUsed && !res.body.locked) { try { res.body.cancel().catch(() => {}); } catch {} }
  }
}

/** Resolve the policy host and refuse to fetch if it has no address or any address is non-public. */
async function policyHostSafe(host, resolver) {
  const [a, aaaa] = await Promise.all([resolver.query(host, 'A'), resolver.query(host, 'AAAA')]);
  const addrs = [...a.answers, ...aaaa.answers].map((x) => x.data);
  if (!addrs.length) return { ok: false, reason: 'no_address', addrs };
  if (addrs.some(isPrivateAddress)) return { ok: false, reason: 'private_address', addrs };
  return { ok: true, addrs };
}

export async function analyzeMtaSts(domain, resolver, { mxHosts = [], nullMx = false, fetchImpl, timeoutMs } = {}) {
  const out = {
    found: false, lookedUp: `_mta-sts.${domain}`, record: null, records: [], parsed: null, lookupError: null,
    policyUrl: `https://mta-sts.${domain}/.well-known/mta-sts.txt`, policyFetch: null, policy: null, coverage: null, nullMx,
  };
  try {
    const tx = await resolver.txt(out.lookedUp);
    out.records = tx.records.filter(isStsRecord);
    if (!out.records.length) return out;
    out.found = true;
    out.record = out.records[0];
    out.parsed = parseStsRecord(out.record);
    if (out.records.length > 1) out.parsed.errors.push(`Found ${out.records.length} MTA-STS records; senders ignore MTA-STS unless exactly one is published.`);
    if (out.parsed.errors.length || nullMx) return out; // invalid record (senders ignore it) or domain receives no mail: don't fetch
    const host = `mta-sts.${domain}`;
    if (!isFetchableHost(host)) { out.policyFetch = { url: out.policyUrl, ok: false, error: 'blocked_host' }; return out; }
    const safe = await policyHostSafe(host, resolver);
    if (!safe.ok) { out.policyFetch = { url: out.policyUrl, ok: false, error: safe.reason }; return out; }
  } catch (e) {
    if (!(e instanceof DnsError)) throw e;
    out.lookupError = e.message;
    return out;
  }
  const pf = await fetchStsPolicy(domain, { fetchImpl, timeoutMs });
  out.policyFetch = { url: pf.url, ok: pf.ok, status: pf.status, error: pf.error, contentType: pf.contentType, location: pf.location };
  if (!pf.ok) return out;
  out.policy = parseStsPolicy(pf.text);
  if (pf.contentType && !pf.contentType.startsWith('text/plain')) out.policy.warnings.push(`Policy is served as "${pf.contentType.slice(0, 60)}"; RFC 8461 requires text/plain.`);
  if (!pf.contentType) out.policy.warnings.push('Policy response has no Content-Type; RFC 8461 requires text/plain.');
  const hosts = mxHosts.filter((h) => h && h !== '.');
  if (hosts.length && out.policy.mx.length) out.coverage = mxCoverage(hosts, out.policy.mx);
  return out;
}
