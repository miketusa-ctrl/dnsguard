/**
 * DnsGuard remote MCP server (v0.7.0). Hand-rolled JSON-RPC 2.0 over Streamable HTTP; no SDK, no dependencies.
 *
 * Dual-era and stateless:
 *  - Modern (MCP 2026-07-28): every request carries params._meta["io.modelcontextprotocol/protocolVersion"] plus the
 *    MCP-Protocol-Version / Mcp-Method / Mcp-Name headers. Methods: server/discover, tools/list, tools/call.
 *  - Legacy (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05): initialize handshake, notifications/initialized, ping,
 *    tools/list, tools/call. JSON-RPC batches (max 10 messages, at most one tools/call) are accepted for legacy clients.
 *  - No sessions: no Mcp-Session-Id is ever issued; one sent by a client is ignored. GET/DELETE → 405 (no SSE stream).
 *  - Responses are always application/json (no SSE).
 *
 * Auth + limits are NOT implemented here: the router passes in authenticate() and runCheck() from app.js, the exact
 * functions behind GET /api/check, so key handling, the result cache and every rate/daily/shared-pool counter are
 * identical. One tools/call = one check. initialize / tools/list / ping / server/discover never touch check quota;
 * they have a light per-isolate cap per IP (DISCOVERY_PER_MIN).
 *
 * To adapt for another Worker: replace TOOLS + callTool() (and SERVER_INFO). Everything else is generic.
 */
import { normalizeDomain } from './domain.js';
import { VERSION } from './check.js';

export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_BATCH = 10;
export const MAX_CHECKS_PER_REQUEST = 1; // bounds CPU per invocation (cpu_ms = 50) and keeps 1 HTTP request ≈ 1 check
export const DISCOVERY_PER_MIN = 120; // per IP per isolate, for non-check messages (initialize, tools/list, ping, …)
const SELECTOR_RE = /^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63}){0,3}$/i; // same rule as /api/check
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CAPS = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER = 'io.modelcontextprotocol/serverInfo';

// JSON-RPC / MCP error codes
export const E = {
  PARSE: -32700, INVALID_REQUEST: -32600, METHOD_NOT_FOUND: -32601, INVALID_PARAMS: -32602, INTERNAL: -32603,
  SERVER: -32000, // implementation-defined (auth, rate limit, body too large, forbidden origin)
  HEADER_MISMATCH: -32020, UNSUPPORTED_VERSION: -32022,
};

export const MCP_CORS = {
  // Bearer keys are explicit (never ambient cookies), so a wildcard origin without credentials is safe and lets
  // browser-based MCP inspectors work. Same policy as /api/check.
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS', // GET/DELETE → 405 (no SSE stream, no sessions)
  'access-control-allow-headers': 'content-type, accept, authorization, x-api-key, mcp-protocol-version, mcp-method, mcp-name',
  'access-control-expose-headers': 'mcp-protocol-version, retry-after, x-cache, x-dnsguard-tier, x-dnsguard-quota-remaining, x-dnsguard-quota',
  'access-control-max-age': '86400',
};

export const SERVER_INFO = { name: 'dnsguard', title: 'DnsGuard', version: VERSION };
const instructions = (anonPerMin = 20) => 'DnsGuard checks a domain\'s public email-authentication DNS records (MX, SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT) and returns a 0–100 score, grade, findings and plain-English fixes. Call check_domain with a bare domain such as example.com. DKIM selectors cannot be listed via DNS: if no DKIM key is found, ask the user for the s= value of a DKIM-Signature header and pass it as dkim_selector. Results are cached for 2 minutes. Anonymous use is limited to about ' + anonPerMin + ' checks per minute per IP; send "Authorization: Bearer <key>" (free dg_live_ key or DnsGuard Pro DNSG- license) for higher limits.';

const CHECK_NAMES = { mx: 'MX', spf: 'SPF', dmarc: 'DMARC', dkim: 'DKIM', bimi: 'BIMI', mtaSts: 'MTA-STS', tlsRpt: 'TLS-RPT' };
const findingSchema = { type: 'object', properties: { level: { type: 'string', enum: ['pass', 'info', 'warn', 'fail'] }, message: { type: 'string' } }, required: ['level', 'message'] };
const checkSchema = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
    score: { type: 'number' },
    maxScore: { type: 'number' },
    bonus: { type: 'boolean', description: 'true for MTA-STS / TLS-RPT (bonus points on top of the 100-point core)' },
    record: { type: 'string', description: 'Published record (omitted when none was found)' },
    findings: { type: 'array', items: findingSchema },
    recommendations: { type: 'array', items: { type: 'string' } },
  },
  required: ['status', 'score', 'maxScore', 'findings', 'recommendations'],
};

export const TOOLS = [{
  name: 'check_domain',
  title: 'Check a domain\'s email authentication (SPF, DKIM, DMARC, BIMI, MX, MTA-STS, TLS-RPT)',
  description: 'Audit the email-authentication DNS records of a domain. Returns a 0–100 score and A–F grade (MX 10, SPF 25, DMARC 30, DKIM 25, BIMI 10, plus up to 5 bonus points for MTA-STS and TLS-RPT, capped at 100), each check\'s status, published record, findings and recommended fixes, and a link to the full report. Read-only: it only queries public DNS and the domain\'s public MTA-STS policy file. Same engine and scoring as the DnsGuard JSON API (GET /api/check).',
  inputSchema: {
    type: 'object',
    properties: {
      domain: { type: 'string', minLength: 1, maxLength: 300, description: 'Domain to check, e.g. example.com. A URL or email address is accepted and reduced to its domain.' },
      dkim_selector: { type: 'string', maxLength: 255, description: 'Optional DKIM selector (the s= value from a DKIM-Signature header), e.g. s1 or google. Common selectors are always tried.' },
      include_raw: { type: 'boolean', default: false, description: 'Also return the full /api/check JSON (all records, SPF include tree, DKIM keys) in structuredContent.raw. Larger output.' },
    },
    required: ['domain'],
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      domain: { type: 'string' },
      organizationalDomain: { type: 'string' },
      score: { type: 'number' },
      maxScore: { type: 'number' },
      grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'F'] },
      scoreBreakdown: { type: 'object', properties: { base: { type: 'number' }, bonus: { type: 'number' }, bonusMax: { type: 'number' }, cap: { type: 'number' } } },
      checks: { type: 'object', properties: Object.fromEntries(Object.keys(CHECK_NAMES).map((k) => [k, checkSchema])) },
      notes: { type: 'array', items: { type: 'string' } },
      checkedAt: { type: 'string' },
      cached: { type: 'boolean' },
      tier: { type: 'string', enum: ['anonymous', 'free', 'pro'] },
      reportUrl: { type: 'string' },
      apiUrl: { type: 'string' },
      version: { type: 'string' },
      raw: { type: 'object', description: 'Full /api/check response (only when include_raw is true)' },
    },
    required: ['domain', 'score', 'maxScore', 'grade', 'checks', 'reportUrl'],
  },
  annotations: { title: 'Check email domain', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
}];
const TOOL_ARGS = new Set(Object.keys(TOOLS[0].inputSchema.properties)); // inputSchema says additionalProperties: false; enforced in callTool

const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Concise, schema-conforming summary of a full /api/check body. */
export function summarizeCheck(body, { origin, tier, cached, includeRaw }) {
  const checks = {};
  for (const k of Object.keys(CHECK_NAMES)) {
    const c = body.checks && body.checks[k];
    if (!c) continue;
    checks[k] = {
      status: c.status,
      score: c.score,
      maxScore: c.maxScore,
      ...(c.bonus ? { bonus: true } : {}),
      ...(typeof c.record === 'string' ? { record: clip(c.record, 600) } : {}),
      findings: (c.findings || []).slice(0, 8).map((f) => ({ level: f.level, message: clip(String(f.message), 300) })),
      recommendations: (c.recommendations || []).slice(0, 4).map((r) => clip(String(r), 300)),
    };
  }
  const q = `domain=${encodeURIComponent(body.domain)}`;
  const out = {
    domain: body.domain,
    organizationalDomain: body.organizationalDomain,
    score: body.score,
    maxScore: body.maxScore,
    grade: body.grade,
    scoreBreakdown: body.scoreBreakdown,
    checks,
    notes: (body.notes || []).map((n) => clip(String(n), 400)),
    checkedAt: body.checkedAt,
    cached: !!cached,
    tier: tier || 'anonymous',
    reportUrl: `${origin}/?${q}`,
    apiUrl: `${origin}/api/check?${q}`,
    version: (body.meta && body.meta.version) || VERSION,
  };
  if (includeRaw) out.raw = body;
  return out;
}

/** Human/LLM-readable text version of the summary (also the content[0] block). */
export function summaryText(s) {
  const lines = [`DnsGuard check for ${s.domain}: ${s.score}/${s.maxScore} (grade ${s.grade})`
    + (s.scoreBreakdown ? ` — core ${s.scoreBreakdown.base}/100 + bonus ${s.scoreBreakdown.bonus}/${s.scoreBreakdown.bonusMax}` : '') + '.'];
  const fixes = [];
  for (const [k, c] of Object.entries(s.checks)) {
    const worst = c.findings.find((f) => f.level === 'fail') || c.findings.find((f) => f.level === 'warn') || c.findings[0];
    lines.push(`- ${CHECK_NAMES[k]}: ${c.status.toUpperCase()} ${c.score}/${c.maxScore}${c.bonus ? ' bonus' : ''}${worst ? ` — ${worst.message}` : ''}`);
    for (const r of c.recommendations.slice(0, 2)) fixes.push(`- [${CHECK_NAMES[k]}] ${r}`);
  }
  if (fixes.length) lines.push('', 'Recommended fixes:', ...fixes.slice(0, 8));
  if (s.notes.length) lines.push('', 'Notes:', ...s.notes.map((n) => `- ${n}`));
  lines.push('', `Full report: ${s.reportUrl}`);
  return lines.join('\n');
}

function toolError(message, data, extra = {}) {
  return { content: [{ type: 'text', text: message }], isError: true, ...(data ? { _meta: { 'dnsguard/error': data } } : {}), ...extra };
}

/** tools/call for check_domain. Returns { result } or { error } (protocol error), plus HTTP headers to surface. */
async function callTool(params, deps, auth) {
  const { name } = params;
  const args = params.arguments === undefined ? {} : params.arguments;
  if (name !== 'check_domain') return { error: { code: E.INVALID_PARAMS, message: `Unknown tool: ${clip(String(name), 80)}` } };
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { error: { code: E.INVALID_PARAMS, message: 'arguments must be an object' } };
  // Input problems are tool-execution errors (isError) so the model can correct itself.
  const unknown = Object.keys(args).filter((k) => !TOOL_ARGS.has(k));
  if (unknown.length) {
    return { result: toolError(`Unknown argument(s): ${clip(unknown.slice(0, 5).join(', '), 80)}. Allowed: ${[...TOOL_ARGS].join(', ')}.`, { code: 'invalid_arguments', httpStatus: 400 }) };
  }
  let domain;
  try { domain = normalizeDomain(typeof args.domain === 'string' ? args.domain : ''); } catch (e) {
    return { result: toolError(`Invalid domain: ${e.message}.`, { code: 'invalid_domain', httpStatus: 400 }) };
  }
  let selector;
  if (args.dkim_selector !== undefined && args.dkim_selector !== null) {
    if (typeof args.dkim_selector !== 'string') return { result: toolError('dkim_selector must be a string.', { code: 'invalid_selector', httpStatus: 400 }) };
    selector = args.dkim_selector.trim().toLowerCase() || undefined;
    if (selector && !SELECTOR_RE.test(selector)) return { result: toolError('dkim_selector may contain only letters, digits, "-", "_" and dots.', { code: 'invalid_selector', httpStatus: 400 }) };
  }
  const r = await deps.runCheck({ domain, selector, auth, env: deps.env, ctx: deps.ctx, ip: deps.ip, doFetch: deps.doFetch });
  const headers = { ...(r.headers || {}) };
  if (!r.ok) {
    const retry = r.headers && r.headers['retry-after'] ? Number(r.headers['retry-after']) : undefined;
    const msg = `${r.message}${retry ? ` (retry after ${retry} seconds)` : ''}`;
    return { result: toolError(msg, { code: r.code, httpStatus: r.status, ...(retry ? { retryAfterSeconds: retry } : {}) }), headers };
  }
  const summary = summarizeCheck(r.body, { origin: deps.origin, tier: auth.tier, cached: r.cached, includeRaw: args.include_raw === true });
  return { result: { content: [{ type: 'text', text: summaryText(summary) }], structuredContent: summary, isError: false }, headers };
}

// ---------- transport helpers ----------

/** Origin policy: absent = OK (CLI / server-side clients). Present: must be a bare https origin or an http loopback
 * origin, or (if MCP_ALLOWED_ORIGINS is set) same-origin / listed. Malformed, "null" and plain-http remote → 403. */
export function originAllowed(origin, selfOrigin, allowList) {
  if (origin === null || origin === undefined) return true;
  if (origin === selfOrigin) return true;
  if (allowList) return String(allowList).split(',').map((s) => s.trim()).filter(Boolean).includes(origin);
  let u;
  try { u = new URL(origin); } catch { return false; }
  if (u.origin !== origin) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

async function readCapped(request, cap) {
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > cap) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(buf);
}

function decodeHeaderValue(v) {
  if (v == null) return v;
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return v;
  try { return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (ch) => ch.charCodeAt(0))); } catch { return null; }
}

const isId = (id) => typeof id === 'string' || Number.isSafeInteger(id);
const rpcError = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), error: { code, message, ...(data !== undefined ? { data } : {}) } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

/**
 * Handle one JSON-RPC message. Returns { response?, status?, headers?, isCheck? }.
 * `response` undefined = notification accepted (202 when it's the whole request).
 */
async function handleMessage(msg, { modern, request, deps, auth, checkBudget }) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request'), status: 400 };
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  if (msg.jsonrpc !== '2.0') return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"'), status: 400 };
  if (typeof msg.method !== 'string') {
    // A JSON-RPC response or garbage. Legacy clients may POST responses → accept like a notification.
    if (!modern && hasId && ('result' in msg || 'error' in msg)) return {};
    return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: method is required'), status: 400 };
  }
  if (!hasId) return {}; // notification (notifications/initialized, cancelled, …): accepted, nothing to do
  if (!isId(msg.id)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request: id must be a string or number'), status: 400 };
  const { id, method } = msg;
  const params = msg.params === undefined ? {} : msg.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return { response: rpcError(id, E.INVALID_PARAMS, 'params must be an object') };

  const done = (result) => ({ response: rpcResult(id, modern ? { resultType: 'complete', ...result, _meta: { ...(result._meta || {}), [META_SERVER]: SERVER_INFO } } : result) });
  const notFound = () => ({ response: rpcError(id, E.METHOD_NOT_FOUND, `Method not found: ${clip(method, 80)}`), status: modern ? 404 : 200 });

  if (modern) {
    // MCP 2026-07-28 per-request validation (version, capabilities, mirrored headers).
    const hName = decodeHeaderValue(request.headers.get('mcp-name'));
    if (request.headers.get('mcp-method') !== method) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Method header is missing or does not match the body method'), status: 400 };
    if (!params._meta || typeof params._meta[META_CAPS] !== 'object' || params._meta[META_CAPS] === null) {
      return { response: rpcError(id, E.INVALID_PARAMS, `Missing required _meta field ${META_CAPS}`), status: 400 };
    }
    if (method === 'tools/call' && hName !== params.name) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Name header is missing or does not match params.name'), status: 400 };
    if (method === 'server/discover') {
      return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, instructions: instructions(deps.anonPerMin), ttlMs: 3_600_000, cacheScope: 'public' });
    }
    if (method === 'tools/list') return done({ tools: TOOLS, ttlMs: 3_600_000, cacheScope: 'public' });
    if (method !== 'tools/call') return notFound(); // includes initialize and ping (removed in 2026-07-28)
  } else {
    if (method === 'initialize') {
      const req = params.protocolVersion;
      const protocolVersion = LEGACY_VERSIONS.includes(req) ? req : LEGACY_VERSIONS[0];
      return done({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instructions(deps.anonPerMin) });
    }
    if (method === 'ping') return done({});
    if (method === 'tools/list') return done({ tools: TOOLS });
    if (method === 'server/discover') return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instructions(deps.anonPerMin) });
    if (method !== 'tools/call') return notFound();
  }

  // tools/call
  if (typeof params.name !== 'string') return { response: rpcError(id, E.INVALID_PARAMS, 'params.name (tool name) is required') };
  if (checkBudget.used >= MAX_CHECKS_PER_REQUEST) {
    return { response: rpcError(id, E.INVALID_REQUEST, `At most ${MAX_CHECKS_PER_REQUEST} tools/call per HTTP request; send each call as its own request.`) };
  }
  checkBudget.used++;
  const r = await callTool(params, deps, auth);
  if (r.error) return { response: rpcError(id, r.error.code, r.error.message), isCheck: true };
  return { ...done(r.result), headers: r.headers, isCheck: true };
}

/** Entry point from the router for every request to /mcp. */
export async function handleMcp(request, env, ctx, deps) {
  const base = { ...deps.cors, ...deps.security };
  const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), 'cache-control': 'no-store', ...base, ...extra },
  });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...deps.cors } });
  if (!originAllowed(request.headers.get('origin'), deps.origin, deps.allowedOrigins)) {
    return reply(403, rpcError(undefined, E.SERVER, 'Forbidden: Origin not allowed'));
  }
  if (request.method !== 'POST') {
    return reply(405, rpcError(undefined, E.SERVER, 'Method not allowed. This MCP endpoint is stateless: POST JSON-RPC messages (no SSE stream, no sessions). Docs: /llms.txt'), { allow: 'POST, OPTIONS' });
  }
  const text = await readCapped(request, MAX_BODY_BYTES);
  if (text === null) return reply(413, rpcError(undefined, E.INVALID_REQUEST, `Request body too large (max ${MAX_BODY_BYTES} bytes)`));
  let payload;
  try { payload = JSON.parse(text); } catch { return reply(400, rpcError(null, E.PARSE, 'Parse error: body must be valid JSON')); }

  // Era detection. Modern = per-request _meta version or a modern MCP-Protocol-Version header.
  const hVer = request.headers.get('mcp-protocol-version');
  const single = !Array.isArray(payload);
  const metaVer = single && payload && typeof payload === 'object' && payload.params && typeof payload.params === 'object'
    && payload.params._meta && typeof payload.params._meta === 'object' ? payload.params._meta[META_VERSION] : undefined;
  const modern = metaVer !== undefined || MODERN_VERSIONS.includes(hVer);
  const idOf = (p) => (p && typeof p === 'object' && isId(p.id) ? p.id : null);
  if (modern) {
    if (!single) return reply(400, rpcError(null, E.INVALID_REQUEST, 'JSON-RPC batches are not supported in protocol 2026-07-28; send one message per POST'));
    if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'id')) {
      if (metaVer === undefined && typeof payload.method === 'string') {
        return reply(400, rpcError(idOf(payload), E.INVALID_PARAMS, `Missing required _meta field ${META_VERSION}`));
      }
      if (metaVer !== undefined && !SUPPORTED_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(String(metaVer), 40) }));
      }
      if (metaVer !== undefined && !MODERN_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, `Protocol version ${metaVer} uses the initialize handshake; per-request _meta requires one of: ${MODERN_VERSIONS.join(', ')}`, { supported: SUPPORTED_VERSIONS, requested: metaVer }));
      }
      if (hVer !== metaVer) return reply(400, rpcError(idOf(payload), E.HEADER_MISMATCH, 'Header mismatch: MCP-Protocol-Version header is missing or does not match _meta protocolVersion'));
    }
  } else if (hVer && !LEGACY_VERSIONS.includes(hVer)) {
    return reply(400, rpcError(single ? idOf(payload) : null, E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(hVer, 40) }));
  }

  const msgs = single ? [payload] : payload;
  if (!msgs.length) return reply(400, rpcError(null, E.INVALID_REQUEST, 'Invalid Request: empty batch'));
  if (msgs.length > MAX_BATCH) return reply(400, rpcError(null, E.INVALID_REQUEST, `Batch too large (max ${MAX_BATCH} messages)`));

  // Light per-IP cap on non-check messages (checks are governed by the /api/check limits inside runCheck).
  const nonCheck = msgs.filter((m) => !(m && m.method === 'tools/call')).length;
  for (let i = 0; i < nonCheck; i++) {
    if (!deps.memLimit(`mcp:${deps.ip}`, DISCOVERY_PER_MIN, 60_000)) {
      return reply(429, rpcError(single ? idOf(payload) : null, E.SERVER, `Too many MCP requests from your IP (about ${DISCOVERY_PER_MIN} per minute). Retry in a minute.`, { code: 'rate_limited', retryAfterSeconds: 60 }), { 'retry-after': '60' });
    }
  }

  // Same key gate as /api/check, evaluated once per HTTP request (bad key → 401 for every method).
  const auth = await deps.authenticate(request, env);
  if (!auth.ok) {
    // No WWW-Authenticate on /mcp: MCP clients treat a 401 Bearer challenge as "start OAuth discovery", which this
    // server doesn't offer; the JSON-RPC error body (data.code = invalid_api_key) is the useful signal.
    const extra = { ...(auth.headers || {}) };
    return reply(auth.status, rpcError(single ? idOf(payload) : null, E.SERVER, auth.message, { code: auth.code, httpStatus: auth.status }), extra);
  }

  const mdeps = { ...deps, env, ctx };
  const checkBudget = { used: 0 };
  const responses = [];
  let status = 200;
  let headers = {};
  for (const m of msgs) {
    let out;
    try {
      out = await handleMessage(m, { modern, request, deps: mdeps, auth, checkBudget });
    } catch {
      out = { response: rpcError(idOf(m), E.INTERNAL, 'Internal error') };
    }
    if (out.response) responses.push(out.response);
    if (single) { status = out.status || 200; headers = out.headers || {}; }
  }
  if (!responses.length) return reply(202, null);
  const exposed = {};
  for (const h of ['retry-after', 'x-cache', 'x-dnsguard-tier', 'x-dnsguard-quota-remaining', 'x-dnsguard-quota']) if (headers[h]) exposed[h] = headers[h];
  return reply(status, single ? responses[0] : responses, exposed);
}
