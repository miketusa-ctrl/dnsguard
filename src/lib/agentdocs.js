/**
 * Agent-discovery documents (since v0.7.0): /llms.txt (llmstxt.org format) and /openapi.json (OpenAPI 3.1).
 * Generated from code constants so limits / versions / URLs can't drift from what the Worker enforces.
 */
import { VERSION } from './check.js';
import { PRO_CHECKOUT_URL, PRO_PRICE } from './pro.js';
import { TOOLS, SUPPORTED_VERSIONS, MAX_BODY_BYTES, MAX_BATCH, DISCOVERY_PER_MIN } from './mcp.js';

export const CONTACT_EMAIL = 'digitalpromohub.support+dnsguard@gmail.com';
const fmt = (n) => n.toLocaleString('en-US');

export function mcpClientConfig(origin) {
  return { mcpServers: { dnsguard: { type: 'http', url: `${origin}/mcp` } } };
}

export function llmsTxt(origin, L) {
  const tool = TOOLS[0];
  return `# DnsGuard

> Free email-domain health checker for SPF, DKIM, DMARC, BIMI, MX, MTA-STS and TLS-RPT. Returns a 0–100 score, an A–F grade, per-record findings and plain-English fixes. Public JSON API plus a remote MCP server for AI agents.

DnsGuard only reads public data: DNS records (over DNS-over-HTTPS) and, when a domain publishes MTA-STS, its public policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt. It does not send email or store the domains you check.

Scoring: MX 10, SPF 25, DMARC 30, DKIM 25, BIMI 10 = 100 core points. MTA-STS (up to 3) and TLS-RPT (up to 2) add up to 5 bonus points, applied only when SPF passes and DMARC is p=quarantine or p=reject; the total is capped at 100. Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F. DKIM selectors can't be listed via DNS, so common and provider-specific selectors are tried; pass your own selector for an exact result.

## For AI agents

- [MCP server](${origin}/mcp): remote MCP over Streamable HTTP at \`${origin}/mcp\` (POST only, stateless, JSON responses, no sessions). Protocol versions: ${SUPPORTED_VERSIONS.join(', ')} (2026-07-28 per-request \`_meta\`; older versions use \`initialize\`). One tool: \`${tool.name}\` with \`domain\` (required), \`dkim_selector\` and \`include_raw\` (optional). Read-only. Client config (most MCP clients accept this; some use a different format, for example VS Code uses a \`servers\` key): \`${JSON.stringify(mcpClientConfig(origin))}\`
- [OpenAPI 3.1 spec](${origin}/openapi.json): machine-readable description of the JSON API
- [JSON API docs](${origin}/#api): human-readable API reference with examples

## JSON API

- \`GET ${origin}/api/check?domain=example.com\` (optional \`&selector=<dkim-selector>\`): full check as JSON (\`score\`, \`grade\`, \`scoreBreakdown\`, \`checks.{mx,spf,dmarc,dkim,bimi,mtaSts,tlsRpt}\` each with \`status\`, \`score\`, \`findings\`, \`recommendations\`, \`record\`). CORS enabled.
- \`GET ${origin}/api/health\`: \`{ "ok": true, "version": "${VERSION}" }\`
- \`GET ${origin}/api/auth/status\`: current limits and whether free-key sign-in is available
- Errors: \`{ "error": { "code", "message" } }\` with HTTP 400 \`invalid_domain\`/\`invalid_selector\`, 401 \`invalid_api_key\`, 422 \`domain_not_found\`, 429 \`rate_limited\`/\`daily_quota_exceeded\`/\`daily_capacity_reached\` (see \`Retry-After\`), 502 \`dns_unavailable\`, 503, 504 \`timeout\`.

## Limits, keys and pricing

- Anonymous (no key): about ${L.anonPerMin} checks per minute per IP; all anonymous users share about ${fmt(L.anonPerDay)} checks per UTC day.
- Free API key (sign in with Google on the homepage): about ${L.keyPerMin} checks per minute and ${fmt(L.keyPerDay)} per UTC day. Send \`Authorization: Bearer dg_live_…\` (or \`X-Api-Key\`).
- DnsGuard Pro, ${PRO_PRICE} via Polar: about ${L.proPerMin} checks per minute and ${fmt(L.proPerDay)} per UTC day per license. Send \`Authorization: Bearer DNSG-…\`. [Subscribe](${PRO_CHECKOUT_URL})
- The MCP endpoint uses the same keys and the same counters: each \`tools/call\` is one check. \`initialize\`, \`tools/list\` and other non-check messages don't count as checks, but have a light cap of about ${DISCOVERY_PER_MIN} per minute per IP (over it: HTTP 429 with \`Retry-After\`). Over a limit, the tool result has \`isError: true\` with the reason and \`retryAfterSeconds\`. An invalid key returns HTTP 401. Results are cached for 2 minutes and cache hits don't count.
- MCP request caps: ${fmt(MAX_BODY_BYTES)}-byte body, JSON-RPC batches (legacy versions only) of at most ${MAX_BATCH} messages with at most one \`tools/call\`.

## Guides

- [SPF guide](${origin}/guides/spf): syntax, the 10-lookup limit, common mistakes
- [DKIM guide](${origin}/guides/dkim): selectors, key sizes, rotation
- [DMARC guide](${origin}/guides/dmarc): policies, reporting, rollout plan
- [BIMI guide](${origin}/guides/bimi): logo requirements and VMC certificates
- [MTA-STS and TLS-RPT guide](${origin}/guides/mta-sts): policy file, modes, reporting
- [SPF record generator](${origin}/guides/spf/generator): build a v=spf1 TXT record in the browser (client-side only, no API)
- [DMARC record generator](${origin}/guides/dmarc/generator): build a v=DMARC1 record for _dmarc (client-side only, no API)

## Optional

- [Homepage and checker](${origin}/)
- [Privacy](${origin}/#privacy)
- Contact: ${CONTACT_EMAIL}
`;
}

const errorSchema = { $ref: '#/components/schemas/Error' };
const errResp = (description, extraHeaders) => ({
  description,
  ...(extraHeaders ? { headers: extraHeaders } : {}),
  content: { 'application/json': { schema: errorSchema } },
});
const mcpNotAllowed = (m) => ({
  tags: ['mcp'],
  operationId: `mcp_${m}_not_allowed`,
  summary: 'Not supported (stateless server: no SSE stream, no sessions)',
  responses: {
    405: { description: 'Always 405 with `Allow: POST, OPTIONS` and a JSON-RPC error body', headers: { Allow: { schema: { type: 'string', const: 'POST, OPTIONS' } } }, content: { 'application/json': { schema: { type: 'object' } } } },
  },
});
const retryAfter = { 'Retry-After': { description: 'Seconds to wait before retrying', schema: { type: 'integer' } } };

export function openApiSpec(origin, L) {
  const tierHeaders = {
    'x-cache': { description: '`HIT` (served from the 2-minute result cache; no quota used) or `MISS`', schema: { type: 'string', enum: ['HIT', 'MISS'] } },
    'x-dnsguard-tier': { description: 'Present on keyed requests: `free` or `pro`', schema: { type: 'string', enum: ['free', 'pro'] } },
    'x-dnsguard-quota-remaining': { description: 'Keyed MISS responses: checks left in your daily cap (UTC day)', schema: { type: 'integer' } },
    'x-dnsguard-quota': { description: '`unavailable` when the daily counter could not be reached (the check is still served; the per-minute limit applies)', schema: { type: 'string', enum: ['unavailable'] } },
  };
  return {
    openapi: '3.1.0',
    info: {
      title: 'DnsGuard API',
      version: VERSION,
      summary: 'Email-domain health checks: SPF, DKIM, DMARC, BIMI, MX, MTA-STS, TLS-RPT.',
      description: `Free JSON API behind ${origin}. No key needed for light use (about ${L.anonPerMin} checks/min per IP; anonymous users share about ${fmt(L.anonPerDay)} checks per UTC day). A free API key (Google sign-in on the homepage) allows about ${L.keyPerMin}/min and ${fmt(L.keyPerDay)}/day; DnsGuard Pro (${PRO_PRICE}, ${PRO_CHECKOUT_URL}) about ${L.proPerMin}/min and ${fmt(L.proPerDay)}/day. Results are cached for 2 minutes per edge isolate; cache hits do not count. There are no X-RateLimit-* headers; a 429 carries Retry-After. AI agents can also use the remote MCP server at ${origin}/mcp (see /llms.txt).`,
      contact: { name: 'DnsGuard', email: CONTACT_EMAIL, url: origin },
    },
    servers: [{ url: origin }],
    externalDocs: { description: 'Human-readable API docs', url: `${origin}/#api` },
    tags: [{ name: 'checks' }, { name: 'meta' }, { name: 'mcp' }],
    components: {
      securitySchemes: {
        bearerAuth: { type: 'http', scheme: 'bearer', description: 'Free key (`dg_live_` + 64 hex) or DnsGuard Pro license (prefix `DNSG`). Optional.' },
        apiKeyHeader: { type: 'apiKey', in: 'header', name: 'X-Api-Key', description: 'Same keys as bearerAuth, alternative header.' },
      },
      schemas: {
        Error: {
          type: 'object', required: ['error'],
          properties: { error: { type: 'object', required: ['code', 'message'], properties: { code: { type: 'string' }, message: { type: 'string' } } } },
        },
        Finding: { type: 'object', required: ['level', 'message'], properties: { level: { type: 'string', enum: ['pass', 'info', 'warn', 'fail'] }, message: { type: 'string' } } },
        Check: {
          type: 'object', required: ['status', 'score', 'maxScore', 'findings', 'recommendations'],
          description: 'Common fields of every check. Each check adds its own record-specific fields (e.g. spf.lookupCount, dmarc.policy, dkim.keys, mtaSts.policyFetch).',
          additionalProperties: true,
          properties: {
            status: { type: 'string', enum: ['pass', 'warn', 'fail', 'info'] },
            score: { type: 'number' },
            maxScore: { type: 'number' },
            bonus: { type: 'boolean', description: 'true for mtaSts and tlsRpt (bonus points)' },
            notApplicable: { type: 'boolean' },
            record: { type: ['string', 'null'] },
            findings: { type: 'array', items: { $ref: '#/components/schemas/Finding' } },
            recommendations: { type: 'array', items: { type: 'string' } },
          },
        },
        CheckResult: {
          type: 'object',
          required: ['domain', 'organizationalDomain', 'checkedAt', 'score', 'maxScore', 'scoreBreakdown', 'grade', 'notes', 'checks', 'meta'],
          properties: {
            domain: { type: 'string', examples: ['example.com'] },
            organizationalDomain: { type: 'string' },
            nonSending: { type: 'boolean', description: 'Null MX + "v=spf1 -all": DKIM and BIMI scored not applicable' },
            checkedAt: { type: 'string', format: 'date-time' },
            score: { type: 'integer', minimum: 0, maximum: 100 },
            maxScore: { type: 'integer', const: 100 },
            scoreBreakdown: {
              type: 'object', required: ['base', 'bonus', 'bonusMax', 'cap'],
              properties: { base: { type: 'integer' }, bonus: { type: 'integer' }, bonusMax: { type: 'integer', const: 5 }, cap: { type: 'integer', const: 100 } },
            },
            grade: { type: 'string', enum: ['A', 'B', 'C', 'D', 'F'] },
            notes: { type: 'array', items: { type: 'string' } },
            checks: {
              type: 'object',
              required: ['mx', 'spf', 'dmarc', 'dkim', 'bimi', 'mtaSts', 'tlsRpt'],
              properties: Object.fromEntries(['mx', 'spf', 'dmarc', 'dkim', 'bimi', 'mtaSts', 'tlsRpt'].map((k) => [k, { $ref: '#/components/schemas/Check' }])),
            },
            meta: {
              type: 'object',
              properties: { version: { type: 'string' }, dnsQueries: { type: 'integer' }, resolvers: { type: 'array', items: { type: 'string' } }, durationMs: { type: 'integer' } },
            },
          },
        },
        JsonRpcMessage: {
          type: 'object', required: ['jsonrpc'],
          properties: { jsonrpc: { const: '2.0' }, id: { type: ['string', 'integer'] }, method: { type: 'string' }, params: { type: 'object' } },
        },
      },
    },
    paths: {
      '/api/check': {
        get: {
          tags: ['checks'],
          operationId: 'checkDomain',
          summary: 'Check a domain\'s email authentication records',
          security: [{}, { bearerAuth: [] }, { apiKeyHeader: [] }],
          parameters: [
            { name: 'domain', in: 'query', required: true, description: 'Domain to check. A URL or email address is reduced to its domain. IP addresses are rejected.', schema: { type: 'string', maxLength: 300 }, example: 'example.com' },
            { name: 'selector', in: 'query', required: false, description: 'Your DKIM selector (s= value). Letters, digits, "-", "_" and up to 3 dots.', schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{1,63}(\\.[A-Za-z0-9_-]{1,63}){0,3}$' } },
          ],
          responses: {
            200: { description: 'Check result', headers: tierHeaders, content: { 'application/json': { schema: { $ref: '#/components/schemas/CheckResult' } } } },
            400: errResp('`invalid_domain` or `invalid_selector`'),
            401: errResp('`invalid_api_key`: a key was sent but is unknown, revoked or expired'),
            405: errResp('`method_not_allowed`: use GET'),
            422: errResp('`domain_not_found`: the domain does not exist (NXDOMAIN)'),
            429: errResp('`rate_limited` (per-minute), `daily_quota_exceeded` (your key\'s daily cap) or `daily_capacity_reached` (shared free daily allowance)', { ...retryAfter, 'x-dnsguard-tier': tierHeaders['x-dnsguard-tier'] }),
            500: errResp('`internal_error`'),
            502: errResp('`dns_unavailable`: upstream DNS-over-HTTPS resolvers failed'),
            503: errResp('`storage_unavailable` (Retry-After: 3600), `keys_unavailable` or `free_api_disabled`', retryAfter),
            504: errResp('`timeout`: the check took longer than 9 s'),
          },
        },
      },
      '/api/health': {
        get: {
          tags: ['meta'], operationId: 'health', summary: 'Liveness and deployed version', security: [{}],
          responses: { 200: { description: 'OK', content: { 'application/json': { schema: { type: 'object', required: ['ok', 'version'], properties: { ok: { const: true }, version: { type: 'string', examples: [VERSION] } } } } } } },
        },
      },
      '/api/auth/status': {
        get: {
          tags: ['meta'], operationId: 'authStatus', summary: 'Current limits and sign-in / Pro availability', security: [{}],
          responses: {
            200: {
              description: 'Status',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      google: { type: 'boolean', description: 'Google sign-in (free key minting) is configured' },
                      freeApi: { type: 'boolean' },
                      limits: {
                        type: 'object',
                        properties: {
                          anonymousPerMin: { type: 'integer' }, freePerMin: { type: 'integer' }, freePerDay: { type: 'integer' },
                          proPerMin: { type: 'integer' }, proPerDay: { type: 'integer' },
                          sharedChecksPerDay: { type: 'integer' }, sharedAnonymousChecksPerDay: { type: 'integer' },
                        },
                      },
                      proCheckout: { type: 'boolean' },
                      proCheckoutUrl: { type: 'string', format: 'uri' },
                      dailyCounter: { type: 'string', enum: ['durable_object', 'unavailable'] },
                    },
                  },
                },
              },
            },
            405: errResp('`method_not_allowed`'),
          },
        },
      },
      '/mcp': {
        post: {
          tags: ['mcp'],
          operationId: 'mcp',
          summary: 'Remote MCP server (Streamable HTTP, JSON-RPC 2.0)',
          description: `Model Context Protocol endpoint. Stateless, JSON responses only (no SSE, no Mcp-Session-Id). Supported protocol versions: ${SUPPORTED_VERSIONS.join(', ')}. Modern (2026-07-28) requests carry params._meta and the MCP-Protocol-Version, Mcp-Method and Mcp-Name headers; legacy clients use initialize. Tool: check_domain. Same keys and limits as /api/check; each tools/call counts as one check. Body max ${MAX_BODY_BYTES} bytes; legacy batches max ${MAX_BATCH} messages with at most one tools/call.`,
          security: [{}, { bearerAuth: [] }, { apiKeyHeader: [] }],
          parameters: [
            { name: 'MCP-Protocol-Version', in: 'header', required: false, schema: { type: 'string', enum: SUPPORTED_VERSIONS } },
            { name: 'Mcp-Method', in: 'header', required: false, description: 'Required for 2026-07-28; must equal the body method', schema: { type: 'string' } },
            { name: 'Mcp-Name', in: 'header', required: false, description: 'Required for 2026-07-28 tools/call; must equal params.name', schema: { type: 'string' } },
          ],
          requestBody: {
            required: true,
            content: { 'application/json': { schema: { oneOf: [{ $ref: '#/components/schemas/JsonRpcMessage' }, { type: 'array', maxItems: MAX_BATCH, items: { $ref: '#/components/schemas/JsonRpcMessage' } }] } } },
          },
          responses: {
            200: { description: 'JSON-RPC response (or batch of responses). Tool failures, including rate limits, are results with isError: true.', content: { 'application/json': { schema: { type: ['object', 'array'] } } } },
            202: { description: 'Notification(s) accepted; no body' },
            400: { description: 'Parse error (-32700), invalid request (-32600), header mismatch (-32020), unsupported protocol version (-32022) or missing _meta (-32602)', content: { 'application/json': { schema: { type: 'object' } } } },
            401: { description: 'Invalid API key (JSON-RPC error, data.code = invalid_api_key)', content: { 'application/json': { schema: { type: 'object' } } } },
            403: { description: 'Origin header present but not allowed', content: { 'application/json': { schema: { type: 'object' } } } },
            404: { description: 'Unknown method in a 2026-07-28 request (-32601)', content: { 'application/json': { schema: { type: 'object' } } } },
            413: { description: 'Body larger than the cap', content: { 'application/json': { schema: { type: 'object' } } } },
            429: { description: 'Too many non-check MCP messages from this IP', headers: retryAfter, content: { 'application/json': { schema: { type: 'object' } } } },
            500: errResp('Unexpected internal error (`internal_error`); per-message failures are JSON-RPC -32603 inside a 200 response instead'),
            503: { description: 'Key storage unavailable', headers: retryAfter, content: { 'application/json': { schema: { type: 'object' } } } },
          },
        },
        get: mcpNotAllowed('get'),
        delete: mcpNotAllowed('delete'),
      },
    },
  };
}
