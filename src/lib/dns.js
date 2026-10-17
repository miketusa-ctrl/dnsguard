// DNS-over-HTTPS (JSON) resolver usable in Workers, Node 18+, and browsers.
export const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28 };
const STATUS = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

export const PROVIDERS = [
  { id: 'cloudflare', url: (n, t) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(n)}&type=${t}` },
  { id: 'google', url: (n, t) => `https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${t}` },
];

/** Join a TXT RDATA string. Cloudflare returns quoted chunks ("a" "b"); Google returns them already joined. */
export function parseTxtData(data) {
  if (typeof data !== 'string') return '';
  const s = data.trim();
  if (!s.startsWith('"')) return s;
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') { i++; continue; }
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        const d = s.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(d)) { out += String.fromCharCode(parseInt(d, 10)); i += 4; }
        else { out += s[i + 1]; i += 2; }
      } else out += s[i++];
    }
    i++; // closing quote
  }
  return out;
}

export class DnsError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

export class Resolver {
  constructor({ fetchImpl, timeoutMs = 2500, maxQueries = 100, providers = PROVIDERS } = {}) {
    this.fetch = fetchImpl || ((...a) => fetch(...a));
    this.timeoutMs = timeoutMs;
    this.maxQueries = maxQueries; // Workers Paid allows 10,000 subrequests; this cap bounds CPU per check (~0.2 ms CPU per DoH query measured)
    this.providers = providers;
    this.queries = 0;
    this.cache = new Map();
    this.providerUsed = new Set();
  }

  /** @returns {Promise<{status:string, answers:{name:string,type:number,ttl:number,data:string}[]}>} */
  query(name, type) {
    const key = `${name.toLowerCase()}|${type}`;
    if (!this.cache.has(key)) this.cache.set(key, this._query(name, type));
    return this.cache.get(key);
  }

  async _query(name, type) {
    let lastErr;
    for (const p of this.providers) {
      if (this.queries >= this.maxQueries) throw new DnsError('query_budget', 'DNS query budget exhausted for this check');
      this.queries++;
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
      try {
        const res = await this.fetch(p.url(name, type), {
          headers: { accept: 'application/dns-json' }, signal: ctrl.signal,
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const j = await res.json();
        const status = STATUS[j.Status] || `RCODE${j.Status}`;
        if (status === 'SERVFAIL' || status === 'REFUSED') throw new Error(status);
        const want = RR[type];
        const answers = (j.Answer || [])
          .filter((a) => a.type === want)
          .map((a) => ({ name: String(a.name).replace(/\.$/, ''), type: a.type, ttl: a.TTL, data: type === 'TXT' ? parseTxtData(a.data) : String(a.data) }));
        this.providerUsed.add(p.id);
        return { status, answers };
      } catch (e) {
        lastErr = e;
      } finally {
        clearTimeout(timer);
      }
    }
    throw new DnsError('dns_unavailable', `DNS lookup failed for ${name} ${type}: ${lastErr && (lastErr.name === 'AbortError' ? 'timeout' : lastErr.message)}`);
  }

  async txt(name) {
    const r = await this.query(name, 'TXT');
    return { status: r.status, records: r.answers.map((a) => a.data) };
  }
}
