// SMTP TLS Reporting (RFC 8460): TXT at _smtp._tls.<domain>, e.g. "v=TLSRPTv1; rua=mailto:tls@example.com".
import { DnsError } from './dns.js';

export function isTlsRpt(txt) { return /^v=TLSRPTv1\s*(;|$)/.test(String(txt).trim()); }

export function parseTlsRpt(record) {
  const errors = [];
  const warnings = [];
  const tags = {};
  const parts = String(record).split(';').map((p) => p.trim()).filter(Boolean);
  parts.forEach((p, i) => {
    const eq = p.indexOf('=');
    if (eq < 1) { errors.push(`Malformed field "${p.slice(0, 60)}" (expected key=value).`); return; }
    const k = p.slice(0, eq).trim();
    const v = p.slice(eq + 1).trim();
    if (i === 0 && (k !== 'v' || v !== 'TLSRPTv1')) errors.push('Record must start with "v=TLSRPTv1".');
    if (tags[k] !== undefined) warnings.push(`Field "${k}" appears more than once.`);
    else tags[k] = v;
  });
  const rua = [];
  if (tags.rua === undefined) errors.push('Missing required rua= field (where reports are sent).');
  else {
    const uris = tags.rua.split(',').map((u) => u.trim()).filter(Boolean);
    if (!uris.length) errors.push('rua= is empty.');
    for (const u of uris) {
      if (/^mailto:[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$/i.test(u)) rua.push(u);
      else if (/^https:\/\//i.test(u) && validHttps(u)) rua.push(u);
      else errors.push(`Invalid rua destination "${u.slice(0, 80)}" (expected mailto:address or https:// URL).`);
    }
  }
  return { record, tags, rua, errors, warnings };
}

function validHttps(u) {
  try { const x = new URL(u); return x.protocol === 'https:' && !!x.hostname && x.hostname.includes('.'); } catch { return false; }
}

export async function analyzeTlsRpt(domain, resolver) {
  const out = { found: false, lookedUp: `_smtp._tls.${domain}`, record: null, records: [], parsed: null, lookupError: null };
  try {
    const tx = await resolver.txt(out.lookedUp);
    out.records = tx.records.filter(isTlsRpt);
  } catch (e) {
    if (!(e instanceof DnsError)) throw e;
    out.lookupError = e.message;
    return out;
  }
  if (!out.records.length) return out;
  out.found = true;
  out.record = out.records[0];
  out.parsed = parseTlsRpt(out.record);
  if (out.records.length > 1) out.parsed.errors.push(`Found ${out.records.length} TLS-RPT records; senders ignore TLS-RPT unless exactly one is published.`);
  return out;
}
