// DMARC (RFC 7489) parsing.
export function isDmarc(txt) { return /^v\s*=\s*DMARC1\s*(;|$)/i.test(txt.trim()); }

export function parseDmarc(record) {
  const errors = [];
  const warnings = [];
  const tags = {};
  const parts = record.split(';').map((p) => p.trim()).filter(Boolean);
  parts.forEach((p, i) => {
    const eq = p.indexOf('=');
    if (eq < 0) { errors.push(`Malformed tag "${p}" (expected key=value).`); return; }
    const k = p.slice(0, eq).trim().toLowerCase();
    const v = p.slice(eq + 1).trim();
    if (i === 0 && (k !== 'v' || v !== 'DMARC1')) errors.push('Record must start with "v=DMARC1".');
    if (tags[k] !== undefined) warnings.push(`Tag "${k}" appears more than once.`);
    tags[k] = v;
  });
  const pol = ['none', 'quarantine', 'reject'];
  const policy = tags.p ? tags.p.toLowerCase() : null;
  if (!policy) {
    if (tags.rua) warnings.push('Missing required "p=" tag; receivers will treat the policy as p=none.');
    else errors.push('Missing required "p=" policy tag.');
  } else if (!pol.includes(policy)) errors.push(`Invalid policy p=${tags.p}.`);
  const sp = tags.sp ? tags.sp.toLowerCase() : null;
  if (sp && !pol.includes(sp)) errors.push(`Invalid subdomain policy sp=${tags.sp}.`);
  let pct = 100;
  if (tags.pct !== undefined) {
    if (!/^\d{1,3}$/.test(tags.pct) || +tags.pct > 100) errors.push(`Invalid pct=${tags.pct} (must be 0-100).`);
    else pct = +tags.pct;
  }
  for (const k of ['adkim', 'aspf']) {
    if (tags[k] !== undefined && !/^[rs]$/i.test(tags[k])) errors.push(`Invalid ${k}=${tags[k]} (must be r or s).`);
  }
  const uris = (v) => (v ? v.split(',').map((u) => u.trim()).filter(Boolean) : []);
  const rua = uris(tags.rua);
  const ruf = uris(tags.ruf);
  for (const u of [...rua, ...ruf]) {
    if (!/^mailto:[^@\s]+@[^@\s]+\.[^@\s!]+(![0-9]+[kmgt]?)?$/i.test(u)) errors.push(`Invalid report URI "${u}" (expected mailto:address).`);
  }
  return {
    record, tags, errors, warnings,
    policy: policy && pol.includes(policy) ? policy : (tags.rua && !policy ? 'none' : null),
    subdomainPolicy: sp && pol.includes(sp) ? sp : null,
    pct,
    adkim: (tags.adkim || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
    aspf: (tags.aspf || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
    rua, ruf,
  };
}

export async function analyzeDmarc(domain, org, resolver) {
  const out = { found: false, record: null, records: [], parsed: null, inherited: false, lookedUp: `_dmarc.${domain}`, errors: [], warnings: [] };
  let tx = await resolver.txt(`_dmarc.${domain}`);
  let recs = tx.records.filter(isDmarc);
  if (recs.length === 0 && org !== domain) {
    tx = await resolver.txt(`_dmarc.${org}`);
    recs = tx.records.filter(isDmarc);
    if (recs.length) { out.inherited = true; out.lookedUp = `_dmarc.${org}`; }
  }
  out.records = recs;
  if (!recs.length) return out;
  out.found = true;
  if (recs.length > 1) out.errors.push(`Found ${recs.length} DMARC records; receivers ignore DMARC when more than one is published.`);
  out.record = recs[0];
  out.parsed = parseDmarc(recs[0]);
  out.errors.push(...out.parsed.errors);
  out.warnings.push(...out.parsed.warnings);
  return out;
}
