// BIMI (draft-brand-indicators-for-message-identification) parsing.
export function isBimi(txt) { return /^v\s*=\s*BIMI1\s*(;|$)/i.test(txt.trim()); }

export function parseBimi(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const errors = [];
  const warnings = [];
  const logo = tags.l || '';
  const vmc = tags.a || '';
  if (tags.l === undefined) errors.push('Missing logo location (l= tag).');
  else if (logo === '') warnings.push('Empty l= tag: this record explicitly declines to show a logo.');
  else {
    if (!/^https:\/\//i.test(logo)) errors.push('Logo URL (l=) must use https://.');
    if (!/\.svg(\?|#|$)/i.test(logo)) warnings.push('Logo URL does not end in .svg; BIMI requires an SVG Tiny PS file.');
  }
  if (vmc && !/^https:\/\//i.test(vmc)) errors.push('Certificate URL (a=) must use https://.');
  if (!vmc) warnings.push('No a= certificate (VMC/CMC). Gmail and Apple Mail require a Verified Mark Certificate or Common Mark Certificate to display the logo.');
  return { record, tags, logoUrl: logo || null, vmcUrl: vmc || null, errors, warnings };
}

export async function analyzeBimi(domain, org, resolver) {
  const out = { found: false, record: null, parsed: null, lookedUp: `default._bimi.${domain}`, inherited: false };
  let tx = await resolver.txt(`default._bimi.${domain}`);
  let recs = tx.records.filter(isBimi);
  if (!recs.length && org !== domain) {
    tx = await resolver.txt(`default._bimi.${org}`);
    recs = tx.records.filter(isBimi);
    if (recs.length) { out.inherited = true; out.lookedUp = `default._bimi.${org}`; }
  }
  if (!recs.length) return out;
  out.found = true;
  out.record = recs[0];
  out.parsed = parseBimi(recs[0]);
  if (recs.length > 1) out.parsed.errors.push('More than one BIMI record published at this name.');
  return out;
}
