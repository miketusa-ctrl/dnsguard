// SPF (RFC 7208) parsing and recursive DNS-lookup counting.
export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;
const MECHS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists']);
const LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const QUAL = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

export function isSpf(txt) { return /^v=spf1(\s|$)/i.test(txt.trim()); }

function validIp4(v) {
  const [ip, cidr, extra] = v.split('/');
  if (extra !== undefined) return false;
  const parts = ip.split('.');
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && +p <= 255)) return false;
  return cidr === undefined || (/^\d{1,2}$/.test(cidr) && +cidr <= 32);
}
function validIp6(v) {
  const i = v.lastIndexOf('/');
  const ip = i >= 0 ? v.slice(0, i) : v;
  const cidr = i >= 0 ? v.slice(i + 1) : undefined;
  if (!/^[0-9a-f:.]+$/i.test(ip) || !ip.includes(':')) return false;
  if ((ip.match(/::/g) || []).length > 1) return false;
  return cidr === undefined || (/^\d{1,3}$/.test(cidr) && +cidr <= 128);
}
function validDomainSpec(v) {
  if (!v) return false;
  if (v.includes('%{')) return true; // macro – can't fully validate statically
  return /^[a-z0-9_.-]+$/i.test(v) && v.includes('.') && !v.startsWith('.');
}
function validCidrSuffix(v) { return /^(\/\d{1,2})?(\/\/\d{1,3})?$/.test(v); }

/** Parse one SPF record into terms + syntax errors/warnings. Pure function. */
export function parseSpf(record) {
  const errors = [];
  const warnings = [];
  const mechanisms = [];
  const modifiers = {};
  const terms = record.trim().split(/\s+/);
  if (!terms.length || terms[0].toLowerCase() !== 'v=spf1') errors.push('Record must start with "v=spf1".');
  let allSeen = false;
  for (const raw of terms.slice(1)) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) {
      const name = mod[1].toLowerCase();
      if (name === 'redirect' || name === 'exp') {
        if (modifiers[name] !== undefined) errors.push(`Modifier "${name}=" appears more than once.`);
        if (!validDomainSpec(mod[2])) errors.push(`Modifier "${raw}" has an invalid domain.`);
      }
      modifiers[name] = mod[2];
      continue;
    }
    let q = '+';
    let body = raw;
    if ('+-~?'.includes(raw[0])) { q = raw[0]; body = raw.slice(1); }
    const m = /^([a-z0-9]+)(.*)$/i.exec(body);
    const name = m ? m[1].toLowerCase() : '';
    const rest = m ? m[2] : body;
    if (!MECHS.has(name)) { errors.push(`Unknown mechanism "${raw}".`); continue; }
    let value = null;
    let ok = true;
    if (name === 'all') ok = rest === '';
    else if (name === 'ip4' || name === 'ip6') {
      ok = rest.startsWith(':') && (name === 'ip4' ? validIp4(rest.slice(1)) : validIp6(rest.slice(1)));
      value = rest.slice(1);
    } else if (name === 'include' || name === 'exists') {
      ok = rest.startsWith(':') && validDomainSpec(rest.slice(1));
      value = rest.slice(1);
    } else { // a, mx, ptr  [:domain][/cidr][//cidr6]
      let r = rest;
      if (r.startsWith(':')) {
        const idx = r.indexOf('/');
        value = idx >= 0 ? r.slice(1, idx) : r.slice(1);
        r = idx >= 0 ? r.slice(idx) : '';
        ok = validDomainSpec(value);
      }
      if (name === 'ptr' && r) ok = false;
      if (r && !validCidrSuffix(r)) ok = false;
    }
    if (!ok) errors.push(`Invalid syntax in "${raw}".`);
    if (allSeen) warnings.push(`"${raw}" comes after "all" and will never be evaluated.`);
    if (name === 'all') allSeen = true;
    if (name === 'ptr') warnings.push('The "ptr" mechanism is deprecated (RFC 7208 §5.5); many receivers ignore it. Replace it with ip4/ip6/include.');
    mechanisms.push({ qualifier: q, result: QUAL[q], mechanism: name, value, raw });
  }
  const all = mechanisms.find((x) => x.mechanism === 'all') || null;
  if (all && modifiers.redirect !== undefined) warnings.push('"redirect=" is ignored because the record contains an "all" mechanism.');
  if (record.length > 450) warnings.push(`Record is ${record.length} characters; very long SPF records risk exceeding DNS UDP size limits.`);
  return { record, mechanisms, modifiers, all, errors, warnings };
}

/** Number of DNS lookups the record itself triggers (not recursive). */
export function directLookups(parsed) {
  let n = parsed.mechanisms.filter((m) => LOOKUP_MECHS.has(m.mechanism)).length;
  if (parsed.modifiers.redirect !== undefined && !parsed.all) n++;
  return n;
}

/**
 * Fetch and analyze SPF for a domain, recursing through include/redirect.
 * @param {string} domain
 * @param {{txt:(n:string)=>Promise<{status:string,records:string[]}>}} resolver
 * @param {{status:string,records:string[]}} [rootTxt] pre-fetched TXT for the domain
 */
export async function analyzeSpf(domain, resolver, rootTxt) {
  const txt = rootTxt || (await resolver.txt(domain));
  const spfRecords = txt.records.filter(isSpf);
  const result = { notes: [], found: spfRecords.length > 0, records: spfRecords, record: spfRecords[0] || null, parsed: null, lookupCount: 0, lookupLimit: SPF_LOOKUP_LIMIT, voidLookups: 0, tree: null, errors: [], warnings: [] };
  if (spfRecords.length === 0) return result;
  if (spfRecords.length > 1) {
    result.errors.push(`Found ${spfRecords.length} SPF records. A domain must publish exactly one; receivers return a permanent error (permerror) when there are several, which most receivers treat as a fail.`);
  }
  result.parsed = parseSpf(spfRecords[0]);
  result.errors.push(...result.parsed.errors);
  result.warnings.push(...result.parsed.warnings);

  const state = { count: 0, voids: 0, visited: new Set([domain.toLowerCase()]), stopped: false };
  async function walk(parsed, depth) {
    const node = { lookups: directLookups(parsed), children: [] };
    state.count += node.lookups;
    const targets = parsed.mechanisms.filter((m) => m.mechanism === 'include').map((m) => ({ kind: 'include', target: m.value }));
    if (parsed.modifiers.redirect !== undefined && !parsed.all) targets.push({ kind: 'redirect', target: parsed.modifiers.redirect });
    for (const t of targets) {
      const child = { kind: t.kind, domain: t.target, record: null, lookups: 0, children: [], error: null };
      node.children.push(child);
      if (t.target.includes('%{')) { child.error = 'Uses SPF macros; cannot be resolved statically.'; result.notes.push(`${t.kind} "${t.target}" uses SPF macros, which are expanded per message; lookups inside it are not counted here.`); continue; }
      if (state.count > SPF_LOOKUP_LIMIT || depth >= 10) { state.stopped = true; child.error = 'Not resolved: lookup limit already exceeded.'; continue; }
      const key = t.target.toLowerCase();
      if (state.visited.has(key)) { child.error = 'Loop detected (domain already included).'; result.errors.push(`SPF include loop via ${t.target}.`); continue; }
      state.visited.add(key);
      let tx;
      try { tx = await resolver.txt(t.target); } catch (e) { child.error = e.message; result.warnings.push(`Could not resolve ${t.target}: ${e.message}`); continue; }
      const recs = tx.records.filter(isSpf);
      if (tx.status === 'NXDOMAIN' || tx.records.length === 0) state.voids++;
      if (recs.length !== 1) {
        child.error = recs.length === 0 ? 'No SPF record at this domain.' : 'Multiple SPF records at this domain.';
        result.errors.push(`${t.kind} "${t.target}": ${child.error} Receivers treat this as a permanent error.`);
        continue;
      }
      child.record = recs[0];
      const p = parseSpf(recs[0]);
      if (p.errors.length) result.errors.push(...p.errors.map((e) => `In ${t.target}: ${e}`));
      const sub = await walk(p, depth + 1);
      child.lookups = sub.lookups;
      child.children = sub.children;
    }
    return node;
  }
  const root = await walk(result.parsed, 0);
  result.tree = { domain, record: result.record, lookups: root.lookups, children: root.children };
  result.lookupCount = state.count;
  result.lookupCountIsMinimum = state.stopped;
  result.voidLookups = state.voids;
  if (state.count > SPF_LOOKUP_LIMIT) {
    result.errors.push(`SPF needs ${state.count}${state.stopped ? '+' : ''} DNS lookups; the limit is ${SPF_LOOKUP_LIMIT}. SPF evaluation returns a permanent error (permerror), which most receivers treat as a fail.`);
  } else if (state.count >= 8) {
    result.warnings.push(`SPF uses ${state.count} of ${SPF_LOOKUP_LIMIT} allowed DNS lookups; adding another include may break it.`);
  }
  if (state.voids > SPF_VOID_LIMIT) result.warnings.push(`${state.voids} includes point to domains with no records ("void lookups"); more than ${SPF_VOID_LIMIT} can cause a permanent error.`);
  return result;
}
