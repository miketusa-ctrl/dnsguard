// DKIM (RFC 6376) selector probing and public-key size estimation.
export const COMMON_SELECTORS = [
  'google', 'selector1', 'selector2', 'default', 'k1', 'k2', 'k3', 's1', 's2', 'mail', 'dkim',
  'mandrill', 'smtp', 'everlytic', 'zoho', 'zmail', 'fm1', 'fm2', 'protonmail', 'mxvault', 'krs', 'cm',
  // Dated selectors used by Google's own domains (Workspace customer domains normally use "google").
  '20230601', '20221208', '20210112',
];

// Provider-specific selectors, probed only when the domain's MX hosts or its top-level SPF record
// point at that provider. Keeps the common list (and the per-check CPU cost) small while still
// finding keys for popular senders. Matching is on hostname suffixes, e.g. "include:sendgrid.net".
export const PROVIDER_SELECTORS = [
  { provider: 'Microsoft 365', hosts: ['protection.outlook.com', 'outlook.com'], selectors: ['selector1', 'selector2'] },
  { provider: 'Google Workspace', hosts: ['google.com', 'googlemail.com'], selectors: ['google'] },
  { provider: 'SendGrid', hosts: ['sendgrid.net'], selectors: ['s1', 's2', 'smtpapi'] },
  { provider: 'Mailchimp / Mandrill', hosts: ['mcsv.net', 'mandrillapp.com', 'mcdlv.net'], selectors: ['k1', 'k2', 'k3', 'mte1', 'mte2'] },
  { provider: 'Mailgun', hosts: ['mailgun.org', 'mailgun.net'], selectors: ['mx', 'pic', 'mailo', 'krs', 'smtp'] },
  { provider: 'Zendesk', hosts: ['zendesk.com'], selectors: ['zendesk1', 'zendesk2'] },
  { provider: 'Fastmail', hosts: ['messagingengine.com'], selectors: ['fm1', 'fm2', 'fm3'] },
  { provider: 'Proton Mail', hosts: ['protonmail.ch', 'proton.me'], selectors: ['protonmail', 'protonmail2', 'protonmail3'] },
  { provider: 'iCloud Mail', hosts: ['icloud.com', 'me.com'], selectors: ['sig1'] },
  { provider: 'Brevo (Sendinblue)', hosts: ['brevo.com', 'sendinblue.com'], selectors: ['mail', 'brevo1', 'brevo2'] },
  { provider: 'Mailjet', hosts: ['mailjet.com'], selectors: ['mailjet'] },
  { provider: 'Constant Contact', hosts: ['constantcontact.com'], selectors: ['ctct1', 'ctct2'] },
  { provider: 'MailerLite', hosts: ['mlsend.com', 'mailerlite.com'], selectors: ['ml', 'litesrv'] },
  { provider: 'Yahoo', hosts: ['yahoodns.net'], selectors: ['s1024', 's2048'] },
  { provider: 'Zoho Mail', hosts: ['zoho.com', 'zoho.eu', 'zohomail.com'], selectors: ['zoho', 'zmail'] },
];
// Upper bound on extra probes from provider hints, so a record that names many providers can't blow up a check.
export const MAX_HINTED_SELECTORS = 15;

function hostMatches(host, suffix) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  return h === suffix || h.endsWith(`.${suffix}`);
}

/**
 * Provider-specific DKIM selectors to add for a domain, from its MX exchanges and the include:/redirect=
 * targets of its top-level SPF record (no extra DNS queries: both are already fetched).
 * @returns {{selectors: string[], providers: string[]}}
 */
export function hintedSelectors({ mxHosts = [], spfRecord = null } = {}) {
  const hosts = [...mxHosts];
  if (spfRecord) {
    for (const t of String(spfRecord).split(/\s+/)) {
      const m = /^[+~?-]?(?:include:|redirect=)(.+)$/i.exec(t);
      if (m) hosts.push(m[1]);
    }
  }
  const selectors = [];
  const providers = [];
  for (const p of PROVIDER_SELECTORS) {
    if (!hosts.some((h) => p.hosts.some((sfx) => hostMatches(h, sfx)))) continue;
    providers.push(p.provider);
    for (const s of p.selectors) if (!COMMON_SELECTORS.includes(s) && !selectors.includes(s)) selectors.push(s);
  }
  return { selectors: selectors.slice(0, MAX_HINTED_SELECTORS), providers };
}

export function parseDkimTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).replace(/\s+/g, '');
  }
  return tags;
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function readLen(b, i) {
  let l = b[i++];
  if (l & 0x80) {
    const n = l & 0x7f;
    if (n > 4) throw new Error('bad length');
    l = 0;
    for (let k = 0; k < n; k++) l = l * 256 + b[i++];
  }
  return [l, i];
}

/** RSA modulus size in bits from base64 SubjectPublicKeyInfo or PKCS#1 RSAPublicKey; null if unparseable. */
export function rsaKeyBits(b64) {
  try {
    const b = b64ToBytes(b64);
    let i = 0;
    let l;
    if (b[i++] !== 0x30) return null;
    [l, i] = readLen(b, i);
    if (b[i] === 0x30) { // SPKI: AlgorithmIdentifier, then BIT STRING wrapping RSAPublicKey
      i++;
      [l, i] = readLen(b, i);
      i += l;
      if (b[i++] !== 0x03) return null;
      [l, i] = readLen(b, i);
      i++; // unused-bits byte
      if (b[i++] !== 0x30) return null;
      [l, i] = readLen(b, i);
    }
    if (b[i++] !== 0x02) return null;
    [l, i] = readLen(b, i);
    while (l > 0 && b[i] === 0) { i++; l--; }
    if (l <= 0 || i >= b.length) return null;
    let bits = l * 8;
    let top = b[i];
    while (top < 0x80) { bits--; top <<= 1; }
    return bits;
  } catch { return null; }
}

/** Analyze one DKIM TXT record. */
export function analyzeDkimRecord(record) {
  const tags = parseDkimTags(record);
  const errors = [];
  const warnings = [];
  if (tags.v !== undefined && tags.v !== 'DKIM1') errors.push(`Unexpected version v=${tags.v}.`);
  const keyType = (tags.k || 'rsa').toLowerCase();
  let keyBits = null;
  const revoked = tags.p === '';
  if (tags.p === undefined) errors.push('Missing public key (p= tag).');
  else if (revoked) warnings.push('Key is revoked (empty p=).');
  else if (keyType === 'rsa') {
    keyBits = rsaKeyBits(tags.p);
    if (keyBits === null) errors.push('Public key could not be decoded.');
    else if (keyBits < 1024) errors.push(`RSA key is only ${keyBits} bits; receivers may reject keys under 1024 bits. Use 2048.`);
    else if (keyBits < 2048) warnings.push(`RSA key is ${keyBits} bits; 2048-bit keys are recommended.`);
  } else if (keyType === 'ed25519') keyBits = 256;
  else warnings.push(`Unknown key type k=${keyType}.`);
  const testing = (tags.t || '').split(':').includes('y');
  if (testing) warnings.push('Testing mode (t=y) is set; receivers may treat signatures as unsigned.');
  return { keyType, keyBits, revoked, testing, errors, warnings, valid: errors.length === 0 && !revoked };
}

export function isDkimRecord(txt) { return /(^|;)\s*(v\s*=\s*DKIM1|p\s*=)/i.test(txt); }

export async function analyzeDkim(domain, resolver, extraSelector, hints = {}) {
  const hinted = hintedSelectors(hints);
  const selectors = [...new Set([...(extraSelector ? [extraSelector] : []), ...COMMON_SELECTORS, ...hinted.selectors])];
  const found = [];
  const errors = [];
  await Promise.all(selectors.map(async (sel) => {
    const name = `${sel}._domainkey.${domain}`;
    try {
      const tx = await resolver.txt(name);
      const recs = tx.records.filter(isDkimRecord);
      if (!recs.length) return;
      const rec = recs.join('');
      found.push({ selector: sel, name, record: rec.length > 600 ? `${rec.slice(0, 600)}…` : rec, ...analyzeDkimRecord(rec) });
    } catch (e) { errors.push(`${sel}: ${e.message}`); }
  }));
  found.sort((a, b) => selectors.indexOf(a.selector) - selectors.indexOf(b.selector));
  return { domain, selectorsChecked: selectors, userSelector: extraSelector || null, providerHints: hinted.providers, found, lookupErrors: errors };
}
