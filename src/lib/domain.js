// Input validation + organizational-domain heuristic.
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;

/** Normalize user input (URL, email, trailing dot, IDN) to an ASCII hostname, or throw. */
export function normalizeDomain(input) {
  if (typeof input !== 'string') throw new Error('domain is required');
  let s = input.trim().toLowerCase();
  if (!s) throw new Error('domain is required');
  if (s.length > 300) throw new Error('domain is too long');
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  s = s.split(/[/?#]/)[0];
  s = s.replace(/:\d+$/, '').replace(/\.$/, '');
  let host;
  try { host = new URL(`http://${s}/`).hostname; } catch { throw new Error('not a valid domain name'); }
  host = host.replace(/\.$/, '');
  if (/^[\d.]+$/.test(host) || host.includes(':') || host.startsWith('[')) throw new Error('IP addresses are not supported; enter a domain name');
  if (host.length > 253) throw new Error('domain is too long');
  const labels = host.split('.');
  if (labels.length < 2) throw new Error('enter a full domain such as example.com');
  if (!labels.every((l) => LABEL.test(l))) throw new Error('not a valid domain name');
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) throw new Error('not a valid top-level domain');
  return host;
}

// Small list of common multi-label public suffixes. Not a full Public Suffix List (see NOTES limitations).
const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'co.za', 'org.za', 'com.br', 'net.br', 'org.br',
  'com.mx', 'org.mx', 'co.in', 'net.in', 'org.in', 'com.cn', 'net.cn', 'org.cn',
  'com.sg', 'com.tr', 'com.hk', 'com.tw', 'co.kr', 'or.kr', 'com.ar', 'com.co', 'co.il',
  'com.my', 'com.ph', 'com.vn', 'co.id', 'com.pk', 'com.ng', 'com.eg', 'com.sa', 'co.th',
]);

export function orgDomain(host) {
  const l = host.split('.');
  if (l.length <= 2) return host;
  const last2 = l.slice(-2).join('.');
  if (MULTI_SUFFIXES.has(last2)) return l.slice(-3).join('.');
  return last2;
}
