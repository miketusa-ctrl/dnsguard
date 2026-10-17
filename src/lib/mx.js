export function parseMx(data) {
  const m = /^(\d+)\s+(\S+)$/.exec(String(data).trim());
  if (!m) return null;
  return { priority: +m[1], exchange: m[2].replace(/\.$/, '') || '.' };
}

export async function analyzeMx(domain, resolver) {
  const r = await resolver.query(domain, 'MX');
  const records = r.answers.map((a) => parseMx(a.data)).filter(Boolean).sort((a, b) => a.priority - b.priority);
  const nullMx = records.length === 1 && (records[0].exchange === '.' || records[0].exchange === '');
  return { status: r.status, records, nullMx };
}
