import { Resolver, DnsError } from './dns.js';
import { orgDomain } from './domain.js';
import { analyzeSpf } from './spf.js';
import { analyzeDmarc } from './dmarc.js';
import { analyzeDkim } from './dkim.js';
import { analyzeBimi } from './bimi.js';
import { analyzeMx } from './mx.js';
import { analyzeMtaSts } from './mtasts.js';
import { analyzeTlsRpt } from './tlsrpt.js';
import { scoreMx, scoreSpf, scoreDmarc, scoreDkim, scoreBimi, scoreMtaSts, scoreTlsRpt, effectiveDmarcPolicy, grade, BONUS, SCORE_CAP } from './score.js';

export const VERSION = '0.9.0';

export class CheckError extends Error {
  constructor(code, message, httpStatus) { super(message); this.code = code; this.httpStatus = httpStatus; }
}

/** Run every check for an already-normalized domain. */
export async function checkDomain(domain, { selector, resolver, fetchImpl, policyTimeoutMs, now = () => new Date() } = {}) {
  const t0 = Date.now();
  const r = resolver || new Resolver();
  const org = orgDomain(domain);
  let mx;
  let rootTxt;
  try {
    [mx, rootTxt] = await Promise.all([analyzeMx(domain, r), r.txt(domain)]);
  } catch (e) {
    throw new CheckError('dns_unavailable', `Could not reach DNS resolvers: ${e.message}`, 502);
  }
  if (mx.status === 'NXDOMAIN' && rootTxt.status === 'NXDOMAIN') {
    throw new CheckError('domain_not_found', `${domain} does not exist in DNS (NXDOMAIN).`, 422);
  }
  let spf; let dmarc; let dkim; let bimi; let mtaSts; let tlsRpt;
  const mxHosts = mx.records.map((x) => x.exchange);
  try {
    [spf, dmarc, dkim, bimi, mtaSts, tlsRpt] = await Promise.all([
      analyzeSpf(domain, r, rootTxt),
      analyzeDmarc(domain, org, r),
      analyzeDkim(domain, r, selector, {
        mxHosts,
        spfRecord: rootTxt.records.find((t) => /^v=spf1(\s|$)/i.test(t.trim())) || null,
      }),
      analyzeBimi(domain, org, r),
      // v0.6.0 transport security. DNS errors here degrade to an info finding instead of failing the check.
      analyzeMtaSts(domain, r, { mxHosts, nullMx: mx.nullMx, fetchImpl: fetchImpl || r.fetch, timeoutMs: policyTimeoutMs }),
      analyzeTlsRpt(domain, r),
    ]);
  } catch (e) {
    if (e instanceof DnsError) throw new CheckError('dns_unavailable', e.message, 502);
    throw e;
  }
  const policy = effectiveDmarcPolicy(dmarc);
  // A domain that declares it never sends or receives mail (null MX + "v=spf1 -all") doesn't need DKIM/BIMI.
  const nonSending = mx.nullMx && spf.records.length === 1 && spf.parsed && spf.parsed.errors.length === 0
    && spf.parsed.mechanisms.length === 1 && spf.parsed.all && spf.parsed.all.qualifier === '-';
  const na = (max, msg) => ({ status: 'info', score: max, maxScore: max, notApplicable: true, findings: [{ level: 'info', message: msg }], recommendations: [] });
  const checks = {
    mx: { ...scoreMx(mx, spf), records: mx.records, nullMx: mx.nullMx },
    spf: { ...scoreSpf(spf), record: spf.record, records: spf.records, lookupCount: spf.lookupCount, lookupLimit: spf.lookupLimit, voidLookups: spf.voidLookups, includes: spf.tree ? spf.tree.children : [] },
    dmarc: { ...scoreDmarc(dmarc), record: dmarc.record, lookedUp: dmarc.lookedUp, inherited: dmarc.inherited, policy, tags: dmarc.parsed ? dmarc.parsed.tags : null, pct: dmarc.parsed ? dmarc.parsed.pct : null, subdomainPolicy: dmarc.parsed ? dmarc.parsed.subdomainPolicy : null, alignment: dmarc.parsed ? { dkim: dmarc.parsed.adkim, spf: dmarc.parsed.aspf } : null, rua: dmarc.parsed ? dmarc.parsed.rua : [], ruf: dmarc.parsed ? dmarc.parsed.ruf : [] },
    dkim: { ...(nonSending ? { ...na(25, 'This domain declares it sends no email (null MX and "v=spf1 -all"), so DKIM is not required.'), verified: true } : scoreDkim(dkim)), selectorsChecked: dkim.selectorsChecked, userSelector: dkim.userSelector, providerHints: dkim.providerHints, keys: dkim.found.map(({ selector: s, name, keyType, keyBits, revoked, testing, valid, record }) => ({ selector: s, name, keyType, keyBits, revoked, testing, valid, record })) },
    bimi: { ...(nonSending ? na(10, 'Not applicable: this domain sends no email.') : scoreBimi(bimi, policy)), record: bimi.record, lookedUp: bimi.lookedUp, logoUrl: bimi.parsed ? bimi.parsed.logoUrl : null, vmcUrl: bimi.parsed ? bimi.parsed.vmcUrl : null },
    mtaSts: {
      ...scoreMtaSts(mtaSts), record: mtaSts.record, lookedUp: mtaSts.lookedUp, id: mtaSts.parsed ? mtaSts.parsed.id : null,
      policyUrl: mtaSts.found ? mtaSts.policyUrl : null,
      policyFetch: mtaSts.policyFetch ? { ok: mtaSts.policyFetch.ok, httpStatus: mtaSts.policyFetch.status ?? null, error: mtaSts.policyFetch.error || null } : null,
      mode: mtaSts.policy && !mtaSts.policy.errors.length ? mtaSts.policy.mode : null,
      mxPatterns: mtaSts.policy ? mtaSts.policy.mx : [],
      maxAge: mtaSts.policy ? mtaSts.policy.maxAge : null,
      mxCoverage: mtaSts.coverage,
    },
    tlsRpt: { ...scoreTlsRpt(tlsRpt, { nullMx: mx.nullMx }), record: tlsRpt.record, lookedUp: tlsRpt.lookedUp, rua: tlsRpt.parsed ? tlsRpt.parsed.rua : [] },
  };
  // Core checks (MX, SPF, DMARC, DKIM, BIMI) add up to 100. MTA-STS + TLS-RPT are bonus points (max 5), total capped at 100.
  // v0.6.1: bonus only when SPF does not fail and DMARC is enforced (quarantine/reject).
  const base = Object.values(checks).filter((c) => !c.bonus).reduce((s, c) => s + c.score, 0);
  const bonusEligible = checks.spf.status !== 'fail' && (policy === 'quarantine' || policy === 'reject');
  const bonusRaw = Object.values(checks).filter((c) => c.bonus).reduce((s, c) => s + c.score, 0);
  const bonus = bonusEligible ? bonusRaw : 0;
  const score = Math.min(SCORE_CAP, base + bonus);
  const notes = [];
  if (!bonusEligible && bonusRaw) notes.push('Transport-security bonus not applied until SPF passes and DMARC is enforced (p=quarantine or p=reject).');
  if (nonSending) notes.push('Non-sending domain detected (null MX + "v=spf1 -all"): DKIM and BIMI are scored as not applicable.');
  if (!checks.dkim.verified) notes.push('No active DKIM key was found at the selectors checked (common ones plus any for mail providers detected in MX/SPF), so the score may understate your setup. Re-check with ?selector=<your-selector>.');
  return {
    domain,
    organizationalDomain: org,
    nonSending,
    checkedAt: now().toISOString(),
    score,
    maxScore: SCORE_CAP,
    scoreBreakdown: { base, bonus, bonusMax: BONUS.mtaSts + BONUS.tlsRpt, cap: SCORE_CAP },
    grade: grade(score),
    notes,
    checks,
    meta: { version: VERSION, dnsQueries: r.queries, resolvers: [...r.providerUsed], durationMs: Date.now() - t0 },
  };
}
