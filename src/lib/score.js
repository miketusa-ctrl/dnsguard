import { MAX_AGE_WEAK, MAX_AGE_RECOMMENDED } from './mtasts.js';
// Turns raw analysis into per-check scores, findings and plain-English fixes.
export const WEIGHTS = { mx: 10, spf: 25, dmarc: 30, dkim: 25, bimi: 10 };
const f = (level, message) => ({ level, message }); // level: pass | info | warn | fail

function statusOf(score, max, findings) {
  if (findings.some((x) => x.level === 'fail')) return 'fail';
  if (findings.some((x) => x.level === 'warn') || score < max * 0.8) return 'warn';
  return 'pass';
}

export function scoreMx(mx, spf) {
  const findings = [];
  const recs = [];
  let score = 0;
  if (mx.nullMx) {
    score = WEIGHTS.mx;
    findings.push(f('info', 'Null MX (RFC 7505) published: this domain declares that it does not receive email.'));
    if (!spf.parsed || spf.parsed.all?.qualifier !== '-' || spf.parsed.mechanisms.length > 1) recs.push('For a domain that sends no mail, also publish "v=spf1 -all" and a DMARC record with p=reject so nobody can spoof it.');
  } else if (mx.records.length) {
    score = WEIGHTS.mx;
    findings.push(f('pass', `${mx.records.length} MX record${mx.records.length > 1 ? 's' : ''} found; mail is delivered to ${mx.records[0].exchange}.`));
    if (mx.records.length === 1) findings.push(f('info', 'Only one MX host. That is common with hosted providers; self-hosted mail should have a backup MX.'));
  } else {
    findings.push(f('warn', 'No MX records: this domain cannot receive email (senders may fall back to the A record).'));
    recs.push('If the domain receives mail, add MX records from your email provider. If it never sends or receives mail, publish a null MX ("0 .") plus "v=spf1 -all" to block spoofing.');
  }
  return { status: statusOf(score, WEIGHTS.mx, findings), score, maxScore: WEIGHTS.mx, findings, recommendations: recs };
}

export function scoreSpf(spf) {
  const findings = [];
  const recs = [];
  const max = WEIGHTS.spf;
  if (!spf.found) {
    findings.push(f('fail', 'No SPF record found.'));
    recs.push('Publish one TXT record at the domain root listing your senders, e.g. "v=spf1 include:_spf.google.com -all" (use your provider\'s include).');
    return { status: 'fail', score: 0, maxScore: max, findings, recommendations: recs };
  }
  let score = 10;
  const p = spf.parsed;
  const multiple = spf.records.length > 1;
  const tooMany = spf.lookupCount > spf.lookupLimit;
  const all = p.all;
  if (all) {
    const q = all.qualifier;
    if (q === '-') { score += 10; findings.push(f('pass', 'Ends with "-all": unlisted senders hard-fail.')); }
    else if (q === '~') { score += 8; findings.push(f('pass', 'Ends with "~all" (softfail). Fine alongside an enforced DMARC policy; "-all" is stricter.')); }
    else if (q === '?') { score += 2; findings.push(f('warn', '"?all" (neutral) gives no protection against spoofing.')); recs.push('Change "?all" to "~all" or "-all" once all legitimate senders are listed.'); }
    else { findings.push(f('fail', '"+all" lets ANY server on the internet send mail as this domain.')); recs.push('Replace "+all" with "-all" (or "~all") immediately.'); }
  } else if (p.modifiers.redirect !== undefined) {
    score += 8;
    findings.push(f('info', `Policy delegated via redirect=${p.modifiers.redirect}.`));
  } else {
    score += 2;
    findings.push(f('warn', 'No "all" mechanism: unlisted senders get a neutral result.'));
    recs.push('End the record with "~all" or "-all".');
  }
  if (!tooMany) score += 5;
  findings.push(f(tooMany ? 'fail' : spf.lookupCount >= 8 ? 'warn' : 'pass', `${spf.lookupCount}${spf.lookupCountIsMinimum ? '+' : ''} of ${spf.lookupLimit} DNS lookups used.`));
  if (tooMany) recs.push('Reduce DNS lookups to 10 or fewer: remove unused includes, replace "a"/"mx" with ip4/ip6 ranges, or flatten includes for senders with static IPs.');
  for (const e of spf.errors) if (!/DNS lookups; the limit/.test(e)) findings.push(f('fail', e));
  for (const w of spf.warnings) if (!/allowed DNS lookups/.test(w)) findings.push(f('warn', w));
  for (const n of spf.notes || []) findings.push(f('info', n));
  if (multiple) recs.push('Merge all SPF records into a single "v=spf1 …" TXT record.');
  const syntaxErrors = spf.errors.filter((e) => !/DNS lookups; the limit/.test(e)).length;
  if (syntaxErrors && !multiple) recs.push('Fix the SPF errors listed above; any of them makes SPF return a permanent error (permerror), which most receivers treat as a fail.');
  if (multiple || tooMany || syntaxErrors) score = Math.min(score, 5);
  if (all && all.qualifier === '+') score = 0;
  return { status: statusOf(score, max, findings), score, maxScore: max, findings, recommendations: recs };
}

export function effectiveDmarcPolicy(dmarc) {
  if (!dmarc.parsed) return null;
  if (dmarc.inherited) return dmarc.parsed.subdomainPolicy || dmarc.parsed.policy;
  return dmarc.parsed.policy;
}

export function scoreDmarc(dmarc) {
  const findings = [];
  const recs = [];
  const max = WEIGHTS.dmarc;
  if (!dmarc.found) {
    findings.push(f('fail', `No DMARC record at ${dmarc.lookedUp}.`));
    recs.push('Publish a TXT record at _dmarc.<your-domain>, starting with monitoring: "v=DMARC1; p=none; rua=mailto:dmarc@<your-domain>". Move to p=quarantine, then p=reject, once reports show legitimate mail passes.');
    return { status: 'fail', score: 0, maxScore: max, findings, recommendations: recs };
  }
  const p = dmarc.parsed;
  if (dmarc.inherited) findings.push(f('info', `No record on this subdomain; the organizational domain's record (${dmarc.lookedUp}) applies.`));
  const pol = effectiveDmarcPolicy(dmarc);
  let score = 0;
  if (pol === 'reject') { score = 22; findings.push(f('pass', 'Policy p=reject: spoofed mail is rejected.')); }
  else if (pol === 'quarantine') { score = 18; findings.push(f('pass', 'Policy p=quarantine: spoofed mail goes to spam.')); recs.push('When reports look clean, move to p=reject for full protection.'); }
  else if (pol === 'none') { score = 7; findings.push(f('warn', 'Policy p=none only monitors; spoofed mail is still delivered.')); recs.push('After reviewing aggregate reports, change to p=quarantine and later p=reject.'); }
  else findings.push(f('fail', 'No valid policy (p=) tag.'));
  if (pol && pol !== 'none') {
    if (p.pct === 100) score += 3;
    else { findings.push(f('warn', `pct=${p.pct}: the policy applies to only ${p.pct}% of failing mail.`)); recs.push('Remove pct= (defaults to 100) once you are confident.'); }
  }
  if (p.rua.length) { score += 5; findings.push(f('pass', `Aggregate reports (rua) go to ${p.rua.join(', ')}.`)); }
  else { findings.push(f('warn', 'No rua= address, so you receive no reports about who sends as your domain.')); recs.push('Add rua=mailto:<address> to receive daily aggregate reports.'); }
  if (p.ruf.length) findings.push(f('info', `Forensic reports (ruf) requested to ${p.ruf.join(', ')}; few receivers send these.`));
  const order = { none: 0, quarantine: 1, reject: 2 };
  if (!dmarc.inherited && p.subdomainPolicy && p.policy && order[p.subdomainPolicy] < order[p.policy]) {
    findings.push(f('warn', `Subdomain policy sp=${p.subdomainPolicy} is weaker than p=${p.policy}; subdomains can be spoofed more easily.`));
    recs.push(`Consider sp=${p.policy} (or remove sp=) unless subdomains are still being onboarded.`);
    score -= 2;
  }
  findings.push(f('info', `Alignment: DKIM ${p.adkim}, SPF ${p.aspf}.`));
  for (const e of dmarc.errors) findings.push(f('fail', e));
  for (const w of dmarc.warnings) findings.push(f('warn', w));
  if (dmarc.errors.length) { score = Math.min(score, 3); recs.push('Fix the DMARC syntax errors listed above; receivers may ignore an invalid record.'); }
  score = Math.max(0, Math.min(max, score));
  return { status: statusOf(score, max, findings), score, maxScore: max, findings, recommendations: recs };
}

export function scoreDkim(dkim) {
  const findings = [];
  const recs = [];
  const max = WEIGHTS.dkim;
  const valid = dkim.found.filter((k) => k.valid);
  const revoked = dkim.found.filter((k) => k.revoked);
  const broken = dkim.found.filter((k) => !k.valid && !k.revoked);
  for (const k of revoked) if (k.selector !== dkim.userSelector) findings.push(f('info', `Selector "${k.selector}": revoked key (empty p=). This is normal for retired keys after rotation.`));
  // A selector the user typed must always get an explicit finding when it isn't usable.
  if (dkim.userSelector) {
    const mine = dkim.found.find((k) => k.selector === dkim.userSelector);
    const name = `${dkim.userSelector}._domainkey.${dkim.domain}`;
    if (!mine) {
      const lookupFailed = (dkim.lookupErrors || []).some((e) => e.startsWith(`${dkim.userSelector}:`));
      findings.push(f('warn', lookupFailed
        ? `Could not look up ${name} (DNS error). Please retry.`
        : `No DKIM key at ${name}. Check the s= value in a DKIM-Signature header.`));
    } else if (mine.revoked) {
      findings.push(f('warn', `The DKIM key at ${name} is revoked (empty p=), so it can't verify signatures. Check the s= value in a recent DKIM-Signature header.`));
    }
  }
  if (!valid.length && !broken.length) {
    findings.push(f('warn', `No active DKIM key found at the ${dkim.selectorsChecked.length} selectors checked (common ones plus any for mail providers detected in MX/SPF). DKIM selectors cannot be listed via DNS, so a key may still exist under another name.`));
    recs.push('Find your selector in the DKIM-Signature header (s=) of a message you sent and re-run the check with it. If you have no key, enable DKIM signing at your email provider and publish the TXT record it gives you.');
    return { status: 'warn', score: 0, maxScore: max, findings, recommendations: recs, verified: false };
  }
  let score = valid.length ? 20 : 5;
  for (const k of [...valid, ...broken]) {
    const size = k.keyBits ? `${k.keyType.toUpperCase()} ${k.keyBits}-bit` : k.keyType.toUpperCase();
    const weak = k.keyType === 'rsa' && k.keyBits && k.keyBits < 2048;
    findings.push(f(k.valid ? (weak ? 'warn' : 'pass') : 'fail', `Selector "${k.selector}": ${size}${k.testing ? ' (testing mode)' : ''}${weak && k.valid ? ' – 2048-bit recommended' : ''}.`));
    for (const e of k.errors) findings.push(f('fail', `${k.selector}: ${e}`));
    for (const w of k.warnings) if (!/recommended|revoked/.test(w)) findings.push(f('warn', `${k.selector}: ${w}`));
  }
  const strong = valid.length && valid.every((k) => k.keyType === 'ed25519' || (k.keyBits || 0) >= 2048);
  if (strong) score += 5;
  else if (valid.length) recs.push('Rotate RSA keys shorter than 2048 bits to 2048-bit keys.');
  if (broken.length) recs.push('Fix or remove the malformed DKIM records listed above.');
  if (valid.some((k) => k.testing)) recs.push('Remove t=y once DKIM is verified working.');
  return { status: statusOf(score, max, findings), score, maxScore: max, findings, recommendations: recs, verified: valid.length > 0 };
}

export function scoreBimi(bimi, dmarcPolicy) {
  const findings = [];
  const recs = [];
  const max = WEIGHTS.bimi;
  const enforced = dmarcPolicy === 'quarantine' || dmarcPolicy === 'reject';
  if (!bimi.found) {
    findings.push(f('info', 'No BIMI record (optional). BIMI lets supporting inboxes show your logo next to authenticated mail.'));
    recs.push(enforced
      ? 'Optional: publish "v=BIMI1; l=https://<host>/logo.svg; a=https://<host>/vmc.pem" at default._bimi.<domain>. Most inboxes also require a VMC or CMC certificate (paid, issued by a certificate authority such as DigiCert or Sectigo).'
      : 'Optional: BIMI first requires DMARC enforcement (p=quarantine or p=reject). Fix DMARC first.');
    return { status: 'info', score: 0, maxScore: max, findings, recommendations: recs, dmarcEnforced: enforced };
  }
  const p = bimi.parsed;
  let score = 0;
  if (!p.errors.length && p.logoUrl) { score += 7; findings.push(f('pass', `Logo: ${p.logoUrl}`)); }
  if (p.vmcUrl && !p.errors.some((e) => e.includes('a='))) { score += 3; findings.push(f('pass', `Certificate (VMC/CMC): ${p.vmcUrl}`)); }
  for (const e of p.errors) findings.push(f('fail', e));
  for (const w of p.warnings) findings.push(f('warn', w));
  if (!enforced) {
    findings.push(f('warn', 'BIMI requires DMARC p=quarantine or p=reject (with pct=100); without it the logo will not be shown.'));
    recs.push('Move DMARC to p=quarantine or p=reject.');
    score = Math.min(score, 3);
  }
  if (bimi.inherited) findings.push(f('info', `Inherited from ${bimi.lookedUp}.`));
  if (!p.vmcUrl) recs.push('Gmail and Apple Mail only show BIMI logos with a VMC or CMC certificate (a= tag).');
  if (p.errors.length) recs.push('Fix the BIMI record errors listed above.');
  return { status: statusOf(score, max, findings), score, maxScore: max, findings, recommendations: recs, dmarcEnforced: enforced };
}

export function grade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 60) return 'D';
  return 'F';
}

// ---- v0.6.0: transport security (MTA-STS + TLS-RPT) as BONUS points ----
// These never lower a score: the five core checks still add up to 100, these add at most 5 bonus points,
// and the total is capped at 100 (see checkDomain). Missing records are "info" with 0 bonus, not a penalty.
export const BONUS = { mtaSts: 3, tlsRpt: 2 };
export const SCORE_CAP = 100;

const POLICY_FETCH_MSG = {
  redirect: (pf) => `The policy URL redirects${pf.location ? ` (to ${pf.location})` : ''}. RFC 8461 forbids following redirects, so senders ignore this policy.`,
  http_status: (pf) => `The policy file returned HTTP ${pf.status} instead of 200, so senders ignore MTA-STS.`,
  not_text: (pf) => `The policy file is served as "${String(pf.contentType).slice(0, 60)}", not text/plain, so it was not read.`,
  too_large: () => 'The policy file is larger than 64 KB, so it was not read (real policies are a few hundred bytes).',
  timeout: () => 'The policy file did not respond within 3 seconds. Senders may treat MTA-STS as unavailable.',
  network: () => 'Could not connect to the policy host over HTTPS (DNS, TLS certificate or connection error), so senders ignore MTA-STS.',
  no_address: () => 'The policy host does not resolve to any address, so senders ignore MTA-STS.',
  private_address: () => 'The policy host resolves to a private or reserved address, so it was not fetched.',
  blocked_host: () => 'The policy host is not a public internet name, so it was not fetched.',
};

export function scoreMtaSts(m) {
  const findings = [];
  const recs = [];
  const max = BONUS.mtaSts;
  const base = { maxScore: max, bonus: true };
  if (m.lookupError) {
    findings.push(f('info', `Could not look up ${m.lookedUp} (DNS error). Please retry.`));
    return { ...base, status: 'info', score: 0, findings, recommendations: recs };
  }
  if (!m.found) {
    findings.push(f('info', m.nullMx ? 'No MTA-STS record (not needed: this domain does not receive email).' : 'No MTA-STS record (optional). MTA-STS tells other mail servers to deliver to you only over verified TLS.'));
    if (!m.nullMx) recs.push(`Optional: publish a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt (start with "mode: testing") and a TXT record "v=STSv1; id=<YYYYMMDDhhmmss>" at ${m.lookedUp}.`);
    return { ...base, status: 'info', score: 0, findings, recommendations: recs };
  }
  const r = m.parsed;
  for (const e of r.errors) findings.push(f('fail', e));
  for (const w of r.warnings) findings.push(f('warn', w));
  if (r.errors.length) {
    recs.push(`Fix the record at ${m.lookedUp}: exactly one TXT record of the form "v=STSv1; id=<1-32 letters or digits>".`);
    return { ...base, status: 'fail', score: 0, findings, recommendations: recs };
  }
  findings.push(f('pass', `Record found (id=${r.id}).`));
  if (m.nullMx) {
    findings.push(f('info', 'This domain publishes a null MX (receives no email), so the policy file was not checked.'));
    return { ...base, status: 'info', score: 0, findings, recommendations: recs };
  }
  const pf = m.policyFetch || {};
  if (!pf.ok) {
    const msg = (POLICY_FETCH_MSG[pf.error] || POLICY_FETCH_MSG.network)(pf);
    findings.push(f(pf.error === 'timeout' || pf.error === 'network' ? 'warn' : 'fail', msg));
    recs.push(`Serve the policy at exactly ${m.policyUrl} with HTTP 200, Content-Type text/plain and a valid certificate for mta-sts.<domain>, without redirects.`);
    return { ...base, status: statusOf(0, max, findings), score: 0, findings, recommendations: recs };
  }
  const p = m.policy;
  for (const e of p.errors) findings.push(f('fail', `Policy: ${e}`));
  for (const w of p.warnings) findings.push(f('warn', `Policy: ${w}`));
  if (p.errors.length) {
    recs.push('Fix the policy file errors listed above; senders ignore an invalid policy.');
    return { ...base, status: 'fail', score: 0, findings, recommendations: recs };
  }
  let score = 0;
  if (p.mode === 'none') {
    findings.push(f('info', 'Policy mode is "none": MTA-STS is switched off (used to retire a policy).'));
  } else if (p.mode === 'testing') {
    score = 1;
    findings.push(f('warn', 'Policy mode is "testing": TLS failures are only reported, mail is still delivered without TLS.'));
    recs.push('After TLS reports look clean for a few weeks, change "mode: testing" to "mode: enforce" and update the id= in the TXT record.');
  } else {
    score = 3;
    findings.push(f('pass', 'Policy mode is "enforce": senders that support MTA-STS will only deliver over verified TLS.'));
  }
  if (p.mx.length) findings.push(f('info', `Allowed MX patterns: ${p.mx.slice(0, 20).join(', ') + (p.mx.length > 20 ? ` (+${p.mx.length - 20} more)` : '')}.`));
  if (m.coverage && m.coverage.uncovered.length) {
    const list = m.coverage.uncovered.join(', ');
    if (p.mode === 'enforce') {
      score = 0;
      findings.push(f('fail', `MX host${m.coverage.uncovered.length > 1 ? 's' : ''} ${list} ${m.coverage.uncovered.length > 1 ? 'are' : 'is'} not covered by the policy's mx patterns. In enforce mode, MTA-STS senders will refuse to deliver to ${m.coverage.uncovered.length > 1 ? 'them' : 'it'}.`));
    } else {
      findings.push(f('warn', `MX host${m.coverage.uncovered.length > 1 ? 's' : ''} ${list} ${m.coverage.uncovered.length > 1 ? 'are' : 'is'} not covered by the policy's mx patterns.`));
    }
    recs.push(`Add "mx:" lines covering ${list} (a "*." pattern matches exactly one extra label).`);
  } else if (m.coverage) {
    findings.push(f('pass', m.coverage.covered.length > 1 ? `All ${m.coverage.covered.length} MX hosts match the policy.` : `The MX host ${m.coverage.covered[0]} matches the policy.`));
  }
  if (p.maxAge !== null && p.mode !== 'none') {
    if (p.maxAge < MAX_AGE_WEAK) {
      if (score > 0) score -= 1;
      findings.push(f('warn', `max_age=${p.maxAge} is under one day, so the policy expires from sender caches quickly and gives weak protection.`));
      recs.push('Raise max_age to at least 604800 (one week); RFC 8461 recommends weeks or more.');
    } else if (p.maxAge < MAX_AGE_RECOMMENDED) {
      findings.push(f('info', `max_age=${p.maxAge} (${Math.round(p.maxAge / 86400)} day${p.maxAge >= 172800 ? 's' : ''}). RFC 8461 recommends weeks or more once the policy is stable.`));
    } else {
      findings.push(f('pass', `max_age=${p.maxAge} (${Math.round(p.maxAge / 86400)} days).`));
    }
  }
  return { ...base, status: statusOf(score, max, findings), score, findings, recommendations: recs };
}

export function scoreTlsRpt(t, { nullMx = false } = {}) {
  const findings = [];
  const recs = [];
  const max = BONUS.tlsRpt;
  const base = { maxScore: max, bonus: true };
  if (t.lookupError) {
    findings.push(f('info', `Could not look up ${t.lookedUp} (DNS error). Please retry.`));
    return { ...base, status: 'info', score: 0, findings, recommendations: recs };
  }
  if (!t.found) {
    findings.push(f('info', nullMx ? 'No TLS-RPT record (not needed: this domain does not receive email).' : 'No TLS-RPT record (optional). TLS-RPT asks other mail servers to send you daily reports about TLS problems delivering to you.'));
    if (!nullMx) recs.push(`Optional: publish "v=TLSRPTv1; rua=mailto:tls-reports@<domain>" as a TXT record at ${t.lookedUp}.`);
    return { ...base, status: 'info', score: 0, findings, recommendations: recs };
  }
  const p = t.parsed;
  for (const e of p.errors) findings.push(f('fail', e));
  for (const w of p.warnings) findings.push(f('warn', w));
  if (p.errors.length) {
    recs.push(`Fix the record at ${t.lookedUp}: exactly one TXT record "v=TLSRPTv1; rua=mailto:<address>" (or an https:// endpoint).`);
    return { ...base, status: 'fail', score: 0, findings, recommendations: recs };
  }
  findings.push(f('pass', `TLS reports go to ${p.rua.join(', ')}.`));
  return { ...base, status: statusOf(max, max, findings), score: max, findings, recommendations: recs };
}
