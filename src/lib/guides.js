// Static explainer pages (SEO/content). Plain HTML strings: no user input is ever interpolated,
// only the request origin (for canonical links), which is escaped.

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export const GUIDES = {
  spf: {
    title: 'What is an SPF record? Syntax, examples and common mistakes',
    h1: 'SPF records explained',
    description: 'How SPF (Sender Policy Framework) works, how to read v=spf1 records, the 10-DNS-lookup limit, ~all vs -all, and the mistakes that break SPF. Check your SPF record free.',
    short: 'Which servers may send mail for your domain, the 10-lookup limit, and ~all vs -all.',
    body: `
<p><strong>SPF (Sender Policy Framework, RFC 7208)</strong> is a DNS TXT record that lists which servers are allowed to send email for your domain. A receiving server looks up the SPF record of the domain in the message's envelope sender (the <code>Return-Path</code> / <code>MAIL FROM</code> address) and checks whether the connecting server's IP address is on the list.</p>

<p class="note">Want to skip the syntax? The <a href="/guides/spf/generator">SPF record generator</a> builds a valid record from the services you use and counts your DNS lookups as you go.</p>

<h2>What an SPF record looks like</h2>
<p>It's a single TXT record on the domain itself (not a subdomain) that starts with <code>v=spf1</code>:</p>
<pre><code>example.com.  TXT  "v=spf1 include:_spf.google.com include:sendgrid.net ip4:203.0.113.10 -all"</code></pre>
<p>Receivers read it left to right and stop at the first mechanism that matches:</p>
<div class="tbl-wrap"><table class="tbl">
<tr><th>Mechanism</th><th>Matches when the sending IP…</th><th>DNS lookups</th></tr>
<tr><td><code>ip4:</code> / <code>ip6:</code></td><td>is in the given address or range</td><td>0</td></tr>
<tr><td><code>a</code></td><td>is an A/AAAA address of the domain</td><td>1</td></tr>
<tr><td><code>mx</code></td><td>is one of the domain's mail servers</td><td>1 (plus the MX hosts' addresses)</td></tr>
<tr><td><code>include:</code></td><td>passes the other domain's SPF record (how you authorize Google Workspace, Microsoft 365, SendGrid, etc.)</td><td>1 + whatever that record uses</td></tr>
<tr><td><code>exists:</code></td><td>makes the given name resolve (advanced)</td><td>1</td></tr>
<tr><td><code>ptr</code></td><td>reverse-resolves to the domain (deprecated; don't use it)</td><td>1+</td></tr>
<tr><td><code>all</code></td><td>always matches; it goes last and sets the default result</td><td>0</td></tr>
</table></div>
<p>A <code>redirect=</code> modifier replaces the whole policy with another domain's record and also costs a lookup.</p>

<h2>~all vs -all vs ?all</h2>
<p>Each mechanism can have a qualifier. The one on <code>all</code> decides what happens to mail from servers you didn't list:</p>
<ul>
<li><code>-all</code> (fail): unlisted servers are not allowed. The strictest setting, and the right one once your list is complete.</li>
<li><code>~all</code> (softfail): unlisted servers are suspicious. Common and reasonable while you're still finding every sender; with DMARC at enforcement, softfail and fail are treated much the same.</li>
<li><code>?all</code> (neutral): no opinion. It gives almost no protection.</li>
<li><code>+all</code> (pass): <em>anyone</em> may send as you. Never use it.</li>
</ul>

<h2>The 10-lookup limit</h2>
<p>Evaluating SPF may trigger at most <strong>10 DNS lookups</strong> in total, counting every <code>include</code>, <code>a</code>, <code>mx</code>, <code>ptr</code>, <code>exists</code> and <code>redirect</code>, including the ones inside included records. Go over and the result is <code>permerror</code>, which most receivers treat as a fail. Each SaaS tool you add with another <code>include:</code> brings you closer. To get back under the limit, remove services you no longer use, replace <code>a</code>/<code>mx</code> with <code>ip4:</code> ranges where they're stable, or send bulk mail from a subdomain with its own SPF record.</p>

<h2>Common SPF mistakes</h2>
<ul>
<li><strong>Two SPF records.</strong> A domain must publish exactly one TXT record starting with <code>v=spf1</code>. Two records is a permerror. Merge them into one.</li>
<li><strong>Too many lookups</strong> (see above).</li>
<li><strong>A missing sender.</strong> Your newsletter tool, CRM or helpdesk sends as your domain but isn't in the record.</li>
<li><strong>Typos</strong> like <code>include: _spf.google.com</code> (with a space) or <code>v=spf1</code> missing at the start.</li>
<li><strong>Relying on SPF alone.</strong> SPF breaks when mail is forwarded and only checks the envelope sender, not the From address people see. Pair it with <a href="/guides/dkim">DKIM</a> and <a href="/guides/dmarc">DMARC</a>.</li>
</ul>

<h2>How DnsGuard scores SPF (25 of 100 points)</h2>
<p>10 points for a single valid record; up to 10 more for the default qualifier (<code>-all</code> 10, <code>~all</code> or <code>redirect</code> 8, <code>?all</code> or no <code>all</code> 2, <code>+all</code> 0); and 5 more if it stays within 10 lookups. A record that returns permerror is capped at 5 points, and <code>+all</code> scores 0.</p>`,
  },
  dkim: {
    title: 'What is DKIM? Selectors, key length and how to check a DKIM record',
    h1: 'DKIM explained',
    description: 'How DKIM signing works, where DKIM keys live in DNS (selector._domainkey), how to find your selector, 1024 vs 2048-bit keys, and how to rotate keys. Check your DKIM record free.',
    short: 'How signatures work, finding your selector, key length and rotation.',
    body: `
<p><strong>DKIM (DomainKeys Identified Mail, RFC 6376)</strong> adds a cryptographic signature to every message you send. Your mail server signs the message with a private key; receivers fetch the matching public key from DNS and verify that the message really came from your domain and wasn't changed on the way. Unlike <a href="/guides/spf">SPF</a>, a DKIM signature usually survives forwarding.</p>

<h2>Where DKIM keys live: the selector</h2>
<p>Each signature carries a domain (<code>d=</code>) and a <strong>selector</strong> (<code>s=</code>). The public key is published as a TXT record at <code>&lt;selector&gt;._domainkey.&lt;domain&gt;</code>:</p>
<pre><code>DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; ...

s1._domainkey.example.com.  TXT  "v=DKIM1; k=rsa; p=MIIBIjANBgkqh...IDAQAB"</code></pre>
<ul>
<li><code>v=DKIM1</code>: version (optional but recommended).</li>
<li><code>k=</code>: key type, <code>rsa</code> (the default) or <code>ed25519</code> (RFC 8463).</li>
<li><code>p=</code>: the base64 public key. An <strong>empty</strong> <code>p=</code> means the key has been revoked.</li>
</ul>
<p>Some providers (Microsoft 365, many email-marketing tools) have you add a CNAME at the selector name that points to a record they host and rotate for you.</p>

<h2>How to find your DKIM selector</h2>
<p>DNS has no way to list a domain's selectors, so every checker has to guess common names (<code>google</code>, <code>selector1</code>, <code>s1</code>, <code>k1</code> and so on). The reliable way is to open a message you sent, view the original or raw headers, find the <code>DKIM-Signature</code> header and read its <code>s=</code> value. Then check it directly: enter your domain below and put the selector under <em>Advanced</em>, or call <code>/api/check?domain=example.com&amp;selector=s1</code>.</p>

<h2>Key length and rotation</h2>
<ul>
<li>Use <strong>2048-bit RSA</strong> keys. 1024-bit keys still verify but are considered weak, and keys under 1024 bits are not accepted by major receivers.</li>
<li>A 2048-bit key is longer than 255 characters, so it is stored as several quoted strings inside one TXT record. Most DNS panels do this for you; if yours doesn't, the key will look truncated.</li>
<li>Rotate keys periodically: publish a new selector, switch signing to it, then revoke the old one by publishing an empty <code>p=</code> (or deleting it) once old mail has been delivered.</li>
</ul>

<h2>Common DKIM mistakes</h2>
<ul>
<li>Signing turned off in the provider's admin panel even though the DNS record exists (common with Google Workspace until you click "Start authentication").</li>
<li>A key pasted with quotes, line breaks or a missing chunk.</li>
<li>Third-party senders signing with their own domain (<code>d=sendgrid.net</code> and so on) instead of yours, so the signature doesn't align for <a href="/guides/dmarc">DMARC</a>. Set up a custom sending domain in each tool.</li>
</ul>

<h2>How DnsGuard scores DKIM (25 of 100 points)</h2>
<p>20 points if at least one valid public key is found, and 5 more if every valid key is 2048-bit or larger (or ed25519). If only malformed (non-revoked invalid) keys are found, DKIM gets 5. Revoked-only keys score 0; revoked keys are still shown for information. If no key is found at the selectors we try, DKIM also scores 0 with a warning, because your mail may well be signed with a selector we couldn't guess. Pass your selector to get an accurate result.</p>`,
  },
  dmarc: {
    title: 'What is DMARC? p=none vs quarantine vs reject, alignment and rua reports',
    h1: 'DMARC explained',
    description: 'How DMARC works: the _dmarc TXT record, SPF/DKIM alignment, p=none vs p=quarantine vs p=reject, rua aggregate reports, and a safe rollout plan. Check your DMARC record free.',
    short: 'Alignment, p=none vs quarantine vs reject, reports, and a safe rollout plan.',
    body: `
<p><strong>DMARC (Domain-based Message Authentication, Reporting and Conformance, RFC 7489)</strong> ties <a href="/guides/spf">SPF</a> and <a href="/guides/dkim">DKIM</a> to the address people actually see in the <code>From:</code> header, tells receivers what to do with mail that fails, and asks them to send you reports. It's what actually stops other people from sending mail that looks like it comes from your domain.</p>

<p class="note">Want to skip the syntax? The <a href="/guides/dmarc/generator">DMARC record generator</a> builds a ready-to-paste <code>_dmarc</code> record, starting safely at <code>p=none</code>.</p>

<h2>What a DMARC record looks like</h2>
<pre><code>_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=100; adkim=r; aspf=r"</code></pre>
<div class="tbl-wrap"><table class="tbl">
<tr><th>Tag</th><th>Meaning</th></tr>
<tr><td><code>v=DMARC1</code></td><td>Required, and must come first.</td></tr>
<tr><td><code>p=</code></td><td>Required policy for failing mail: <code>none</code> (monitor only), <code>quarantine</code> (spam folder) or <code>reject</code> (refuse it).</td></tr>
<tr><td><code>sp=</code></td><td>Policy for subdomains. Defaults to <code>p</code>.</td></tr>
<tr><td><code>rua=</code></td><td>Where receivers send daily aggregate reports (<code>mailto:</code> addresses).</td></tr>
<tr><td><code>ruf=</code></td><td>Where to send per-message failure reports. Few receivers send them.</td></tr>
<tr><td><code>pct=</code></td><td>Percentage of failing mail the policy applies to (default 100). Useful during rollout.</td></tr>
<tr><td><code>adkim=</code> / <code>aspf=</code></td><td>Alignment mode: <code>r</code> relaxed (default; subdomains of the same organizational domain match) or <code>s</code> strict (exact match).</td></tr>
</table></div>

<h2>Alignment: why SPF and DKIM passing isn't enough</h2>
<p>A message passes DMARC when <strong>either</strong> SPF passes for a domain that aligns with the <code>From:</code> domain, <strong>or</strong> a DKIM signature passes with a <code>d=</code> domain that aligns with it. A newsletter sent through a third-party tool might pass SPF for the tool's own bounce domain and still fail DMARC, because that domain isn't yours. The fix is to set up the tool's custom return-path or DKIM domain on your own domain.</p>

<h2>p=none vs p=quarantine vs p=reject</h2>
<ul>
<li><strong>p=none</strong> only monitors. It's the right first step, and Gmail and Yahoo require at least this from bulk senders since 2024, but it doesn't protect you from spoofing.</li>
<li><strong>p=quarantine</strong> sends failing mail to spam.</li>
<li><strong>p=reject</strong> blocks it outright. This is the goal for most domains, and it's required to display a <a href="/guides/bimi">BIMI</a> logo (quarantine also qualifies).</li>
</ul>

<h2>A safe rollout plan</h2>
<ol>
<li>Publish <code>p=none</code> with a <code>rua=</code> address and read the aggregate reports for two to four weeks.</li>
<li>Fix every legitimate sender that fails: add it to SPF, turn on DKIM signing with your domain, or move it to a subdomain.</li>
<li>Move to <code>p=quarantine</code>, optionally with <code>pct=25</code> and then 50 and 100.</li>
<li>Move to <code>p=reject</code> once reports stay clean. Domains that never send email should go straight to <code>p=reject</code>, together with <code>v=spf1 -all</code> and a null MX.</li>
</ul>

<h2>Common DMARC mistakes</h2>
<ul>
<li>Publishing the record on the domain itself instead of at <code>_dmarc.</code>, or publishing two records.</li>
<li>Staying on <code>p=none</code> forever.</li>
<li>A weaker <code>sp=none</code> that leaves every subdomain open to spoofing.</li>
<li>Sending <code>rua</code> reports to an address on another domain without that domain's authorization record (<code>example.com._report._dmarc.reports.example.net</code>), so receivers drop the reports.</li>
</ul>

<h2>How DnsGuard scores DMARC (30 of 100 points)</h2>
<p><code>p=reject</code> 22, <code>p=quarantine</code> 18, <code>p=none</code> 7; plus 3 if an enforcing policy applies to 100% of mail, plus 5 for a <code>rua</code> report address, minus 2 if <code>sp</code> is weaker than <code>p</code>. A record with syntax errors is capped at 3. Subdomains without their own record are scored on the organizational domain's record and its <code>sp</code>.</p>`,
  },
  bimi: {
    title: 'What is BIMI? Requirements, SVG logo format and VMC certificates',
    h1: 'BIMI explained',
    description: 'How BIMI shows your logo next to your emails: the default._bimi TXT record, DMARC enforcement requirement, SVG Tiny PS logos, and VMC/CMC mark certificates. Check your BIMI record free.',
    short: 'Showing your logo in the inbox: DMARC requirements, SVG format and certificates.',
    body: `
<p><strong>BIMI (Brand Indicators for Message Identification)</strong> lets mailbox providers show your logo next to messages from your domain. It's a reward for strong authentication: it only works once <a href="/guides/dmarc">DMARC</a> is enforced.</p>

<h2>Requirements</h2>
<ol>
<li><strong>DMARC at enforcement:</strong> <code>p=quarantine</code> or <code>p=reject</code>, applying to all mail (no <code>pct</code> below 100), and subdomains not set to <code>sp=none</code>.</li>
<li><strong>Passing <a href="/guides/spf">SPF</a> or <a href="/guides/dkim">DKIM</a> with alignment</strong> on the mail itself.</li>
<li><strong>A logo in SVG Tiny Portable/Secure (SVG Tiny PS) format</strong>, square, served over HTTPS. A regular SVG exported from a design tool usually needs converting.</li>
<li><strong>A mark certificate</strong> for most big inboxes: a Verified Mark Certificate (VMC), which needs a registered trademark, or a Common Mark Certificate (CMC), which Gmail also accepts for logos that have been in public use. Some providers show logos without a certificate; Gmail and Apple Mail don't.</li>
</ol>

<h2>What a BIMI record looks like</h2>
<pre><code>default._bimi.example.com.  TXT  "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/vmc.pem"</code></pre>
<ul>
<li><code>v=BIMI1</code>: version, required.</li>
<li><code>l=</code>: HTTPS URL of the SVG Tiny PS logo.</li>
<li><code>a=</code>: HTTPS URL of the VMC or CMC (a PEM file). Leave it empty if you don't have one.</li>
</ul>
<p><code>default</code> is the selector almost everyone uses.</p>

<h2>Common BIMI mistakes</h2>
<ul>
<li>Publishing BIMI while DMARC is still <code>p=none</code>. The record is ignored.</li>
<li>Serving the logo over <code>http://</code>, or as a PNG or a regular SVG instead of SVG Tiny PS.</li>
<li>Expecting the logo to show in Gmail without a certificate.</li>
</ul>

<h2>How DnsGuard scores BIMI (10 of 100 points)</h2>
<p>7 points for a valid record with an HTTPS logo URL (<code>.svg</code> expected; we warn if the URL doesn't end in <code>.svg</code>) and 3 more for an <code>a=</code> certificate URL. If DMARC isn't enforced, BIMI is capped at 3 points, because receivers will ignore it. DnsGuard checks the record's format only; it doesn't download or validate the logo or certificate.</p>`,
  },
  'mta-sts': {
    title: 'MTA-STS and TLS-RPT explained: policy file, modes, mx patterns and reports',
    h1: 'MTA-STS and TLS-RPT explained',
    description: 'How MTA-STS forces TLS for mail sent to your domain: the _mta-sts TXT record, the mta-sts.txt policy file, testing vs enforce, mx patterns, max_age, and TLS-RPT reports.',
    short: 'Encrypted delivery to your mail servers: the policy file, testing vs enforce, and TLS reports.',
    body: `
<p>SMTP between mail servers uses TLS opportunistically: if a sender can't negotiate TLS, or an attacker strips it, the message is usually delivered in plain text anyway. <strong>MTA-STS (SMTP MTA Strict Transport Security, RFC 8461)</strong> lets a domain that <em>receives</em> email say "only deliver to my listed mail servers, over TLS with a valid certificate". <strong>TLS-RPT (SMTP TLS Reporting, RFC 8460)</strong> asks senders to email you a daily report when TLS delivery to you fails. Both are optional and much less common than <a href="/guides/spf">SPF</a>, <a href="/guides/dkim">DKIM</a> and <a href="/guides/dmarc">DMARC</a>, and they protect a different thing: the connection, not the sender's identity.</p>

<h2>The two parts of MTA-STS</h2>
<p><strong>1. A TXT record</strong> at <code>_mta-sts.&lt;domain&gt;</code>:</p>
<pre><code>_mta-sts.example.com.  TXT  "v=STSv1; id=20261006T120000"</code></pre>
<p><code>id</code> is 1–32 letters or digits. Change it every time you change the policy file, so senders know to fetch the new version. Publish exactly one such record.</p>
<p><strong>2. A policy file</strong> served over HTTPS at exactly <code>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</code>, with a valid certificate for <code>mta-sts.&lt;domain&gt;</code>, HTTP 200, <code>Content-Type: text/plain</code> and no redirects:</p>
<pre><code>version: STSv1
mode: enforce
mx: mx1.example.com
mx: *.mail.example.net
max_age: 604800</code></pre>
<div class="tbl-wrap"><table class="tbl">
<tr><th>Field</th><th>Meaning</th></tr>
<tr><td><code>version</code></td><td>Always <code>STSv1</code>.</td></tr>
<tr><td><code>mode</code></td><td><code>testing</code>: report problems but still deliver. <code>enforce</code>: refuse to deliver unless TLS to a listed MX succeeds. <code>none</code>: switch MTA-STS off (used to retire a policy).</td></tr>
<tr><td><code>mx</code></td><td>One line per allowed mail server. <code>*.example.net</code> matches exactly one extra label (<code>a.example.net</code>, but not <code>a.b.example.net</code> or <code>example.net</code>). Every host in your MX records must match.</td></tr>
<tr><td><code>max_age</code></td><td>How long senders may cache the policy, in seconds, up to 31557600 (about a year). RFC 8461 recommends weeks or more once things are stable.</td></tr>
</table></div>

<h2>A safe rollout plan</h2>
<ol>
<li>Publish TLS-RPT first (below) so you get reports.</li>
<li>Serve the policy file with <code>mode: testing</code>, list every MX host, and use a short <code>max_age</code> such as 86400 (one day). Publish the TXT record.</li>
<li>Read the TLS reports for a few weeks and fix any MX host with an expired or mismatched certificate.</li>
<li>Switch to <code>mode: enforce</code>, raise <code>max_age</code> to 604800 (one week) or more, and change the <code>id</code>.</li>
<li>When you change mail providers, add the new MX hosts to the policy (and change the <code>id</code>) <em>before</em> you change your MX records.</li>
</ol>

<h2>TLS-RPT: reports about TLS failures</h2>
<pre><code>_smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@example.com"</code></pre>
<p><code>rua</code> takes one or more <code>mailto:</code> addresses or <code>https://</code> endpoints, separated by commas. Senders such as Google and Microsoft then send a daily JSON report listing successful and failed TLS sessions to your mail servers. It works with or without MTA-STS (it also covers DANE).</p>

<h2>Common mistakes</h2>
<ul>
<li>A TXT record with no reachable policy file, or a policy on a host whose certificate doesn't cover <code>mta-sts.&lt;domain&gt;</code>.</li>
<li>Redirecting the policy URL (for example to <code>www</code>). Senders must not follow redirects, so the policy is ignored.</li>
<li><code>mode: enforce</code> with an MX host missing from the <code>mx</code> lines. Senders that support MTA-STS will refuse to deliver to it.</li>
<li>Changing the policy but not the <code>id</code>, so senders keep using the cached old policy until <code>max_age</code> runs out.</li>
<li>Staying on <code>mode: testing</code> forever.</li>
</ul>

<h2>How DnsGuard scores MTA-STS and TLS-RPT (bonus: up to 5 points)</h2>
<p>These are bonus points on top of the 100 points from MX, SPF, DKIM, DMARC and BIMI, and the total is capped at 100. A missing record scores 0 with an info note, so it never lowers your score. Bonus points apply only when SPF passes and DMARC is at quarantine or reject.</p>
<p><strong>MTA-STS (up to 3):</strong> a valid record and policy in <code>enforce</code> mode scores 3, <code>testing</code> 1 and <code>none</code> 0. An <code>enforce</code> policy whose <code>mx</code> patterns don't cover every MX host scores 0. A <code>max_age</code> under 86400 (one day) costs 1 point (never below 0). MTA-STS scores 0 if the TXT record is missing or invalid (or there is more than one) or its DNS lookup fails, if the policy file can't be fetched (the policy host has no address or a private one, a connection or certificate error, a timeout after 3 seconds, a status other than 200, a redirect, a non-text response or more than 64 KB), or if the policy is invalid (including a <code>max_age</code> above 31557600). For a domain with a null MX, the policy file isn't fetched and MTA-STS scores 0.</p>
<p><strong>TLS-RPT (up to 2):</strong> 2 points for exactly one valid <code>v=TLSRPTv1</code> record whose <code>rua</code> destinations are all valid <code>mailto:</code> or <code>https://</code> URIs; otherwise 0.</p>
<p>DnsGuard fetches only <code>https://mta-sts.&lt;domain&gt;/.well-known/mta-sts.txt</code> for the domain you check. It never follows redirects and doesn't fetch the <code>rua</code> endpoints.</p>`,
  },
};

const ORDER = ['spf', 'dkim', 'dmarc', 'bimi', 'mta-sts'];
const NAMES = { spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC', bimi: 'BIMI', 'mta-sts': 'MTA-STS &amp; TLS-RPT' };
export const GUIDE_PATHS = ['/guides', ...ORDER.map((k) => `/guides/${k}`)];

export const GENERATOR_LINKS = '<a href="/guides/spf/generator">SPF record generator</a> · <a href="/guides/dmarc/generator">DMARC record generator</a>';

export function shell({ origin, path, title, description, h1, lead, body, current, crumbs, script }) {
  const others = ORDER.filter((k) => k !== current).map((k) => `<a href="/guides/${k}">${NAMES[k]}</a>`).join(' · ');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} – DnsGuard</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(origin + path)}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="top">
  <div class="wrap nav">
    <a class="brand" href="/"><svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="7" fill="#0f766e"/><path d="M16 6l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V9z" fill="#fff"/></svg> DnsGuard</a>
    <nav><a href="/">Checker</a><a href="/guides">Guides</a><a href="/#api">API</a></nav>
  </div>
</header>
<main class="wrap guide">
<p class="small crumbs"><a href="/">DnsGuard</a> › <a href="/guides">Guides</a>${crumbs || (current ? ` › ${NAMES[current]}` : '')}</p>
<h1>${esc(h1)}</h1>
${lead ? `<p class="lead">${esc(lead)}</p>` : ''}
${body}
<section class="cta">
  <h2>Check your domain now</h2>
  <p>Free check of SPF, DKIM, DMARC, BIMI, MX, MTA-STS and TLS-RPT with a 0–100 score and plain-English fixes. No sign-up.</p>
  <form class="check" action="/" method="get">
    <label for="domain" class="sr">Domain</label>
    <input id="domain" name="domain" type="text" inputmode="url" placeholder="example.com" spellcheck="false" autocapitalize="off" required maxlength="253">
    <button type="submit">Check domain</button>
  </form>
</section>
${current ? `<p>More guides: ${others}</p>` : ''}
<p>Free tools: ${GENERATOR_LINKS}</p>
</main>
<footer class="foot">
  <div class="wrap">
    <p>DnsGuard: free email-domain health checks. Results are informational and based on public DNS at the moment of the check; they are not a guarantee of deliverability.</p>
    <p>Contact: <a href="mailto:digitalpromohub.support+dnsguard@gmail.com">digitalpromohub.support+dnsguard@gmail.com</a></p>
  </div>
</footer>
${script ? `<script src="${esc(script)}" defer></script>\n` : ''}</body>
</html>`;
}

// Returns the HTML for a guide path, or null if the path isn't a guide.
export function guidePage(path, origin) {
  if (path === '/guides') {
    const list = ORDER.map((k) => `<div class="card"><h3><a href="/guides/${k}">${NAMES[k]}</a></h3><p>${esc(GUIDES[k].short)}</p></div>`).join('\n');
    return shell({
      origin, path,
      title: 'Email authentication guides: SPF, DKIM, DMARC, BIMI and MTA-STS',
      description: 'Plain-English guides to the DNS records that protect your email: SPF, DKIM, DMARC, BIMI, MTA-STS and TLS-RPT. Syntax, examples, common mistakes, and a free checker.',
      h1: 'Email authentication guides',
      lead: 'Four DNS records decide whether your email is trusted, lands in spam, or can be spoofed, and two more protect mail on its way to you. Here is what each one does and how to get it right.',
      body: `<div class="grid">\n${list}\n</div>
<h2>In what order should I set them up?</h2>
<ol>
<li><a href="/guides/spf">SPF</a>: list the services that send mail as your domain.</li>
<li><a href="/guides/dkim">DKIM</a>: turn on signing with your own domain in each of those services.</li>
<li><a href="/guides/dmarc">DMARC</a>: start at <code>p=none</code> with reports, then move to <code>quarantine</code> and <code>reject</code>.</li>
<li><a href="/guides/bimi">BIMI</a>: once DMARC is enforced, publish your logo.</li>
<li><a href="/guides/mta-sts">MTA-STS and TLS-RPT</a>: optional, for the mail you receive. Turn on TLS reports, then an MTA-STS policy in testing mode, then enforce.</li>
</ol>
<h2>Record generators</h2>
<div class="grid">
<div class="card"><h3><a href="/guides/spf/generator">SPF record generator</a></h3><p>Pick your mail services and servers, choose -all or ~all, and copy a valid v=spf1 record. Counts DNS lookups as you go.</p></div>
<div class="card"><h3><a href="/guides/dmarc/generator">DMARC record generator</a></h3><p>Choose a policy, report addresses and alignment, and copy a ready-to-paste _dmarc record.</p></div>
</div>`,
      current: null,
    });
  }
  const m = /^\/guides\/([a-z]+(?:-[a-z]+)?)$/.exec(path);
  const g = m && Object.prototype.hasOwnProperty.call(GUIDES, m[1]) ? GUIDES[m[1]] : null;
  if (!g) return null;
  return shell({ origin, path, title: g.title, description: g.description, h1: g.h1, lead: '', body: g.body, current: m[1] });
}
