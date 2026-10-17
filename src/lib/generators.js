// v0.9.0: SPF + DMARC record generator pages (SEO tools). Static HTML only: no user input is ever interpolated
// server-side (the request origin is escaped by shell()). The builders run client-side in /generators.js
// (public/generators.js.txt): no API calls, no cookies, no storage; nothing typed is sent to DnsGuard.
import { shell } from './guides.js';

export const GENERATOR_PATHS = ['/guides/spf/generator', '/guides/dmarc/generator'];
export const GENERATOR_SCRIPT = '/generators.js';

const NOSCRIPT = '<noscript><p class="note">This generator runs in your browser and needs JavaScript. Without it, start from the example above and edit it by hand using the guide.</p></noscript>';
const PRIVACY = '<p class="small">Runs entirely in your browser. Nothing you type here is sent to DnsGuard or stored.</p>';

const SPF_PRESETS = [
  ['Google Workspace', '_spf.google.com'],
  ['Microsoft 365', 'spf.protection.outlook.com'],
  ['SendGrid', 'sendgrid.net'],
  ['Mailgun', 'mailgun.org'],
  ['Amazon SES', 'amazonses.com'],
  ['Zoho Mail', 'zohomail.com'],
  ['Brevo', 'spf.brevo.com'],
  ['Zendesk', 'mail.zendesk.com'],
];

const SPF_BODY = `
<p>An SPF record is one DNS TXT record that lists every server allowed to send email for your domain. Pick the services you send with, add your own servers, choose what happens to everything else, and copy the result into your DNS panel. New to SPF? Read the <a href="/guides/spf">SPF guide</a> first.</p>
${PRIVACY}
<div class="gen" id="spf-gen">
  <div class="field">
    <label for="spf-domain">Your domain</label>
    <input id="spf-domain" type="text" inputmode="url" placeholder="example.com" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="253">
  </div>
  <fieldset>
    <legend>Services that send email as your domain (<code>include:</code>)</legend>
    <p class="presets">${SPF_PRESETS.map(([n, d]) => `<button type="button" data-include="${d}">+ ${n}</button>`).join(' ')}</p>
    <label for="spf-include">Include domains, one per line. Your provider's setup page gives the exact value.</label>
    <textarea id="spf-include" rows="3" placeholder="_spf.google.com" spellcheck="false" autocapitalize="off"></textarea>
  </fieldset>
  <fieldset>
    <legend>Your own servers</legend>
    <label class="chk"><input id="spf-a" type="checkbox"> <code>a</code>: the server your domain's A/AAAA record points to sends mail</label>
    <label class="chk"><input id="spf-mx" type="checkbox"> <code>mx</code>: your inbound mail servers (MX) also send mail</label>
    <label for="spf-ip4">IPv4 addresses or ranges (<code>ip4:</code>), one per line</label>
    <textarea id="spf-ip4" rows="2" placeholder="203.0.113.10&#10;198.51.100.0/24" spellcheck="false" autocapitalize="off"></textarea>
    <label for="spf-ip6">IPv6 addresses or ranges (<code>ip6:</code>), one per line</label>
    <textarea id="spf-ip6" rows="2" placeholder="2001:db8::/32" spellcheck="false" autocapitalize="off"></textarea>
  </fieldset>
  <details class="adv">
    <summary>Advanced: <code>exists:</code> and <code>redirect=</code></summary>
    <label for="spf-exists"><code>exists:</code> domains or macros, one per line (rarely needed)</label>
    <textarea id="spf-exists" rows="2" placeholder="%{i}._spf.example.com" spellcheck="false" autocapitalize="off"></textarea>
    <label for="spf-redirect"><code>redirect=</code> use another domain's SPF policy instead of an <code>all</code> (leave empty unless you know you need it)</label>
    <input id="spf-redirect" type="text" placeholder="_spf.example.com" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="253">
  </details>
  <fieldset>
    <legend>Mail from servers you didn't list</legend>
    <label for="spf-all">Qualifier on <code>all</code></label>
    <select id="spf-all">
      <option value="-" selected>-all: fail (recommended once your list is complete)</option>
      <option value="~">~all: softfail (while you're still finding every sender)</option>
      <option value="?">?all: neutral (almost no protection)</option>
      <option value="+">+all (pass everyone; never use)</option>
    </select>
  </fieldset>
  <div class="out">
    <h2>Your SPF record</h2>
    <p class="small">Type <strong>TXT</strong>, name <strong id="spf-host">your domain (@)</strong>, value:</p>
    <pre class="rec" id="spf-out">v=spf1 -all</pre>
    <p class="actions"><button type="button" id="spf-copy">Copy record</button> <span id="spf-copied" class="small" aria-live="polite"></span></p>
    <p class="small">DNS lookups: <span id="spf-lookups" class="count c-pass">0 / 10</span> (each <code>include</code>, <code>a</code>, <code>mx</code>, <code>exists</code> and <code>redirect</code> counts one; includes can add more)</p>
    <ul class="gen-msgs" id="spf-msgs" aria-live="polite"></ul>
    ${NOSCRIPT}
    <p>After you publish it, <a id="spf-check" href="/">check your domain</a> to see the real lookup count and your full email score.</p>
  </div>
</div>

<h2>How to publish it</h2>
<ol>
<li>In your DNS provider's panel, find the existing TXT record that starts with <code>v=spf1</code>. If there is one, edit it instead of adding a new one. A domain must have exactly one.</li>
<li>Set the name (host) to <code>@</code> or leave it blank, which means the domain itself, and paste the value.</li>
<li>Wait for the TTL to pass (often 5 minutes to an hour), then run a check.</li>
</ol>

<h2>Tips</h2>
<ul>
<li>Start with <code>~all</code> if you're not sure you've found every sender, then switch to <code>-all</code>. Once <a href="/guides/dmarc">DMARC</a> is enforced, the two are treated much the same.</li>
<li>Stay under 10 DNS lookups. Remove services you've stopped using, and prefer <code>ip4:</code> ranges over <code>a</code>/<code>mx</code> when your server addresses are stable.</li>
<li>Domains that never send email should publish <code>v=spf1 -all</code> on its own.</li>
<li>SPF is only one part. Turn on <a href="/guides/dkim">DKIM</a> in each service and publish a <a href="/guides/dmarc/generator">DMARC record</a>.</li>
</ul>`;

const DMARC_BODY = `
<p>A DMARC record tells receiving mail servers what to do with mail that fails <a href="/guides/spf">SPF</a> and <a href="/guides/dkim">DKIM</a> alignment, and where to send reports. Choose your settings and copy the record into your DNS panel. New to DMARC? Read the <a href="/guides/dmarc">DMARC guide</a> first.</p>
${PRIVACY}
<div class="gen" id="dmarc-gen">
  <div class="field">
    <label for="dmarc-domain">Your domain</label>
    <input id="dmarc-domain" type="text" inputmode="url" placeholder="example.com" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="253">
  </div>
  <fieldset>
    <legend>Policy</legend>
    <label for="dmarc-p">Policy for your domain (<code>p=</code>)</label>
    <select id="dmarc-p">
      <option value="none" selected>none: monitor only (safe first step)</option>
      <option value="quarantine">quarantine: send failing mail to spam</option>
      <option value="reject">reject: refuse failing mail</option>
    </select>
    <label for="dmarc-sp">Policy for subdomains (<code>sp=</code>)</label>
    <select id="dmarc-sp">
      <option value="" selected>Same as the domain (leave out sp)</option>
      <option value="none">none</option>
      <option value="quarantine">quarantine</option>
      <option value="reject">reject</option>
    </select>
    <label for="dmarc-pct">Percentage of failing mail the policy applies to (<code>pct=</code>, 0–100)</label>
    <input id="dmarc-pct" type="number" min="0" max="100" step="1" value="100">
  </fieldset>
  <fieldset>
    <legend>Reports</legend>
    <label for="dmarc-rua">Aggregate report addresses (<code>rua=</code>), comma-separated</label>
    <input id="dmarc-rua" type="text" inputmode="email" placeholder="dmarc-reports@example.com" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="500">
    <label for="dmarc-ruf">Failure report addresses (<code>ruf=</code>, optional, few receivers send them)</label>
    <input id="dmarc-ruf" type="text" inputmode="email" placeholder="" spellcheck="false" autocapitalize="off" autocomplete="off" maxlength="500">
    <label for="dmarc-fo">When to send failure reports (<code>fo=</code>, used only with ruf)</label>
    <select id="dmarc-fo">
      <option value="0" selected>0: when SPF and DKIM both fail (default)</option>
      <option value="1">1: when either SPF or DKIM fails</option>
      <option value="d">d: when DKIM fails</option>
      <option value="s">s: when SPF fails</option>
    </select>
  </fieldset>
  <details class="adv">
    <summary>Advanced: alignment (<code>adkim=</code>, <code>aspf=</code>)</summary>
    <label for="dmarc-adkim">DKIM alignment</label>
    <select id="dmarc-adkim"><option value="r" selected>relaxed (default)</option><option value="s">strict</option></select>
    <label for="dmarc-aspf">SPF alignment</label>
    <select id="dmarc-aspf"><option value="r" selected>relaxed (default)</option><option value="s">strict</option></select>
  </details>
  <div class="out">
    <h2>Your DMARC record</h2>
    <p class="small">Type <strong>TXT</strong>, name <strong id="dmarc-host">_dmarc.example.com</strong> (most DNS panels want just <code>_dmarc</code>), value:</p>
    <pre class="rec" id="dmarc-out">v=DMARC1; p=none</pre>
    <p class="actions"><button type="button" id="dmarc-copy">Copy record</button> <span id="dmarc-copied" class="small" aria-live="polite"></span></p>
    <ul class="gen-msgs" id="dmarc-msgs" aria-live="polite"></ul>
    ${NOSCRIPT}
    <p>After you publish it, <a id="dmarc-check" href="/">check your domain</a> to confirm receivers can read it.</p>
  </div>
</div>

<h2>The path to p=reject</h2>
<ol>
<li><strong>Monitor.</strong> Publish <code>p=none</code> with a <code>rua=</code> address and read the aggregate reports for two to four weeks.</li>
<li><strong>Fix your senders.</strong> Every legitimate service that fails needs SPF or DKIM aligned with your domain. Add it to your <a href="/guides/spf/generator">SPF record</a> or turn on DKIM signing with your own domain.</li>
<li><strong>Quarantine.</strong> Switch to <code>p=quarantine</code>. You can start with <code>pct=25</code>, then 50, then 100.</li>
<li><strong>Reject.</strong> Once reports stay clean, switch to <code>p=reject</code>. Domains that never send email can go straight to <code>p=reject</code>.</li>
</ol>

<h2>How to publish it</h2>
<ol>
<li>In your DNS provider's panel, add a TXT record with the name <code>_dmarc</code> (the panel adds your domain) and paste the value. If a <code>_dmarc</code> TXT record already exists, edit it instead. A domain must have exactly one.</li>
<li>If reports go to an address at another domain, that domain has to publish an authorization record. The generator shows it when you need one; report services usually publish it for you.</li>
<li>Wait for the TTL to pass, then run a check.</li>
</ol>`;

const PAGES = {
  '/guides/spf/generator': {
    title: 'SPF record generator: build a valid v=spf1 TXT record',
    description: 'Free SPF record generator. Add Google Workspace, Microsoft 365 and other senders, IPs and -all or ~all, count DNS lookups live, and copy a ready-to-paste v=spf1 TXT record.',
    h1: 'SPF record generator',
    crumbs: ' › <a href="/guides/spf">SPF</a> › Generator',
    body: SPF_BODY,
  },
  '/guides/dmarc/generator': {
    title: 'DMARC record generator: build a _dmarc TXT record',
    description: 'Free DMARC record generator. Choose p=none, quarantine or reject, report addresses (rua, ruf), pct and alignment, and copy a ready-to-paste v=DMARC1 record for _dmarc.',
    h1: 'DMARC record generator',
    crumbs: ' › <a href="/guides/dmarc">DMARC</a> › Generator',
    body: DMARC_BODY,
  },
};

// Returns the HTML for a generator path, or null.
export function generatorPage(path, origin) {
  const g = Object.prototype.hasOwnProperty.call(PAGES, path) ? PAGES[path] : null;
  if (!g) return null;
  return shell({ origin, path, title: g.title, description: g.description, h1: g.h1, lead: '', body: g.body, current: null, crumbs: g.crumbs, script: GENERATOR_SCRIPT });
}
