/** Server-side Google OAuth (authorization-code) helpers. No Google JS SDK. */

const AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';
const SCOPES = 'openid email'; // minimum: no `profile` scope (name/picture not requested)
const STATE_COOKIE = 'dg_oauth_state';
const STATE_TTL_SEC = 600;

export function oauthConfigured(env) {
  return Boolean(env && env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);
}

export function randomToken(bytes = 24) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return [...buf].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function stateCookieHeader(state, { clear = false, secure = true } = {}) {
  if (clear) {
    return `${STATE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure ? '; Secure' : ''}`;
  }
  return `${STATE_COOKIE}=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${STATE_TTL_SEC}${secure ? '; Secure' : ''}`;
}

export function readStateCookie(request) {
  const raw = request.headers.get('cookie') || '';
  const parts = raw.split(';').map((p) => p.trim());
  for (const p of parts) {
    if (p.startsWith(`${STATE_COOKIE}=`)) return p.slice(STATE_COOKIE.length + 1);
  }
  return null;
}

export const ROTATE_STATE_PREFIX = 'rot_';
/** The sign-in intent is bound into the state value (which must equal the HttpOnly cookie). */
export function intentFromState(state) { return String(state || '').startsWith(ROTATE_STATE_PREFIX) ? 'rotate' : 'signin'; }

export function buildAuthorizeUrl({ clientId, redirectUri, state }) {
  const u = new URL(AUTH_URL);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', SCOPES);
  u.searchParams.set('state', state);
  u.searchParams.set('access_type', 'online');
  u.searchParams.set('prompt', 'select_account');
  return u.toString();
}

export function callbackRedirectUri(origin) {
  return `${origin.replace(/\/+$/, '')}/api/auth/google/callback`;
}

export async function exchangeCode({ code, clientId, clientSecret, redirectUri, fetchImpl = fetch }) {
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: 'authorization_code',
  });
  const res = await fetchImpl(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.access_token) {
    const msg = json.error_description || json.error || `token exchange failed (${res.status})`;
    const err = new Error(msg);
    err.code = 'oauth_token_error';
    throw err;
  }
  return json;
}

export async function fetchGoogleUser(accessToken, fetchImpl = fetch) {
  const res = await fetchImpl(USERINFO_URL, {
    headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || !json.sub) {
    const err = new Error(json.error_description || json.error || `userinfo failed (${res.status})`);
    err.code = 'oauth_userinfo_error';
    throw err;
  }
  return { googleSub: String(json.sub), email: String(json.email || '').toLowerCase(), emailVerified: json.email_verified === true || json.email_verified === 'true' };
}
