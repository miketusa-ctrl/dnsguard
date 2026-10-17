/**
 * DnsGuard Pro (Polar) — single place for public checkout URL, slug, and limits.
 * License validation uses fleet-license.js + shared LICENSES KV (no Polar on the hot path).
 * Never log full license keys — use maskLicenseKey from fleet-license.js.
 */
import { hashApiKey } from './keys.js';

/** Polar checkout link (persistent). Format: https://buy.polar.sh/polar_cl_… */
export const PRO_CHECKOUT_URL =
  'https://buy.polar.sh/polar_cl_gikZjiwyAE6uZPCem4zDUlQLJTrEMo7VHvCph3xozYN';

export const PRO_PRODUCT_SLUG = 'dnsguard-pro';
export const PRO_KEY_PREFIX = 'DNSG';
export const PRO_CHECKS_PER_MIN = 600;
export const PRO_CHECKS_PER_DAY = 10_000;
export const PRO_PRICE = '$9/mo';

/** Free mint keys always start with this; they win over Pro when both could apply. */
export const FREE_KEY_PREFIX = 'dg_live_';

export function isFreeKeyPresented(key) {
  return typeof key === 'string' && key.startsWith(FREE_KEY_PREFIX);
}

/** Case-insensitive product prefix before the first dash (Polar license-key benefit). */
export function looksLikeProKey(key) {
  if (!key || typeof key !== 'string') return false;
  const head = key.trim().split('-')[0] || '';
  return head.toUpperCase() === PRO_KEY_PREFIX;
}

/**
 * Durable Object / rate-limit identity for a Pro license.
 * Stable hash of the raw key — never store or return the raw key.
 * Shape: `pro:` + first 32 hex chars of SHA-256(key).
 */
export async function proQuotaIdFor(rawKey) {
  const hash = await hashApiKey(rawKey);
  return `pro:${hash.slice(0, 32)}`;
}
