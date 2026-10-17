/** Cloudflare Worker env bindings (ambient). */
interface Env {
  /** Shared Polar Pro licenses KV (the license gateway). Read-only on the hot path. */
  LICENSES?: KVNamespace;
  /** Pro per-minute rate limit (~600/min per license). */
  PRO_CHECK_LIMITER?: RateLimit;
}
