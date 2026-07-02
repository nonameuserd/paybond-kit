/** Max age for authorize → wrapExecute cache reuse (seconds). */
export const AUTHORIZATION_CACHE_TTL_SEC = 120;

export type CachedAuthorizationEntry<TAuth> = {
  auth: TAuth;
  policyDigest?: string;
  operation: string;
  requestedSpendCents: number;
  toolName: string;
  cachedAtMs: number;
};

export type AuthorizationCacheExpectation = {
  operation: string;
  requestedSpendCents: number;
  toolName: string;
};

/** Drop expired entries before inserting a new authorization. */
export function evictExpiredAuthorizationCache<TAuth>(
  cache: Map<string, CachedAuthorizationEntry<TAuth>>,
  ttlSec: number = AUTHORIZATION_CACHE_TTL_SEC,
  nowMs: number = Date.now(),
): void {
  const ttlMs = ttlSec * 1000;
  for (const [key, entry] of cache) {
    if (nowMs - entry.cachedAtMs > ttlMs) {
      cache.delete(key);
    }
  }
}

/**
 * Remove and return a cached authorization when it is fresh and matches the
 * wrapExecute call (operation, spend, tool name).
 */
export function takeValidCachedAuthorization<TAuth>(
  cache: Map<string, CachedAuthorizationEntry<TAuth>>,
  cacheKey: string,
  expected: AuthorizationCacheExpectation,
  ttlSec: number = AUTHORIZATION_CACHE_TTL_SEC,
  nowMs: number = Date.now(),
): CachedAuthorizationEntry<TAuth> | undefined {
  const cached = cache.get(cacheKey);
  if (!cached) {
    return undefined;
  }
  cache.delete(cacheKey);

  const ttlMs = ttlSec * 1000;
  if (nowMs - cached.cachedAtMs > ttlMs) {
    return undefined;
  }
  if (cached.operation !== expected.operation) {
    return undefined;
  }
  if (cached.requestedSpendCents !== expected.requestedSpendCents) {
    return undefined;
  }
  if (cached.toolName !== expected.toolName) {
    return undefined;
  }

  return cached;
}
