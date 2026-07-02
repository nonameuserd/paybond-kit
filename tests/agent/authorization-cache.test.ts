import { describe, expect, it } from "vitest";
import {
  AUTHORIZATION_CACHE_TTL_SEC,
  evictExpiredAuthorizationCache,
  takeValidCachedAuthorization,
  type CachedAuthorizationEntry,
} from "../../src/agent/authorization-cache.js";

function entry(
  overrides: Partial<CachedAuthorizationEntry<{ auditId: string }>> = {},
): CachedAuthorizationEntry<{ auditId: string }> {
  return {
    auth: { auditId: "audit-1" },
    operation: "travel.book_hotel",
    requestedSpendCents: 100,
    toolName: "travel.book_hotel",
    cachedAtMs: 1_000,
    ...overrides,
  };
}

describe("authorization cache", () => {
  it("evicts expired entries", () => {
    const nowMs = 200_000;
    const cache = new Map<string, CachedAuthorizationEntry<{ auditId: string }>>([
      ["fresh", entry({ cachedAtMs: nowMs - 1_000 })],
      ["stale", entry({ cachedAtMs: nowMs - AUTHORIZATION_CACHE_TTL_SEC * 1000 - 1 })],
    ]);

    evictExpiredAuthorizationCache(cache, AUTHORIZATION_CACHE_TTL_SEC, nowMs);

    expect([...cache.keys()]).toEqual(["fresh"]);
  });

  it("returns a matching fresh entry and removes it from the cache", () => {
    const cache = new Map<string, CachedAuthorizationEntry<{ auditId: string }>>([
      ["call-1:travel.book_hotel", entry()],
    ]);

    const cached = takeValidCachedAuthorization(
      cache,
      "call-1:travel.book_hotel",
      {
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
        toolName: "travel.book_hotel",
      },
      AUTHORIZATION_CACHE_TTL_SEC,
      1_500,
    );

    expect(cached?.auth.auditId).toBe("audit-1");
    expect(cache.size).toBe(0);
  });

  it("rejects stale, operation-mismatched, and spend-mismatched entries", () => {
    const stale = new Map([["k", entry({ cachedAtMs: 0 })]]);
    expect(
      takeValidCachedAuthorization(
        stale,
        "k",
        {
          operation: "travel.book_hotel",
          requestedSpendCents: 100,
          toolName: "travel.book_hotel",
        },
        AUTHORIZATION_CACHE_TTL_SEC,
        AUTHORIZATION_CACHE_TTL_SEC * 1000 + 1,
      ),
    ).toBeUndefined();

    const operationMismatch = new Map([
      ["k", entry({ operation: "travel.book_flight" })],
    ]);
    expect(
      takeValidCachedAuthorization(operationMismatch, "k", {
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
        toolName: "travel.book_hotel",
      }),
    ).toBeUndefined();

    const spendMismatch = new Map([["k", entry({ requestedSpendCents: 9_999 })]]);
    expect(
      takeValidCachedAuthorization(spendMismatch, "k", {
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
        toolName: "travel.book_hotel",
      }),
    ).toBeUndefined();
  });
});
