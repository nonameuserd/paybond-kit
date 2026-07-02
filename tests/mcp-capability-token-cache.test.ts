import { afterEach, describe, expect, it, vi } from "vitest";

import {
  MCP_CAPABILITY_TOKEN_STORE_TOOLS,
  McpCapabilityTokenCache,
  mcpToolStoresCapabilityToken,
  parseMcpCapabilityTokenCacheConfig,
} from "../src/mcp-capability-token-cache.js";

describe("McpCapabilityTokenCache", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("stores and resolves capability tokens", () => {
    const cache = new McpCapabilityTokenCache({ ttlSec: 60, maxEntries: 4 });
    cache.store("intent-1", "cap-token");
    expect(cache.resolve("intent-1")).toBe("cap-token");
  });

  it("expires tokens after TTL", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-01T00:00:00Z"));

    const cache = new McpCapabilityTokenCache({ ttlSec: 30, maxEntries: 4 });
    cache.store("intent-1", "cap-token");

    vi.advanceTimersByTime(31_000);
    expect(cache.resolve("intent-1")).toBeUndefined();
  });

  it("evicts oldest entries when max size is exceeded", () => {
    const cache = new McpCapabilityTokenCache({ ttlSec: 60, maxEntries: 2 });
    cache.store("intent-1", "cap-1");
    cache.store("intent-2", "cap-2");
    cache.store("intent-3", "cap-3");

    expect(cache.resolve("intent-1")).toBeUndefined();
    expect(cache.resolve("intent-2")).toBe("cap-2");
    expect(cache.resolve("intent-3")).toBe("cap-3");
  });

  it("parses env overrides", () => {
    expect(
      parseMcpCapabilityTokenCacheConfig({
        PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC: "120",
        PAYBOND_MCP_CAPABILITY_TOKEN_CACHE_MAX: "8",
      }),
    ).toEqual({ ttlSec: 120, maxEntries: 8 });
  });

  it("rejects invalid TTL env values", () => {
    expect(() =>
      parseMcpCapabilityTokenCacheConfig({
        PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC: "not-a-number",
      }),
    ).toThrow(/PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC/);
  });
});

describe("mcpToolStoresCapabilityToken", () => {
  it("allows only Harbor intent issuance tools", () => {
    expect(mcpToolStoresCapabilityToken("paybond_create_spend_intent")).toBe(true);
    expect(mcpToolStoresCapabilityToken(" paybond_fund_intent ")).toBe(true);
    expect(mcpToolStoresCapabilityToken("paybond_authorize_agent_spend")).toBe(false);
    expect(mcpToolStoresCapabilityToken("paybond_verify_capability")).toBe(false);
    expect(MCP_CAPABILITY_TOKEN_STORE_TOOLS).toHaveLength(4);
  });
});
