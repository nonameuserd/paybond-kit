export const MCP_CAPABILITY_TOKEN_TTL_ENV = "PAYBOND_MCP_CAPABILITY_TOKEN_TTL_SEC";
export const MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV =
  "PAYBOND_MCP_CAPABILITY_TOKEN_CACHE_MAX";
export const DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC = 900;
export const DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX = 64;
const MIN_MCP_CAPABILITY_TOKEN_TTL_SEC = 60;
const MAX_MCP_CAPABILITY_TOKEN_TTL_SEC = 86_400;
const MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX = 1;
const MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX = 512;

/** MCP tools that mint or return funded intent capability tokens from Harbor. */
export const MCP_CAPABILITY_TOKEN_STORE_TOOLS = [
  "paybond_bootstrap_sandbox_guardrail",
  "paybond_create_intent",
  "paybond_create_spend_intent",
  "paybond_fund_intent",
] as const;

export type McpCapabilityTokenStoreTool =
  (typeof MCP_CAPABILITY_TOKEN_STORE_TOOLS)[number];

const MCP_CAPABILITY_TOKEN_STORE_TOOL_SET = new Set<string>(
  MCP_CAPABILITY_TOKEN_STORE_TOOLS,
);

/** Return true when an MCP tool response may populate the runtime token cache. */
export function mcpToolStoresCapabilityToken(toolName: string): boolean {
  return MCP_CAPABILITY_TOKEN_STORE_TOOL_SET.has(toolName.trim());
}

export type McpCapabilityTokenCacheConfig = {
  ttlSec: number;
  maxEntries: number;
};

type CacheEntry = {
  token: string;
  storedAtMs: number;
};

export class McpCapabilityTokenCache {
  private readonly ttlSec: number;
  private readonly maxEntries: number;
  private readonly entries = new Map<string, CacheEntry>();

  constructor(config?: McpCapabilityTokenCacheConfig) {
    this.ttlSec = config?.ttlSec ?? DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC;
    this.maxEntries = config?.maxEntries ?? DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX;
  }

  store(intentId: string, token: string): void {
    const key = intentId.trim();
    const value = token.trim();
    if (!key || !value) {
      return;
    }
    this.evictExpired();
    this.entries.set(key, { token: value, storedAtMs: Date.now() });
    this.evictOverflow();
  }

  resolve(intentId: string): string | undefined {
    this.evictExpired();
    const key = String(intentId).trim();
    const entry = this.entries.get(key);
    if (!entry) {
      return undefined;
    }
    if (Date.now() - entry.storedAtMs > this.ttlSec * 1000) {
      this.entries.delete(key);
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, entry);
    return entry.token;
  }

  private evictExpired(): void {
    const now = Date.now();
    const ttlMs = this.ttlSec * 1000;
    for (const [key, entry] of this.entries) {
      if (now - entry.storedAtMs > ttlMs) {
        this.entries.delete(key);
      }
    }
  }

  private evictOverflow(): void {
    while (this.entries.size > this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      this.entries.delete(oldest);
    }
  }
}

export function parseMcpCapabilityTokenCacheConfig(
  env: Record<string, string | undefined> = process.env,
): McpCapabilityTokenCacheConfig {
  const ttlRaw = env[MCP_CAPABILITY_TOKEN_TTL_ENV]?.trim();
  const maxRaw = env[MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV]?.trim();

  let ttlSec = DEFAULT_MCP_CAPABILITY_TOKEN_TTL_SEC;
  if (ttlRaw) {
    const parsed = Number.parseFloat(ttlRaw);
    if (!Number.isFinite(parsed)) {
      throw new Error(
        `invalid ${MCP_CAPABILITY_TOKEN_TTL_ENV} (expected a number of seconds)`,
      );
    }
    if (
      parsed < MIN_MCP_CAPABILITY_TOKEN_TTL_SEC ||
      parsed > MAX_MCP_CAPABILITY_TOKEN_TTL_SEC
    ) {
      throw new Error(
        `invalid ${MCP_CAPABILITY_TOKEN_TTL_ENV} (expected ${MIN_MCP_CAPABILITY_TOKEN_TTL_SEC}-${MAX_MCP_CAPABILITY_TOKEN_TTL_SEC} seconds)`,
      );
    }
    ttlSec = parsed;
  }

  let maxEntries = DEFAULT_MCP_CAPABILITY_TOKEN_CACHE_MAX;
  if (maxRaw) {
    const parsed = Number.parseInt(maxRaw, 10);
    if (!Number.isInteger(parsed)) {
      throw new Error(
        `invalid ${MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV} (expected an integer)`,
      );
    }
    if (
      parsed < MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX ||
      parsed > MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX
    ) {
      throw new Error(
        `invalid ${MCP_CAPABILITY_TOKEN_CACHE_MAX_ENV} (expected ${MIN_MCP_CAPABILITY_TOKEN_CACHE_MAX}-${MAX_MCP_CAPABILITY_TOKEN_CACHE_MAX})`,
      );
    }
    maxEntries = parsed;
  }

  return { ttlSec, maxEntries };
}
