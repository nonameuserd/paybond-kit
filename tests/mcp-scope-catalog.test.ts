import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  MCP_RESOURCE_SCOPES,
  MCP_SCOPE_CATALOG_VERSION,
  MCP_SCOPE_DEFINITIONS,
  MCP_SCOPE_LEVELS,
  MCP_SCOPE_PRESETS,
  MCP_SCOPE_ROUTES,
  MCP_TOOL_SCOPES,
  classifyPaybondApiKey,
  formatMcpScope,
  normalizeMcpScopes,
  parseMcpScopeToken,
  parseMcpScopes,
  presetScopes,
  scopeSatisfies,
  toolAllowedByScope,
} from "../src/mcp/scope-catalog.js";

const CATALOG_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "mcp-scopes",
  "catalog.json",
);

type CanonicalCatalog = {
  version: number;
  levels: ReadonlyArray<string>;
  scopes: ReadonlyArray<{
    id: string;
    title: string;
    max_level: string;
    description: string;
  }>;
  tools: Record<string, { scope: string; level: string }>;
  resources: Record<string, { scope: string; level: string }>;
  routes: ReadonlyArray<{ method: string; pattern: string; scope: string; level: string }>;
  presets: ReadonlyArray<{
    id: string;
    title: string;
    description: string;
    scopes: ReadonlyArray<{ scope: string; level: string }>;
  }>;
};

function loadCanonicalCatalog(): CanonicalCatalog {
  return JSON.parse(readFileSync(CATALOG_PATH, "utf8")) as CanonicalCatalog;
}

describe("MCP scope catalog TS mirror", () => {
  const canonical = loadCanonicalCatalog();

  it("mirrors version, levels, and scope definitions", () => {
    expect(MCP_SCOPE_CATALOG_VERSION).toBe(canonical.version);
    expect([...MCP_SCOPE_LEVELS]).toEqual([...canonical.levels]);
    expect(
      MCP_SCOPE_DEFINITIONS.map((definition) => ({
        id: definition.id,
        title: definition.title,
        max_level: definition.maxLevel,
        description: definition.description,
      })),
    ).toEqual(canonical.scopes);
  });

  it("mirrors tool, resource, route, and preset mappings", () => {
    expect(MCP_TOOL_SCOPES).toEqual(canonical.tools);
    expect(MCP_RESOURCE_SCOPES).toEqual(canonical.resources);
    expect(
      MCP_SCOPE_ROUTES.map((route) => ({
        method: route.method,
        pattern: route.pattern,
        scope: route.scope,
        level: route.level,
      })),
    ).toEqual(canonical.routes);
    expect(
      MCP_SCOPE_PRESETS.map((preset) => ({
        id: preset.id,
        title: preset.title,
        description: preset.description,
        scopes: preset.scopes,
      })),
    ).toEqual(canonical.presets);
  });

  it("never puts settlement write in a preset", () => {
    for (const preset of MCP_SCOPE_PRESETS) {
      expect(
        preset.scopes.some(
          (grant) => grant.scope === "mcp.settlement" && grant.level === "write",
        ),
      ).toBe(false);
    }
  });
});

describe("MCP scope helpers", () => {
  it("classifies API key prefixes without inspecting secrets", () => {
    expect(classifyPaybondApiKey("paybond_sk_sandbox_x_y")).toBe("standard");
    expect(classifyPaybondApiKey("paybond_rk_live_x_y")).toBe("restricted");
    expect(classifyPaybondApiKey("paybond_oat_sandbox_x_y")).toBe("restricted");
    expect(classifyPaybondApiKey("other")).toBe("unknown");
  });

  it("parses tokens and enforces write-implies-read", () => {
    expect(parseMcpScopeToken("mcp.spend:write")).toEqual({
      scope: "mcp.spend",
      level: "write",
    });
    expect(() => parseMcpScopeToken("mcp.discovery:write")).toThrow(/at most/);
    expect(
      scopeSatisfies([{ scope: "mcp.spend", level: "write" }], {
        scope: "mcp.spend",
        level: "read",
      }),
    ).toBe(true);
    expect(
      toolAllowedByScope("paybond_create_intent", [
        { scope: "mcp.spend", level: "write" },
      ]),
    ).toBe(true);
    expect(
      toolAllowedByScope("paybond_fund_intent", [
        { scope: "mcp.spend", level: "write" },
      ]),
    ).toBe(false);
  });

  it("normalizes grants and formats scope tokens", () => {
    expect(
      normalizeMcpScopes([
        { scope: "mcp.spend", level: "read" },
        { scope: "mcp.spend", level: "write" },
        { scope: "mcp.discovery", level: "read" },
      ]),
    ).toEqual([
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.spend", level: "write" },
    ]);
    expect(formatMcpScope({ scope: "mcp.discovery", level: "read" })).toBe(
      "mcp.discovery:read",
    );
    expect(parseMcpScopes(["mcp.discovery:read", { scope: "mcp.spend", level: "write" }])).toEqual([
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.spend", level: "write" },
    ]);
    expect(presetScopes("mcp-readonly")).toHaveLength(4);
    expect(presetScopes("nope")).toBeNull();
  });
});
