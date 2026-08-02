import { describe, expect, it } from "vitest";

import { resolveRestrictedKeyScopes } from "../src/cli/commands/workflows.js";
import { CliError } from "../src/cli/types.js";

describe("resolveRestrictedKeyScopes", () => {
  it("returns empty scopes for standard keys", () => {
    expect(resolveRestrictedKeyScopes({ kind: "standard", preset: undefined, scopeTokens: [] })).toEqual(
      [],
    );
  });

  it("rejects scope flags on standard keys", () => {
    expect(() =>
      resolveRestrictedKeyScopes({
        kind: "standard",
        preset: "mcp-readonly",
        scopeTokens: [],
      }),
    ).toThrow(CliError);
  });

  it("expands presets for restricted keys", () => {
    const scopes = resolveRestrictedKeyScopes({
      kind: "restricted",
      preset: "mcp-readonly",
      scopeTokens: [],
    });
    expect(scopes.map((scope) => `${scope.scope}:${scope.level}`)).toEqual([
      "mcp.discovery:read",
      "mcp.signal:read",
      "mcp.compliance:read",
      "mcp.receipts:read",
    ]);
  });

  it("parses explicit --scope tokens", () => {
    const scopes = resolveRestrictedKeyScopes({
      kind: "restricted",
      preset: undefined,
      scopeTokens: ["mcp.discovery:read", "mcp.spend:write"],
    });
    expect(scopes).toEqual([
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.spend", level: "write" },
    ]);
  });

  it("rejects missing scopes for restricted keys", () => {
    expect(() =>
      resolveRestrictedKeyScopes({ kind: "restricted", preset: undefined, scopeTokens: [] }),
    ).toThrow(/requires --preset/);
  });
});
