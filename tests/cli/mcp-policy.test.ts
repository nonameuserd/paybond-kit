import { describe, expect, it } from "vitest";

import {
  mergeMcpToolPolicy,
  parseMcpToolAllowlist,
  parseMcpToolPolicy,
  toolAllowedByPolicy,
  validateMcpToolSchema,
} from "../../src/cli/mcp-policy.js";

describe("mcp policy", () => {
  it("readonly policy allows read-only tools only", () => {
    const config = parseMcpToolPolicy("readonly");
    expect(toolAllowedByPolicy("paybond_get_principal", { readOnlyHint: true }, config)).toBe(true);
    expect(
      toolAllowedByPolicy("paybond_create_spend_intent", { readOnlyHint: false, destructiveHint: false }, config),
    ).toBe(false);
  });

  it("spend-write policy blocks live-money tools", () => {
    const config = parseMcpToolPolicy("spend-write");
    expect(
      toolAllowedByPolicy("paybond_create_spend_intent", { readOnlyHint: false, destructiveHint: false }, config),
    ).toBe(true);
    expect(toolAllowedByPolicy("paybond_fund_intent", { readOnlyHint: false, destructiveHint: true }, config)).toBe(
      false,
    );
  });

  it("allowlist requires tool names", () => {
    expect(() => mergeMcpToolPolicy(parseMcpToolPolicy("allowlist"))).toThrow(/tool-allowlist is required/);
    expect(parseMcpToolAllowlist("paybond_get_principal,paybond_list_intents")).toEqual([
      "paybond_get_principal",
      "paybond_list_intents",
    ]);
  });

  it("validates tool schemas", () => {
    const errors = validateMcpToolSchema({ name: "paybond_get_principal" });
    expect(errors.some((error) => error.includes("description"))).toBe(true);
  });
});
