import { describe, expect, it } from "vitest";

import { PaybondPolicy } from "../../src/policy/load.js";
import { policyToAdapterOptions } from "../../src/policy/adapter-options.js";
import { mergePaybondPolicies } from "../../src/policy/merge.js";
import { PaybondPolicyValidationError, parsePaybondPolicyDocument } from "../../src/policy/schema.js";

const TRAVEL_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: 20000,
      evidence_preset: "cost_and_completion",
    },
  },
} as const;

describe("policyToAdapterOptions", () => {
  it("returns denyProviderExecutedTools when adapter flag is true", () => {
    const doc = parsePaybondPolicyDocument({
      ...TRAVEL_POLICY,
      adapter: { deny_provider_executed_tools: true },
    });
    expect(policyToAdapterOptions(doc)).toEqual({ denyProviderExecutedTools: true });
  });

  it("returns empty options when adapter flag is omitted", () => {
    const doc = parsePaybondPolicyDocument(TRAVEL_POLICY);
    expect(policyToAdapterOptions(doc)).toEqual({});
  });
});

describe("PaybondPolicy adapter accessors", () => {
  it("exposes denyProviderExecutedTools and toAdapterOptions from document", () => {
    const policy = PaybondPolicy.fromDocument(
      parsePaybondPolicyDocument({
        ...TRAVEL_POLICY,
        adapter: { deny_provider_executed_tools: true },
      }),
    );
    expect(policy.denyProviderExecutedTools).toBe(true);
    expect(policy.toAdapterOptions()).toEqual({ denyProviderExecutedTools: true });
  });
});

describe("policy adapter merge", () => {
  it("merges org adapter deny into effective policy", () => {
    const base = parsePaybondPolicyDocument({
      version: 2,
      name: "org-base",
      default_deny: true,
      tools: TRAVEL_POLICY.tools,
      adapter: { deny_provider_executed_tools: true },
    });
    const overlay = parsePaybondPolicyDocument({
      version: 2,
      name: "tenant-east",
      default_deny: true,
      extends: { org_policy_id: "org-base", org_id: "org_acme_corp" },
      tools: {},
    });
    const merged = mergePaybondPolicies(base, overlay);
    expect(merged.effective.adapter?.deny_provider_executed_tools).toBe(true);
    expect(policyToAdapterOptions(merged.effective)).toEqual({
      denyProviderExecutedTools: true,
    });
  });

  it("rejects tenant attempts to relax org adapter deny", () => {
    const base = parsePaybondPolicyDocument({
      version: 2,
      name: "org-base",
      default_deny: true,
      tools: TRAVEL_POLICY.tools,
      adapter: { deny_provider_executed_tools: true },
    });
    const overlay = parsePaybondPolicyDocument({
      version: 2,
      name: "tenant-east",
      default_deny: true,
      extends: { org_policy_id: "org-base", org_id: "org_acme_corp" },
      overrides: { adapter: { deny_provider_executed_tools: false } },
      tools: {},
    });
    expect(() => mergePaybondPolicies(base, overlay)).toThrow(PaybondPolicyValidationError);
  });
});
