import { describe, expect, it, vi } from "vitest";

import { PaybondPolicy } from "../../src/policy/load.js";
import {
  parsePolicyRemoteValidateResponse,
  policyValidateQueryString,
  validatePolicyPayloadRemote,
  validatePolicyRemote,
  type PolicyRemoteValidateClient,
} from "../../src/policy/validate-remote.js";

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
    "search.web": {
      side_effecting: false,
    },
  },
  intent: {
    allowed_tools: ["travel.book_hotel"],
    policy_binding: {
      template_id: "completion_budget_v1",
      head_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    },
  },
} as const;

const REMOTE_REPORT = {
  valid: false,
  local_valid: true,
  remote_valid: false,
  policy_name: "travel-agent-v1",
  tenant_id: "tenant-sandbox-1",
  errors: [
    {
      path: "intent.policy_binding.head_digest",
      code: "template_head_mismatch",
      message: "head digest does not match published tenant head",
    },
  ],
  warnings: [],
  checks: [
    { name: "template_exists", passed: true },
    { name: "head_digest_match", passed: false },
  ],
};

describe("parsePolicyRemoteValidateResponse", () => {
  it("parses a Gateway validation report", () => {
    const report = parsePolicyRemoteValidateResponse(REMOTE_REPORT);
    expect(report.valid).toBe(false);
    expect(report.local_valid).toBe(true);
    expect(report.remote_valid).toBe(false);
    expect(report.policy_name).toBe("travel-agent-v1");
    expect(report.tenant_id).toBe("tenant-sandbox-1");
    expect(report.errors).toHaveLength(1);
    expect(report.checks).toEqual([
      { name: "template_exists", passed: true },
      { name: "head_digest_match", passed: false },
    ]);
  });

  it("parses inheritance merge metadata when present", () => {
    const report = parsePolicyRemoteValidateResponse({
      ...REMOTE_REPORT,
      valid: true,
      remote_valid: true,
      errors: [],
      effective_policy_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      merge_report: {
        org_policy_id: "acme-agent-spend-v1",
        org_id: "org_acme_corp",
        base_policy_name: "acme-agent-spend-v1",
        overlay_policy_name: "acme-travel-tenant-east",
        overrides_applied: ["tools.travel.book_hotel.max_spend_cents"],
        denied_widenings: [],
      },
    });
    expect(report.effective_policy_digest).toBe(
      "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    expect(report.merge_report?.org_policy_id).toBe("acme-agent-spend-v1");
    expect(report.merge_report?.overrides_applied).toEqual([
      "tools.travel.book_hotel.max_spend_cents",
    ]);
  });
});

describe("policyValidateQueryString", () => {
  it("includes strict and resolve_inheritance flags", () => {
    expect(policyValidateQueryString({ strict: true, resolveInheritance: true })).toBe(
      "?strict=1&resolve_inheritance=1",
    );
  });
});

describe("validatePolicyRemote", () => {
  it("posts the serialized policy document to the gateway client", async () => {
    const validatePolicy = vi.fn<PolicyRemoteValidateClient["validatePolicy"]>().mockResolvedValue(
      parsePolicyRemoteValidateResponse(REMOTE_REPORT),
    );
    const client: PolicyRemoteValidateClient = { validatePolicy };

    const report = await validatePolicyRemote(TRAVEL_POLICY, client, { strict: true });
    expect(report.remote_valid).toBe(false);
    expect(validatePolicy).toHaveBeenCalledOnce();
    const [payload, options] = validatePolicy.mock.calls[0] ?? [];
    expect(options).toEqual({ strict: true });
    expect(payload).toMatchObject({
      version: 1,
      name: "travel-agent-v1",
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          evidence_preset: "cost_and_completion",
        },
      },
      intent: {
        policy_binding: {
          template_id: "completion_budget_v1",
        },
      },
    });
  });
});

describe("validatePolicyPayloadRemote", () => {
  it("passes resolve_inheritance through to the gateway client", async () => {
    const validatePolicy = vi.fn<PolicyRemoteValidateClient["validatePolicy"]>().mockResolvedValue(
      parsePolicyRemoteValidateResponse(REMOTE_REPORT),
    );
    const client: PolicyRemoteValidateClient = { validatePolicy };
    const overlay = {
      version: 2,
      name: "acme-travel-tenant-east",
      extends: { org_policy_id: "acme-agent-spend-v1", org_id: "org_acme_corp" },
      default_deny: true,
      tools: {},
    };

    await validatePolicyPayloadRemote(overlay, client, { resolveInheritance: true, strict: true });
    const [, options] = validatePolicy.mock.calls[0] ?? [];
    expect(options).toEqual({ resolveInheritance: true, strict: true });
  });
});

describe("PaybondPolicy.validateRemote", () => {
  it("delegates to validatePolicyRemote", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    const validatePolicy = vi.fn<PolicyRemoteValidateClient["validatePolicy"]>().mockResolvedValue(
      parsePolicyRemoteValidateResponse({ ...REMOTE_REPORT, valid: true, remote_valid: true, errors: [] }),
    );

    const report = await policy.validateRemote({ validatePolicy });
    expect(report.valid).toBe(true);
    expect(validatePolicy).toHaveBeenCalledOnce();
  });
});
