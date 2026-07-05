import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { scaffoldPaybondPolicy } from "../../src/policy/init.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import { PolicyValidator } from "../../src/policy/validate.js";

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
  },
} as const;

describe("PolicyValidator", () => {
  it("accepts a well-aligned travel policy", async () => {
    const report = await PolicyValidator.validate(TRAVEL_POLICY);
    expect(report.valid).toBe(true);
    expect(report.policy_name).toBe("travel-agent-v1");
    expect(report.tools).toEqual({ side_effecting: 1, read_only: 1 });
    expect(report.errors).toEqual([]);
  });

  it("errors when allowed_tools references an unknown tool", async () => {
    const report = await PolicyValidator.validate({
      ...TRAVEL_POLICY,
      intent: { allowed_tools: ["travel.book_hotel", "payments.charge"] },
    });
    expect(report.valid).toBe(false);
    expect(report.errors.some((issue) => issue.code === "policy.allowed_tool_not_registered")).toBe(
      true,
    );
  });

  it("errors when evidence_preset is missing from the completion catalog", async () => {
    const report = await PolicyValidator.validate({
      version: 1,
      name: "bad-preset-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          evidence_preset: "not_a_real_preset",
        },
      },
    });
    expect(report.valid).toBe(false);
    expect(report.errors.some((issue) => issue.code === "policy.unknown_evidence_preset")).toBe(true);
  });

  it("enforces strict alignment between side-effecting tools and allowed_tools", async () => {
    const report = await PolicyValidator.validate(
      {
        version: 1,
        name: "strict-gap-v1",
        default_deny: true,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            evidence_preset: "cost_and_completion",
          },
          "travel.book_flight": {
            side_effecting: true,
            evidence_preset: "cost_and_completion",
          },
        },
        intent: { allowed_tools: ["travel.book_hotel"] },
      },
      { strict: true },
    );
    expect(report.valid).toBe(false);
    expect(report.errors.some((issue) => issue.code === "policy.side_effecting_not_allowed")).toBe(
      true,
    );
  });

  it("checks Harbor template ids when gateway lookup is enabled", async () => {
    const report = await PolicyValidator.validate(
      {
        version: 1,
        name: "gateway-v1",
        default_deny: true,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            evidence_preset: "cost_and_completion",
          },
        },
        intent: {
          policy_binding: { template_id: "missing_template" },
          allowed_tools: ["travel.book_hotel"],
        },
      },
      {
        checkGateway: true,
        gateway: {
          async listTemplateIds() {
            return ["completion_v1"];
          },
        },
      },
    );
    expect(report.valid).toBe(false);
    expect(report.errors.some((issue) => issue.code === "policy.unknown_policy_template")).toBe(true);
  });

  it("surfaces schema issues for invalid documents", async () => {
    const report = await PolicyValidator.validate({
      version: 2,
      name: "bad-version",
      default_deny: true,
      tools: {},
    });
    expect(report.valid).toBe(false);
    expect(report.policy_name).toBeNull();
    expect(report.errors.length).toBeGreaterThan(0);
  });
});

describe("scaffoldPaybondPolicy", () => {
  it("writes a starter policy file with defaults", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-init-"));
    const out = join(dir, "paybond.policy.yaml");

    const result = await scaffoldPaybondPolicy({
      out,
      operation: "travel.book_hotel",
      evidencePreset: "cost_and_completion",
    });

    expect(result.name).toBe("travel-book-hotel-v1");
    expect(result.bytes_written).toBeGreaterThan(0);

    const policy = await PaybondPolicy.load(out);
    expect(policy.defaultDeny).toBe(true);
    expect(policy.intent?.allowed_tools).toEqual(["travel.book_hotel"]);

    const yaml = await readFile(out, "utf8");
    expect(yaml).toContain("createWithPolicyBinding");

    const report = await policy.validate();
    expect(report.valid).toBe(true);
  });

  it("refuses to overwrite unless --force is set", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-init-force-"));
    const out = join(dir, "paybond.policy.yaml");
    await writeFile(out, "version: 1\n", "utf8");

    await expect(
      scaffoldPaybondPolicy({
        out,
        operation: "travel.book_hotel",
        evidencePreset: "cost_and_completion",
      }),
    ).rejects.toThrow(/already exists/);
  });
});
