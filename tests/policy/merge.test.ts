import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { mergePaybondPolicies } from "../../src/policy/merge.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import {
  PaybondPolicyValidationError,
  parsePaybondPolicyDocumentV2,
} from "../../src/policy/schema.js";
import { readFileSync } from "node:fs";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const EXAMPLES_DIR = join(MODULE_DIR, "../../../policy/examples");

const ORG_BASE = JSON.parse(
  readFileSync(join(EXAMPLES_DIR, "org-base-acme-agent-spend-v1.json"), "utf8"),
);
const TENANT_OVERLAY = JSON.parse(
  readFileSync(join(EXAMPLES_DIR, "tenant-overlay-acme-travel-east.json"), "utf8"),
);

describe("mergePaybondPolicies", () => {
  it("merges org base with tenant overlay per tier-6 example", () => {
    const base = parsePaybondPolicyDocumentV2(ORG_BASE);
    const overlay = parsePaybondPolicyDocumentV2(TENANT_OVERLAY);
    const { effective, report } = mergePaybondPolicies(base, overlay);

    expect(effective.version).toBe(1);
    expect(effective.name).toBe("acme-travel-tenant-east");
    expect(effective.tools["travel.book_hotel"]?.max_spend_cents).toBe(15000);
    expect(effective.tools["acme.internal.approve_po"]?.side_effecting).toBe(true);
    expect(effective.intent?.budget?.max_spend_usd).toBe(150);
    expect(report.org_policy_id).toBe("acme-agent-spend-v1");
    expect(report.org_id).toBe("org_acme_corp");
    expect(report.overrides_applied).toContain("tools.travel.book_hotel.max_spend_cents");
    expect(report.overrides_applied).toContain("intent.budget.max_spend_usd");
  });

  it("rejects spend cap widenings", () => {
    const base = parsePaybondPolicyDocumentV2(ORG_BASE);
    const overlay = parsePaybondPolicyDocumentV2({
      ...TENANT_OVERLAY,
      overrides: {
        tools: {
          "travel.book_hotel": {
            max_spend_cents: 25000,
          },
        },
      },
    });

    expect(() => mergePaybondPolicies(base, overlay)).toThrow(PaybondPolicyValidationError);
  });

  it("rejects disabling org-required side-effecting tools", () => {
    const base = parsePaybondPolicyDocumentV2(ORG_BASE);
    const overlay = parsePaybondPolicyDocumentV2({
      ...TENANT_OVERLAY,
      overrides: {
        tools: {
          "travel.book_hotel": {
            side_effecting: false,
          },
        },
      },
    });

    expect(() => mergePaybondPolicies(base, overlay)).toThrow(/cannot disable org-required/);
  });

  it("rejects widening allowed_tools beyond org allowlist", () => {
    const base = parsePaybondPolicyDocumentV2(ORG_BASE);
    const overlay = parsePaybondPolicyDocumentV2({
      ...TENANT_OVERLAY,
      overrides: {
        intent: {
          allowed_tools: ["travel.book_hotel", "payments.wire"],
        },
      },
    });

    expect(() => mergePaybondPolicies(base, overlay)).toThrow(/widens org allowlist/);
  });
});

describe("PaybondPolicy.mergeLocal", () => {
  it("loads effective policy from overlay with base_policy path", async () => {
    const overlayPath = join(EXAMPLES_DIR, "tenant-overlay-acme-travel-east.json");
    const { policy, report } = await PaybondPolicy.mergeLocal({
      base: join(EXAMPLES_DIR, "org-base-acme-agent-spend-v1.json"),
      overlay: overlayPath,
    });

    expect(policy.document.tools["travel.book_hotel"]?.max_spend_cents).toBe(15000);
    expect(report.overrides_applied.length).toBeGreaterThan(0);
  });
});
