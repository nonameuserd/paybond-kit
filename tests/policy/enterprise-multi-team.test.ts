import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { mergePaybondPolicies } from "../../src/policy/merge.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import { PolicyValidator } from "../../src/policy/validate.js";
import { parsePaybondPolicyDocumentV2 } from "../../src/policy/schema.js";
import { readFileSync } from "node:fs";
import { parsePolicyDocumentText } from "../../src/policy/parse-text.js";
import { parsePaybondPolicyDocument } from "../../src/policy/schema.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const EXAMPLE_ROOT = join(MODULE_DIR, "../../../../examples/enterprise-multi-team-policy");

const ORG_BASE_PATH = join(EXAMPLE_ROOT, "org-agent-spend-v1.yaml");
const TEAM_OVERLAYS = [
  {
    team: "travel-east",
    path: join(EXAMPLE_ROOT, "teams/travel-east/paybond.policy.yaml"),
    expectedHotelCap: 15000,
    expectedBudget: 150,
    tenantTool: "acme.east.approve_travel",
    allowedTools: ["travel.book_hotel", "search.web", "acme.east.approve_travel"],
  },
  {
    team: "travel-west",
    path: join(EXAMPLE_ROOT, "teams/travel-west/paybond.policy.yaml"),
    expectedHotelCap: 10000,
    expectedBudget: 75,
    tenantTool: "acme.west.travel_concierge",
    allowedTools: ["travel.book_hotel", "search.web", "acme.west.travel_concierge"],
  },
  {
    team: "procurement",
    path: join(EXAMPLE_ROOT, "teams/procurement/paybond.policy.yaml"),
    expectedRfqCap: 75000,
    expectedBudget: 175,
    tenantTool: "acme.procurement.vendor_gate",
    allowedTools: ["procurement.submit_rfq", "search.web", "acme.procurement.vendor_gate"],
  },
] as const;

function loadYamlPolicy(path: string) {
  const text = readFileSync(path, "utf8");
  return parsePaybondPolicyDocument(parsePolicyDocumentText(text, path));
}

describe("enterprise multi-team policy example", () => {
  const orgBase = loadYamlPolicy(ORG_BASE_PATH);

  it("org base is a valid v2 document", () => {
    expect(orgBase.version).toBe(2);
    expect(orgBase.name).toBe("acme-agent-spend-v1");
    expect(orgBase.tools["travel.book_hotel"]?.max_spend_cents).toBe(20000);
  });

  it.each(TEAM_OVERLAYS.map((entry) => [entry.team, entry] as const))(
    "%s overlay merges and validates locally",
    async (_team, entry) => {
      const overlay = loadYamlPolicy(entry.path);
      expect(overlay.version).toBe(2);

      const { effective, report } = mergePaybondPolicies(
        parsePaybondPolicyDocumentV2(orgBase),
        parsePaybondPolicyDocumentV2(overlay),
      );

      expect(report.org_policy_id).toBe("acme-agent-spend-v1");
      expect(report.org_id).toBe("org_acme_corp");

      if ("expectedHotelCap" in entry) {
        expect(effective.tools["travel.book_hotel"]?.max_spend_cents).toBe(entry.expectedHotelCap);
      }
      if ("expectedRfqCap" in entry) {
        expect(effective.tools["procurement.submit_rfq"]?.max_spend_cents).toBe(entry.expectedRfqCap);
      }
      expect(effective.intent?.budget?.max_spend_usd).toBe(entry.expectedBudget);
      expect(effective.tools[entry.tenantTool]?.side_effecting).toBe(true);
      expect(effective.intent?.allowed_tools).toEqual(entry.allowedTools);

      const validation = await PolicyValidator.validate(entry.path);
      expect(validation.errors, `${entry.team} validation errors`).toEqual([]);
      expect(validation.valid).toBe(true);
    },
  );

  it("PaybondPolicy.load resolves effective policy via base_policy path", async () => {
    const eastPath = join(EXAMPLE_ROOT, "teams/travel-east/paybond.policy.yaml");
    const policy = await PaybondPolicy.load(eastPath);
    expect(policy.document.tools["travel.book_hotel"]?.max_spend_cents).toBe(15000);
    expect(policy.document.tools["acme.east.approve_travel"]?.side_effecting).toBe(true);
  });
});
