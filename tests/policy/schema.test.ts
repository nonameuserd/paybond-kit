import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";
import { describe, expect, it } from "vitest";

import {
  PAYBOND_POLICY_SCHEMA_VERSION,
  PaybondPolicyValidationError,
  parsePaybondPolicyDocument,
} from "../../src/policy/schema.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const POLICY_DIR = join(MODULE_DIR, "../../../policy");

const TRAVEL_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: 20000,
      evidence_preset: "cost_and_completion",
      vendor_pack: "travel_booking_v1",
    },
    "search.web": {
      side_effecting: false,
    },
  },
  intent: {
    policy_binding: {
      template_id: "travel_agent_template",
      head_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    budget: {
      currency: "usd",
      max_spend_usd: 200,
    },
    allowed_tools: ["travel.book_hotel"],
  },
} as const;

describe("paybond.policy.yaml v1 schema", () => {
  it("parses the tier-4 travel agent example", () => {
    const doc = parsePaybondPolicyDocument(TRAVEL_POLICY);
    expect(doc.version).toBe(PAYBOND_POLICY_SCHEMA_VERSION);
    expect(doc.name).toBe("travel-agent-v1");
    expect(doc.default_deny).toBe(true);
    expect(doc.tools["travel.book_hotel"]?.evidence_preset).toBe("cost_and_completion");
    expect(doc.intent?.allowed_tools).toEqual(["travel.book_hotel"]);
  });

  it("rejects unsupported schema versions", () => {
    expect(() =>
      parsePaybondPolicyDocument({
        ...TRAVEL_POLICY,
        version: 99,
      }),
    ).toThrow(PaybondPolicyValidationError);
  });

  it("parses v2 org base documents", () => {
    const doc = parsePaybondPolicyDocument({
      version: 2,
      name: "acme-agent-spend-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          max_spend_cents: 20000,
          evidence_preset: "cost_and_completion",
        },
      },
    });
    expect(doc.version).toBe(2);
    if (doc.version === 2) {
      expect(doc.extends).toBeUndefined();
    }
  });

  it("parses v2 tenant overlay with extends and overrides", () => {
    const doc = parsePaybondPolicyDocument({
      version: 2,
      name: "acme-travel-tenant-east",
      extends: {
        org_policy_id: "acme-agent-spend-v1",
        org_id: "org_acme_corp",
      },
      default_deny: true,
      overrides: {
        tools: {
          "travel.book_hotel": {
            max_spend_cents: 15000,
          },
        },
      },
      tools: {},
    });
    expect(doc.version).toBe(2);
    if (doc.version === 2) {
      expect(doc.extends?.org_id).toBe("org_acme_corp");
      expect(doc.overrides?.tools?.["travel.book_hotel"]?.max_spend_cents).toBe(15000);
    }
  });

  it("requires evidence_preset on side-effecting tools", () => {
    expect(() =>
      parsePaybondPolicyDocument({
        ...TRAVEL_POLICY,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            max_spend_cents: 20000,
          },
        },
      }),
    ).toThrow(/evidence_preset/);
  });

  it("rejects max_spend_cents and spend_from_args together", () => {
    expect(() =>
      parsePaybondPolicyDocument({
        ...TRAVEL_POLICY,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            evidence_preset: "cost_and_completion",
            max_spend_cents: 100,
            spend_from_args: "estimated_price_cents",
          },
        },
      }),
    ).toThrow(/mutually exclusive/);
  });

  it("validates example documents against policy.schema.json", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(readFileSync(join(POLICY_DIR, "policy.schema.json"), "utf8"));
    const validate = ajv.compile(schema);
    const valid = validate(TRAVEL_POLICY);
    expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });
});

function policyDocumentToDict(doc: ReturnType<typeof parsePaybondPolicyDocument>) {
  return {
    version: doc.version,
    name: doc.name,
    default_deny: doc.default_deny,
    tools: Object.fromEntries(
      Object.entries(doc.tools).map(([toolName, entry]) => [
        toolName,
        {
          side_effecting: entry.side_effecting,
          ...(entry.max_spend_cents !== undefined
            ? { max_spend_cents: entry.max_spend_cents }
            : {}),
          ...(entry.spend_from_args !== undefined
            ? { spend_from_args: entry.spend_from_args }
            : {}),
          ...(entry.evidence_preset !== undefined
            ? { evidence_preset: entry.evidence_preset }
            : {}),
          ...(entry.vendor_pack !== undefined ? { vendor_pack: entry.vendor_pack } : {}),
          ...(entry.operation !== undefined ? { operation: entry.operation } : {}),
        },
      ]),
    ),
    ...(doc.intent
      ? {
          intent: {
            ...(doc.intent.policy_binding
              ? {
                  policy_binding: {
                    template_id: doc.intent.policy_binding.template_id,
                    ...(doc.intent.policy_binding.version_seq !== undefined
                      ? { version_seq: doc.intent.policy_binding.version_seq }
                      : {}),
                    ...(doc.intent.policy_binding.head_digest !== undefined
                      ? { head_digest: doc.intent.policy_binding.head_digest }
                      : {}),
                  },
                }
              : {}),
            ...(doc.intent.budget ? { budget: doc.intent.budget } : {}),
            ...(doc.intent.allowed_tools?.length
              ? { allowed_tools: doc.intent.allowed_tools }
              : {}),
          },
        }
      : {}),
  };
}

describe("policyDocumentToDict parity helper", () => {
  it("round-trips through parse", () => {
    const doc = parsePaybondPolicyDocument(TRAVEL_POLICY);
    expect(policyDocumentToDict(doc)).toEqual(TRAVEL_POLICY);
  });
});
