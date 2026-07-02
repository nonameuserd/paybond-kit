import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { PaybondPolicy } from "../../src/policy/index.js";

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

const TRAVEL_POLICY_YAML = `version: 1
name: travel-agent-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    max_spend_cents: 20000
    evidence_preset: cost_and_completion
    vendor_pack: travel_booking_v1
  search.web:
    side_effecting: false
intent:
  policy_binding:
    template_id: travel_agent_template
    head_digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  budget:
    currency: usd
    max_spend_usd: 200
  allowed_tools:
    - travel.book_hotel
`;

describe("PaybondPolicy.load", () => {
  it("loads and validates an in-memory policy object", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    expect(policy.name).toBe("travel-agent-v1");
    expect(policy.defaultDeny).toBe(true);
    expect(policy.intent?.allowed_tools).toEqual(["travel.book_hotel"]);
  });

  it("loads a policy YAML file from disk", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-"));
    const path = join(dir, "paybond.policy.yaml");
    await writeFile(path, TRAVEL_POLICY_YAML, "utf8");

    const policy = await PaybondPolicy.load(path);
    expect(policy.source).toBe(path);
    expect(policy.name).toBe("travel-agent-v1");
  });

  it("loads a policy JSON file from disk", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-"));
    const path = join(dir, "paybond.policy.json");
    await writeFile(path, JSON.stringify(TRAVEL_POLICY), "utf8");

    const policy = await PaybondPolicy.load(path);
    expect(policy.name).toBe("travel-agent-v1");
  });
});

describe("PaybondPolicy.toToolRegistry", () => {
  it("builds a side-effecting registry with fixed spend caps", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    const registry = policy.toToolRegistry();

    expect(registry.defaultDeny).toBe(true);
    expect(registry.isSideEffecting("travel.book_hotel")).toBe(true);
    expect(registry.isSideEffecting("search.web")).toBe(false);
    expect(registry.resolveSpendCents("travel.book_hotel", {})).toBe(20000);
    expect(registry.resolveOperation("travel.book_hotel")).toBe("travel.book_hotel");
    expect(registry.getSideEffectingEntry("travel.book_hotel")?.evidencePreset).toBe(
      "cost_and_completion",
    );
  });

  it("builds spend resolvers from spend_from_args JSON paths", async () => {
    const policy = await PaybondPolicy.load({
      version: 1,
      name: "spend-path-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          spend_from_args: "estimated_price_cents",
          evidence_preset: "cost_and_completion",
        },
      },
    });
    const registry = policy.toToolRegistry();

    expect(registry.resolveSpendCents("travel.book_hotel", { estimated_price_cents: 1500 })).toBe(
      1500,
    );
    expect(registry.resolveSpendCents("travel.book_hotel", {})).toBeUndefined();
  });

  it("maps custom Harbor operations when operation is set", async () => {
    const policy = await PaybondPolicy.load({
      version: 1,
      name: "ops-v1",
      default_deny: false,
      tools: {
        book_hotel: {
          side_effecting: true,
          operation: "travel.book_hotel",
          evidence_preset: "cost_and_completion",
        },
      },
    });
    const registry = policy.toToolRegistry();

    expect(registry.resolveOperation("book_hotel")).toBe("travel.book_hotel");
    expect(registry.sideEffectingOperations()).toEqual(["travel.book_hotel"]);
  });
});
