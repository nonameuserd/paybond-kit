import { describe, expect, it } from "vitest";

import { getCompletionPreset } from "../../src/completion-catalog.js";
import {
  PaybondPolicy,
  PaybondPolicySandboxBootstrapError,
  policySandboxBootstrap,
} from "../../src/policy/index.js";

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

describe("policySandboxBootstrap", () => {
  it("derives sandbox bootstrap from the first side-effecting tool by default", () => {
    const preset = getCompletionPreset("cost_and_completion");
    const bootstrap = policySandboxBootstrap(TRAVEL_POLICY);

    expect(bootstrap).toEqual({
      kind: "sandbox",
      operation: "travel.book_hotel",
      requestedSpendCents: 20_000,
      currency: "usd",
      evidenceSchema: preset.evidence_schema,
      completionPreset: "cost_and_completion",
      templateId: preset.harbor_template_id,
      parameters: preset.parameters,
    });
  });

  it("resolves bootstrap by explicit tool name and operation override", async () => {
    const policy = await PaybondPolicy.load({
      ...TRAVEL_POLICY,
      tools: {
        ...TRAVEL_POLICY.tools,
        "travel.book_hotel": {
          ...TRAVEL_POLICY.tools["travel.book_hotel"],
          operation: "travel.book_hotel.v2",
        },
      },
    });

    expect(policy.sandboxBootstrap({ toolName: "travel.book_hotel" }).operation).toBe(
      "travel.book_hotel.v2",
    );
    expect(policy.sandboxBootstrap({ operation: "travel.book_hotel.v2" }).operation).toBe(
      "travel.book_hotel.v2",
    );
  });

  it("rejects bootstrap when no side-effecting tools exist", () => {
    expect(() =>
      policySandboxBootstrap({
        version: 1,
        name: "read-only",
        default_deny: true,
        tools: {
          "search.web": { side_effecting: false },
        },
      }),
    ).toThrow(PaybondPolicySandboxBootstrapError);
  });
});
