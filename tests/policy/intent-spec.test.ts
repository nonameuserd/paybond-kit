import { describe, expect, it } from "vitest";

import { getCompletionPreset } from "../../src/completion-catalog.js";
import { PaybondPolicy, PaybondPolicyIntentSpecError } from "../../src/policy/index.js";
import {
  buildSignedCreateIntentBodyWithPolicyBinding,
  type PublishedPolicyHead,
} from "../../src/principal-intent.js";

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
      version_seq: 3,
      head_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
    budget: {
      currency: "usd",
      max_spend_usd: 200,
    },
    allowed_tools: ["travel.book_hotel"],
  },
} as const;

const PRINCIPAL_SEED = new Uint8Array(32).fill(1);
const PAYEE_SEED = new Uint8Array(32).fill(2);

const PUBLISHED_HEAD: PublishedPolicyHead = {
  templateId: "travel_agent_template",
  versionSeq: 3,
  materializedPredicate: { all: [{ field: "status", eq: "ok" }] },
  policyContentDigestHex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
};

function baseOverrides() {
  return {
    principalDid: "did:paybond:principal",
    principalSigningSeed: PRINCIPAL_SEED,
    payeeDid: "did:paybond:payee",
    payeeSigningSeed: PAYEE_SEED,
    deadlineRfc3339: "2026-12-31T23:59:59Z",
    settlementRail: "stripe_connect" as const,
    recognitionProof: { kind: "test" },
    publishedPolicyHead: PUBLISHED_HEAD,
  };
}

describe("policyToIntentCreateInput", () => {
  it("maps policy intent alignment to createWithPolicyBinding params", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    const input = policy.toIntentCreateInput(baseOverrides());

    expect(input.allowedTools).toEqual(["travel.book_hotel"]);
    expect(input.currency).toBe("usd");
    expect(input.amountCents).toBe(20000);
    expect(input.budget.max).toBe(20000);
    expect(input.policyBinding).toEqual({
      templateId: "travel_agent_template",
      versionSeq: 3,
    });
    expect(input.completionPresetId).toBe("cost_and_completion");
    expect(input.evidenceSchema).toEqual(
      getCompletionPreset("cost_and_completion").evidence_schema,
    );
  });

  it("resolves custom Harbor operations from tool registry entries", async () => {
    const policy = await PaybondPolicy.load({
      version: 1,
      name: "ops-v1",
      default_deny: true,
      tools: {
        book_hotel: {
          side_effecting: true,
          operation: "travel.book_hotel",
          evidence_preset: "cost_and_completion",
        },
      },
      intent: {
        policy_binding: {
          template_id: "travel_agent_template",
          version_seq: 3,
        },
        allowed_tools: ["book_hotel"],
      },
    });

    const input = policy.toIntentCreateInput({
      ...baseOverrides(),
      amountCents: 5000,
      currency: "usd",
      budget: { max: 5000 },
    });

    expect(input.allowedTools).toEqual(["travel.book_hotel"]);
  });

  it("builds a signing-v7 Harbor body compatible with the existing create flow", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    const input = policy.toIntentCreateInput({
      ...baseOverrides(),
      intentId: "00000000-0000-4000-8000-000000000001",
    });

    const body = buildSignedCreateIntentBodyWithPolicyBinding({
      tenantId: "tenant-1",
      intentId: input.intentId!,
      principalDid: input.principalDid,
      principalSigningSeed: input.principalSigningSeed,
      payeeDid: input.payeeDid,
      payeeSigningSeed: input.payeeSigningSeed,
      budget: input.budget,
      currency: input.currency,
      amountCents: input.amountCents,
      evidenceSchema: input.evidenceSchema,
      deadlineRfc3339: input.deadlineRfc3339,
      allowedTools: input.allowedTools,
      settlementRail: input.settlementRail,
      policyBinding: input.policyBinding,
      publishedPolicyHead: input.publishedPolicyHead,
      completionPresetId: input.completionPresetId,
      completionContract: input.completionContract,
    });

    expect(body.signing_version).toBe(7);
    expect(body.policy_binding).toEqual({
      template_id: "travel_agent_template",
      version_seq: 3,
    });
    expect(body.allowed_tools).toEqual(["travel.book_hotel"]);
    expect(body.completion_preset_id).toBe("cost_and_completion");
  });

  it("rejects mismatched published policy head digests", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);

    expect(() =>
      policy.toIntentCreateInput({
        ...baseOverrides(),
        publishedPolicyHead: {
          ...PUBLISHED_HEAD,
          policyContentDigestHex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      }),
    ).toThrow(PaybondPolicyIntentSpecError);
  });

  it("requires policy intent.policy_binding", async () => {
    const policy = await PaybondPolicy.load({
      version: 1,
      name: "no-binding",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          evidence_preset: "cost_and_completion",
        },
      },
      intent: {
        allowed_tools: ["travel.book_hotel"],
      },
    });

    expect(() => policy.toIntentCreateInput(baseOverrides())).toThrow(
      PaybondPolicyIntentSpecError,
    );
  });
});
