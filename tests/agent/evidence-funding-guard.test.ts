import { describe, expect, it } from "vitest";

import {
  assertToolResultNotFundingWebhook,
  buildAutoEvidencePayload,
} from "../../src/agent/evidence.js";
import { jsonValueDigest } from "../../src/json-digest.js";
import { mapStripeToolResultToEvidence } from "../../src/stripe-commerce/evidence.js";

const SAMPLE_CHARGE_RESULT = {
  payment_intent_id: "pi_3NxExample",
  charge_id: "ch_3NxExample",
  cost_cents: 1250,
  status: "succeeded",
};

const FUNDING_WEBHOOK = {
  id: "evt_123",
  object: "event",
  type: "payment_intent.succeeded",
  data: {
    object: {
      id: "pi_123",
      metadata: {
        tenant_id: "tenant-a",
        paybond_intent_id: "00000000-0000-0000-0000-000000000111",
      },
    },
  },
};

describe("agent auto-evidence funding guard", () => {
  it("rejects Stripe funding webhook payloads used as completion evidence", () => {
    expect(() => assertToolResultNotFundingWebhook(FUNDING_WEBHOOK)).toThrow(/funding signals/);
    expect(() =>
      buildAutoEvidencePayload(
        { evidencePreset: "stripe_charge" },
        FUNDING_WEBHOOK,
        {
          toolName: "payments.charge_customer",
          toolCallId: "call-1",
          operation: "payments.charge_customer",
          arguments: {},
        },
      ),
    ).toThrow(/funding signals/);
  });

  it("accepts legitimate stripe_charge tool results", () => {
    const mapped = mapStripeToolResultToEvidence(SAMPLE_CHARGE_RESULT, {
      preset: "stripe_charge",
    });
    const expectedDigest = `blake3:${Buffer.from(
      jsonValueDigest({ charge_id: "ch_3NxExample", cost_cents: 1250 }),
    ).toString("hex")}`;
    expect(mapped).toEqual({
      charge_id: "ch_3NxExample",
      http_status: 200,
      response_digest: expectedDigest,
    });

    const payload = buildAutoEvidencePayload(
      { evidencePreset: "cost_and_completion" },
      { status: "ok", cost_cents: 100 },
      { toolName: "paid-tool", toolCallId: "call-2", operation: "paid-tool", arguments: {} },
    );
    expect(payload).toEqual({ status: "ok", cost_cents: 100 });
  });

  it("accepts mapped stripe_charge evidence objects", () => {
    const mapped = mapStripeToolResultToEvidence(SAMPLE_CHARGE_RESULT, {
      preset: "stripe_charge",
    });
    expect(() => assertToolResultNotFundingWebhook(mapped)).not.toThrow();
  });
});
