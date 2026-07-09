import { describe, expect, it } from "vitest";

import { jsonValueDigest } from "../../src/json-digest.js";
import {
  assertNotStripeFundingWebhook,
  mapStripeToolResultToEvidence,
} from "../../src/stripe-commerce/evidence.js";

const SAMPLE_TOOL_RESULT = {
  payment_intent_id: "pi_3NxExample",
  charge_id: "ch_3NxExample",
  cost_cents: 1250,
  status: "succeeded",
};

describe("stripe-commerce evidence", () => {
  it("maps SDK tool results to stripe_charge vendor evidence", () => {
    const evidence = mapStripeToolResultToEvidence(SAMPLE_TOOL_RESULT, {
      preset: "stripe_charge",
    });
    const expectedDigest = `blake3:${Buffer.from(
      jsonValueDigest({ charge_id: "ch_3NxExample", cost_cents: 1250 }),
    ).toString("hex")}`;
    expect(evidence).toEqual({
      charge_id: "ch_3NxExample",
      http_status: 200,
      response_digest: expectedDigest,
    });
  });

  it("maps SDK tool results to cost_and_completion evidence", () => {
    const evidence = mapStripeToolResultToEvidence(SAMPLE_TOOL_RESULT, {
      preset: "cost_and_completion",
    });
    expect(evidence).toEqual({
      status: "completed",
      cost_cents: 1250,
    });
  });

  it("accepts Stripe payment_intent SDK object shapes", () => {
    const evidence = mapStripeToolResultToEvidence(
      {
        id: "pi_3NxExample",
        object: "payment_intent",
        status: "succeeded",
        latest_charge: "ch_3NxExample",
        cost_cents: 500,
      },
      { preset: "stripe_charge" },
    );
    expect(evidence).toMatchObject({
      charge_id: "ch_3NxExample",
      http_status: 200,
    });
  });

  it("rejects payment_intent.succeeded webhook envelopes", () => {
    expect(() =>
      assertNotStripeFundingWebhook({
        id: "evt_123",
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
      }),
    ).toThrow(/funding signals/);
  });

  it("rejects webhook data.object envelopes without event type", () => {
    expect(() =>
      mapStripeToolResultToEvidence(
        {
          data: {
            object: {
              id: "pi_1",
              metadata: { tenant_id: "tenant-a" },
            },
          },
        },
        { preset: "stripe_charge" },
      ),
    ).toThrow(/data\.object envelopes are funding signals/);
  });

  it("rejects Stripe event object kind", () => {
    expect(() =>
      assertNotStripeFundingWebhook({
        object: "event",
        type: "charge.succeeded",
      }),
    ).toThrow(/funding signals/);
  });

  it("requires charge_id for stripe_charge preset", () => {
    expect(() =>
      mapStripeToolResultToEvidence(
        {
          payment_intent_id: "pi_123",
          cost_cents: 100,
          status: "succeeded",
        },
        { preset: "stripe_charge" },
      ),
    ).toThrow(/missing charge_id/);
  });
});
