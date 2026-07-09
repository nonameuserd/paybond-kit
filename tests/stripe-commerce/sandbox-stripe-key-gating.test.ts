import { afterEach, describe, expect, it } from "vitest";

import {
  mockChargeCustomer,
  resolveSandboxStripeTestKey,
} from "../../templates/paybond-stripe-agent-demo/src/charge-customer.js";

const METADATA = {
  tenant_id: "tenant_demo",
  paybond_intent_id: "00000000-0000-0000-0000-000000000001",
};

describe("resolveSandboxStripeTestKey (stripe-agent-demo template)", () => {
  const originalStripeKey = process.env.STRIPE_SECRET_KEY;

  afterEach(() => {
    if (originalStripeKey === undefined) {
      delete process.env.STRIPE_SECRET_KEY;
    } else {
      process.env.STRIPE_SECRET_KEY = originalStripeKey;
    }
  });

  it("returns undefined when no secret is configured (offline mock default)", () => {
    delete process.env.STRIPE_SECRET_KEY;
    expect(resolveSandboxStripeTestKey("sandbox")).toBeUndefined();
    expect(resolveSandboxStripeTestKey("live")).toBeUndefined();
    expect(resolveSandboxStripeTestKey("unknown")).toBeUndefined();
  });

  it("returns sk_test_ key only when session environment is sandbox", () => {
    process.env.STRIPE_SECRET_KEY = "sk_test_demo";
    expect(resolveSandboxStripeTestKey("sandbox")).toBe("sk_test_demo");
  });

  it("refuses a secret when session environment is live (fail closed)", () => {
    process.env.STRIPE_SECRET_KEY = "sk_test_demo";
    expect(() => resolveSandboxStripeTestKey("live")).toThrow(/sandbox-only/i);
  });

  it("refuses a secret when session environment is unknown (fail closed)", () => {
    process.env.STRIPE_SECRET_KEY = "sk_test_demo";
    expect(() => resolveSandboxStripeTestKey("unknown")).toThrow(/sandbox-only/i);
  });

  it("rejects sk_live_ keys even in sandbox (fail closed)", () => {
    process.env.STRIPE_SECRET_KEY = "sk_live_should_never_charge";
    expect(() => resolveSandboxStripeTestKey("sandbox")).toThrow(/sk_test_/i);
  });

  it("mock charge path needs no Stripe secret", () => {
    delete process.env.STRIPE_SECRET_KEY;
    const result = mockChargeCustomer(METADATA, { amountCents: 2500 }, "intent-demo");
    expect(result.mode).toBe("mock");
    expect(result.payment_intent_id).toMatch(/^pi_mock_/);
    expect(result.metadata).toEqual(METADATA);
  });
});
