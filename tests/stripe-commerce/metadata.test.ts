import { describe, expect, it } from "vitest";

import {
  buildPaybondStripeMetadata,
  PAYBOND_STRIPE_METADATA_INTENT_ID_KEY,
  PAYBOND_STRIPE_METADATA_RAIL_KEY,
  PAYBOND_STRIPE_METADATA_TENANT_ID_KEY,
} from "../../src/stripe-commerce/metadata.js";

describe("stripe-commerce metadata", () => {
  it("builds canonical Harbor webhook metadata keys", () => {
    const metadata = buildPaybondStripeMetadata({
      tenantId: "tenant-a",
      intentId: "00000000-0000-0000-0000-000000000111",
    });
    expect(metadata).toEqual({
      [PAYBOND_STRIPE_METADATA_TENANT_ID_KEY]: "tenant-a",
      [PAYBOND_STRIPE_METADATA_INTENT_ID_KEY]: "00000000-0000-0000-0000-000000000111",
    });
  });

  it("includes settlement rail when provided", () => {
    const metadata = buildPaybondStripeMetadata({
      tenantId: "tenant-a",
      intentId: "00000000-0000-0000-0000-000000000111",
      rail: "stripe_connect",
    });
    expect(metadata[PAYBOND_STRIPE_METADATA_RAIL_KEY]).toBe("stripe_connect");
  });

  it("trims tenant and intent ids", () => {
    const metadata = buildPaybondStripeMetadata({
      tenantId: "  tenant-a  ",
      intentId: "  00000000-0000-0000-0000-000000000111  ",
    });
    expect(metadata.tenant_id).toBe("tenant-a");
    expect(metadata.paybond_intent_id).toBe("00000000-0000-0000-0000-000000000111");
  });

  it("rejects empty tenant id", () => {
    expect(() =>
      buildPaybondStripeMetadata({
        tenantId: "   ",
        intentId: "00000000-0000-0000-0000-000000000111",
      }),
    ).toThrow(/tenantId is required/);
  });

  it("rejects empty intent id", () => {
    expect(() =>
      buildPaybondStripeMetadata({
        tenantId: "tenant-a",
        intentId: "",
      }),
    ).toThrow(/intentId is required/);
  });

  it("rejects unknown settlement rails", () => {
    expect(() =>
      buildPaybondStripeMetadata({
        tenantId: "tenant-a",
        intentId: "00000000-0000-0000-0000-000000000111",
        rail: "stripe_mpp" as "stripe_connect",
      }),
    ).toThrow(/rail must be stripe_connect or stripe_ach_debit/);
  });
});
