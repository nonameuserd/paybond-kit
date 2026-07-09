import { describe, expect, it } from "vitest";

import {
  decodeCommerceBindingFromShopifyNoteAttributes,
  decodeCommerceBindingFromStripeMetadata,
  encodeCommerceBindingToShopifyNoteAttributes,
  encodeCommerceBindingToStripeMetadata,
  PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY,
  PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY,
} from "../src/commerce-binding.js";

describe("commerce-binding", () => {
  it("encodes canonical keys into Stripe metadata", () => {
    const metadata = encodeCommerceBindingToStripeMetadata({
      tenantId: "tenant-a",
      intentId: "00000000-0000-0000-0000-000000000111",
    });
    expect(metadata).toEqual({
      [PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY]: "tenant-a",
      [PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY]: "00000000-0000-0000-0000-000000000111",
    });
  });

  it("merges into existing Stripe metadata and preserves unknown keys", () => {
    const metadata = encodeCommerceBindingToStripeMetadata(
      {
        tenantId: "tenant-a",
        intentId: "00000000-0000-0000-0000-000000000111",
      },
      { foo: "bar" },
    );
    expect(metadata.foo).toBe("bar");
    expect(metadata.tenant_id).toBe("tenant-a");
  });

  it("rejects collisions in existing Stripe metadata", () => {
    expect(() =>
      encodeCommerceBindingToStripeMetadata(
        { tenantId: "tenant-a", intentId: "intent-a" },
        { tenant_id: "tenant-b" },
      ),
    ).toThrow(/tenant_id collision/);
  });

  it("decodes from Stripe metadata when keys are present", () => {
    const binding = decodeCommerceBindingFromStripeMetadata({
      tenant_id: "tenant-a",
      paybond_intent_id: "intent-a",
    });
    expect(binding).toEqual({ tenantId: "tenant-a", intentId: "intent-a" });
  });

  it("returns null when Stripe metadata is missing binding keys", () => {
    expect(decodeCommerceBindingFromStripeMetadata({})).toBeNull();
    expect(decodeCommerceBindingFromStripeMetadata({ tenant_id: "tenant-a" })).toBeNull();
  });

  it("encodes canonical keys into Shopify note_attributes and preserves unknown attributes", () => {
    const attrs = encodeCommerceBindingToShopifyNoteAttributes(
      { tenantId: "tenant-a", intentId: "intent-a" },
      [{ name: "foo", value: "bar" }],
    );
    expect(attrs).toEqual([
      { name: "foo", value: "bar" },
      { name: "tenant_id", value: "tenant-a" },
      { name: "paybond_intent_id", value: "intent-a" },
    ]);
  });

  it("rejects collisions in existing Shopify note_attributes", () => {
    expect(() =>
      encodeCommerceBindingToShopifyNoteAttributes(
        { tenantId: "tenant-a", intentId: "intent-a" },
        [{ name: "tenant_id", value: "tenant-b" }],
      ),
    ).toThrow(/tenant_id collision/);
  });

  it("decodes from Shopify note_attributes when keys are present", () => {
    const binding = decodeCommerceBindingFromShopifyNoteAttributes([
      { name: "foo", value: "bar" },
      { name: "tenant_id", value: "tenant-a" },
      { name: "paybond_intent_id", value: "intent-a" },
    ]);
    expect(binding).toEqual({ tenantId: "tenant-a", intentId: "intent-a" });
  });

  it("returns null when Shopify note_attributes is missing binding keys", () => {
    expect(decodeCommerceBindingFromShopifyNoteAttributes([])).toBeNull();
    expect(
      decodeCommerceBindingFromShopifyNoteAttributes([{ name: "tenant_id", value: "tenant-a" }]),
    ).toBeNull();
  });

  it("rejects conflicting duplicates in Shopify note_attributes", () => {
    expect(() =>
      decodeCommerceBindingFromShopifyNoteAttributes([
        { name: "tenant_id", value: "tenant-a" },
        { name: "tenant_id", value: "tenant-b" },
        { name: "paybond_intent_id", value: "intent-a" },
      ]),
    ).toThrow(/tenant_id collision/);
  });
});

