import { describe, expect, it } from "vitest";

import {
  createCheckoutWithBinding,
  mergeBindingIntoCheckoutPayload,
} from "../../src/shopify/checkout.js";
import { PAYBOND_UCP_AGENT_PROFILE_URL } from "../../src/shopify/types.js";

describe("shopify checkout binding", () => {
  it("injects canonical note_attributes and profile meta", () => {
    const payload = createCheckoutWithBinding({
      tenantId: "tenant-a",
      intentId: "00000000-0000-0000-0000-000000000111",
      lineItems: [{ variantId: "12345", quantity: 2 }],
    });

    expect(payload.line_items).toEqual([
      { item: { id: "gid://shopify/ProductVariant/12345" }, quantity: 2 },
    ]);
    expect(payload.note_attributes).toEqual([
      { name: "tenant_id", value: "tenant-a" },
      { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
    ]);
    expect(payload.meta?.profile_url).toBe(PAYBOND_UCP_AGENT_PROFILE_URL);
    expect(PAYBOND_UCP_AGENT_PROFILE_URL).toBe("https://paybond.ai/.well-known/ucp/profile.json");
  });

  it("preserves unknown note attributes while injecting binding", () => {
    const payload = createCheckoutWithBinding({
      tenantId: "tenant-a",
      intentId: "00000000-0000-0000-0000-000000000111",
      lineItems: [{ variantId: "gid://shopify/ProductVariant/99", quantity: 1 }],
      existingNoteAttributes: [{ name: "gift_message", value: "thanks" }],
      cartId: "cart_abc",
      agentProfileUrl: "https://example.test/profile.json",
    });

    expect(payload.cart_id).toBe("cart_abc");
    expect(payload.note_attributes).toEqual([
      { name: "gift_message", value: "thanks" },
      { name: "tenant_id", value: "tenant-a" },
      { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
    ]);
    expect(payload.meta?.profile_url).toBe("https://example.test/profile.json");
  });

  it("merges binding into update_checkout payloads", () => {
    const merged = mergeBindingIntoCheckoutPayload(
      { tenantId: "tenant-a", intentId: "00000000-0000-0000-0000-000000000111" },
      {
        note_attributes: [{ name: "buyer_note", value: "leave at door" }],
        shipping_address: { city: "Austin" },
      },
    );

    expect(merged.note_attributes).toEqual([
      { name: "buyer_note", value: "leave at door" },
      { name: "tenant_id", value: "tenant-a" },
      { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
    ]);
    expect(merged.shipping_address).toEqual({ city: "Austin" });
  });
});
