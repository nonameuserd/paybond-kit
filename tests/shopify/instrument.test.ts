import { describe, expect, it } from "vitest";

import {
  assertNotShopifyFundingWebhook,
  mapShopifyToolResultToEvidence,
} from "../../src/shopify/evidence.js";
import { createGuardedShopifyCheckoutHandler } from "../../src/shopify/instrument.js";

describe("shopify commerce evidence", () => {
  it("maps checkout tool results to cost_and_completion evidence", () => {
    const evidence = mapShopifyToolResultToEvidence(
      {
        status: "completed",
        cost_cents: 4500,
        order_id: "gid://shopify/Order/123",
        shop: "paybond-agent-commerce-dev.myshopify.com",
      },
      { preset: "cost_and_completion" },
    );

    expect(evidence).toEqual({ status: "completed", cost_cents: 4500 });
  });

  it("rejects Shopify funding webhook envelopes", () => {
    expect(() =>
      assertNotShopifyFundingWebhook({
        topic: "orders/paid",
        "X-Shopify-Shop-Domain": "demo.myshopify.com",
        "X-Shopify-Webhook-Id": "wh_1",
      }),
    ).toThrow(/funding signals/);
  });
});

describe("shopify instrument wrapper", () => {
  it("injects binding before executing checkout", async () => {
    const binding = { tenantId: "tenant-a", intentId: "00000000-0000-0000-0000-000000000111" };
    const handler = createGuardedShopifyCheckoutHandler({
      binding: () => binding,
      executeCheckout: async (input) => {
        expect(input.checkoutPayload.note_attributes).toEqual([
          { name: "tenant_id", value: "tenant-a" },
          { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
        ]);
        return {
          status: "completed",
          cost_cents: input.amountCents,
          order_id: "gid://shopify/Order/123",
          shop: input.shopDomain,
        };
      },
    });

    const result = await handler({
      shopDomain: "paybond-agent-commerce-dev.myshopify.com",
      lineItems: [{ variantId: "123", quantity: 1 }],
      amountCents: 4500,
    });

    expect(result.status).toBe("completed");
    expect(result.cost_cents).toBe(4500);
  });

  it("fails closed when Paybond binding is missing", async () => {
    const handler = createGuardedShopifyCheckoutHandler({
      binding: () => ({ tenantId: "", intentId: "" }),
      executeCheckout: async () => ({
        status: "completed",
        cost_cents: 1,
        shop: "demo.myshopify.com",
      }),
    });

    await expect(
      handler({
        shopDomain: "demo.myshopify.com",
        lineItems: [{ variantId: "1", quantity: 1 }],
        amountCents: 100,
      }),
    ).rejects.toThrow(/Paybond session binding is required/);
  });
});
