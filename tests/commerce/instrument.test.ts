import { describe, expect, it, vi } from "vitest";

import {
  createGuardedCommerceCheckoutHandler,
  createShopifyCommerceProvider,
  createZincCommerceProvider,
} from "../../src/commerce/index.js";

describe("createGuardedCommerceCheckoutHandler", () => {
  it("injects binding before provider execution (instrument smoke)", async () => {
    const bindingRef = {
      tenantId: "tenant-smoke",
      intentId: "00000000-0000-0000-0000-000000000222",
    };

    const executeCheckout = vi.fn(async (input) => ({
      status: "completed" as const,
      cost_cents: input.amountCents,
      order_id: "gid://shopify/Order/999",
      shop: input.shopDomain,
    }));

    const shopify = createShopifyCommerceProvider({ executeCheckout });
    const zinc = createZincCommerceProvider({
      mode: "sandbox",
      sandboxOrderIdPrefix: "smoke_",
    });

    const checkout = createGuardedCommerceCheckoutHandler({
      providers: { shopify, zinc },
      defaultProvider: "shopify",
      binding: () => bindingRef,
    });

    const shopifyResult = await checkout({
      amountCents: 4500,
      shopify: {
        shopDomain: "paybond-agent-commerce-dev.myshopify.com",
        lineItems: [{ variantId: "gid://shopify/ProductVariant/1", quantity: 1 }],
      },
    });

    expect(shopifyResult.provider).toBe("shopify");
    expect(shopifyResult.cost_cents).toBe(4500);
    expect(executeCheckout.mock.calls[0]?.[0].checkoutPayload.note_attributes).toEqual([
      { name: "tenant_id", value: "tenant-smoke" },
      { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000222" },
    ]);

    const zincResult = await checkout({
      provider: "zinc",
      amountCents: 1800,
      zinc: {
        retailer: "amazon",
        products: [{ product_id: "B00SMOKE", quantity: 1, price_cents: 1800 }],
      },
    });

    expect(zincResult).toMatchObject({
      status: "completed",
      cost_cents: 1800,
      provider: "zinc",
      order_id: "smoke_ord_amazon_B00SMOKE",
    });
  });
});
