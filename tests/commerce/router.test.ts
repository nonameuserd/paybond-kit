import { describe, expect, it, vi } from "vitest";

import {
  COMMERCE_CHECKOUT_MAPPER_VERSION,
  createCommerceCheckoutRouter,
  createShopifyCommerceProvider,
  createStripeCommerceProvider,
  createZincCommerceProvider,
  deriveZincProductsCostCents,
  mapCommerceCheckoutResultToEvidence,
  resolveCommerceCheckoutProvider,
} from "../../src/commerce/index.js";

describe("commerce checkout evidence", () => {
  it("maps results to cost_and_completion evidence", () => {
    const evidence = mapCommerceCheckoutResultToEvidence(
      {
        status: "completed",
        cost_cents: 2500,
        provider: "zinc",
        order_id: "zinc_sandbox_ord_amazon_B00TEST",
        zinc_request_id: "req_ignored",
      },
      { preset: "cost_and_completion" },
    );

    expect(evidence).toEqual({
      status: "completed",
      cost_cents: 2500,
      provider: "zinc",
      order_id: "zinc_sandbox_ord_amazon_B00TEST",
    });
    expect(COMMERCE_CHECKOUT_MAPPER_VERSION).toBe("commerce_checkout_v1");
  });

  it("rejects missing cost_cents", () => {
    expect(() =>
      mapCommerceCheckoutResultToEvidence(
        { status: "completed", provider: "stripe" },
        { preset: "cost_and_completion" },
      ),
    ).toThrow(/missing cost_cents/);
  });

  it("rejects explicit null cost_cents and does not fall back to amount_cents", () => {
    expect(() =>
      mapCommerceCheckoutResultToEvidence(
        { status: "completed", cost_cents: null, amount_cents: 9999 },
        { preset: "cost_and_completion" },
      ),
    ).toThrow(/missing cost_cents/);
  });

  it("does not invent cost_cents from amount_cents alone", () => {
    expect(() =>
      mapCommerceCheckoutResultToEvidence(
        { status: "completed", amount_cents: 4500 },
        { preset: "cost_and_completion" },
      ),
    ).toThrow(/missing cost_cents/);
  });
});

describe("createCommerceCheckoutRouter", () => {
  const binding = {
    tenantId: "tenant-a",
    intentId: "00000000-0000-0000-0000-000000000111",
  };

  it("routes to default provider and injects Shopify binding", async () => {
    const executeCheckout = vi.fn(async (input) => {
      expect(input.tenantId).toBe("tenant-a");
      expect(input.intentId).toBe("00000000-0000-0000-0000-000000000111");
      expect(input.checkoutPayload.note_attributes).toEqual([
        { name: "buyer_note", value: "leave at door" },
        { name: "tenant_id", value: "tenant-a" },
        { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
      ]);
      // Executor top-level noteAttributes must be the bound set, not unbound client attrs.
      expect(input.noteAttributes).toEqual(input.checkoutPayload.note_attributes);
      return {
        status: "completed" as const,
        cost_cents: input.amountCents,
        order_id: "gid://shopify/Order/123",
        shop: input.shopDomain,
      };
    });

    const shopify = createShopifyCommerceProvider({ executeCheckout });
    const checkout = createCommerceCheckoutRouter({
      providers: { shopify },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    const result = await checkout({
      amountCents: 4500,
      shopify: {
        shopDomain: "paybond-agent-commerce-dev.myshopify.com",
        lineItems: [{ variantId: "123", quantity: 1 }],
        noteAttributes: [{ name: "buyer_note", value: "leave at door" }],
      },
    });

    expect(result).toMatchObject({
      status: "completed",
      cost_cents: 4500,
      provider: "shopify",
      order_id: "gid://shopify/Order/123",
      shop: "paybond-agent-commerce-dev.myshopify.com",
    });
    expect(executeCheckout).toHaveBeenCalledOnce();
  });

  it("fails closed when Shopify executor returns undefined cost_cents", async () => {
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () =>
        ({
          status: "completed",
          shop: "demo.myshopify.com",
        }) as never,
    });
    const checkout = createCommerceCheckoutRouter({
      providers: { shopify },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    await expect(
      checkout({
        amountCents: 4500,
        shopify: {
          shopDomain: "demo.myshopify.com",
          lineItems: [{ variantId: "123", quantity: 1 }],
        },
      }),
    ).rejects.toThrow(/cost_cents/);
  });

  it("routes explicitly to stripe and stamps metadata", async () => {
    const executeCheckout = vi.fn(async (input) => {
      expect(input.metadata).toMatchObject({
        tenant_id: "tenant-a",
        paybond_intent_id: "00000000-0000-0000-0000-000000000111",
        paybond_settlement_rail: "stripe_connect",
      });
      return {
        status: "completed" as const,
        cost_cents: input.amountCents,
        payment_intent_id: "pi_test_123",
      };
    });

    const stripe = createStripeCommerceProvider({ executeCheckout });
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () => {
        throw new Error("shopify should not run");
      },
    });

    const checkout = createCommerceCheckoutRouter({
      providers: { shopify, stripe },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    const result = await checkout({
      provider: "stripe",
      amountCents: 1999,
      stripe: {
        rail: "stripe_connect",
        description: "agent cart",
      },
    });

    expect(result).toMatchObject({
      status: "completed",
      cost_cents: 1999,
      provider: "stripe",
      payment_intent_id: "pi_test_123",
      order_id: "pi_test_123",
    });
  });

  it("runs zinc sandbox with product-derived cost_cents", async () => {
    const zinc = createZincCommerceProvider({
      mode: "sandbox",
      sandboxOrderIdPrefix: "zinc_test_",
    });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => binding,
    });

    const result = await checkout({
      amountCents: 3200,
      zinc: {
        retailer: "amazon",
        products: [{ product_id: "B00TEST", quantity: 1, price_cents: 3200 }],
        max_price_cents: 5000,
      },
    });

    expect(result.status).toBe("completed");
    expect(result.cost_cents).toBe(3200);
    expect(result.provider).toBe("zinc");
    expect(result.order_id).toBe("zinc_test_ord_amazon_B00TEST");
    expect(result.zinc_request_id).toMatch(/^zinc_test_/);
  });

  it("fails zinc sandbox when product-derived cost exceeds max_price_cents", async () => {
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => binding,
    });

    const result = await checkout({
      amountCents: 9000,
      zinc: {
        retailer: "amazon",
        products: [{ product_id: "B00TEST", quantity: 1, price_cents: 9000 }],
        max_price_cents: 5000,
      },
    });

    expect(result.status).toBe("failed");
    expect(result.cost_cents).toBe(0);
  });

  it("rejects zinc sandbox under-reported amountCents", async () => {
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => binding,
    });

    await expect(
      checkout({
        amountCents: 1000,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00TEST", quantity: 2, price_cents: 1500 }],
        },
      }),
    ).rejects.toThrow(/must equal product-derived cost_cents \(3000\)/);
  });

  it("rejects zinc sandbox over-reported amountCents", async () => {
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => binding,
    });

    await expect(
      checkout({
        amountCents: 5000,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00TEST", quantity: 1, price_cents: 3200 }],
        },
      }),
    ).rejects.toThrow(/must equal product-derived cost_cents \(3200\)/);
  });

  it("rejects invalid zinc max_price_cents", async () => {
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => binding,
    });

    await expect(
      checkout({
        amountCents: 100,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00", quantity: 1, price_cents: 100 }],
          max_price_cents: -1,
        },
      }),
    ).rejects.toThrow(/max_price_cents/);
  });

  it("rejects unknown provider", async () => {
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () => ({
        status: "completed",
        cost_cents: 1,
        shop: "demo.myshopify.com",
      }),
    });
    const checkout = createCommerceCheckoutRouter({
      providers: { shopify },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    await expect(
      checkout({
        // @ts-expect-error intentional unknown provider
        provider: "ebay",
        amountCents: 100,
      }),
    ).rejects.toThrow(/unknown provider/);
  });

  it("rejects blank provider instead of falling back to default", async () => {
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () => ({
        status: "completed",
        cost_cents: 1,
        shop: "demo.myshopify.com",
      }),
    });
    const checkout = createCommerceCheckoutRouter({
      providers: { shopify },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    await expect(
      checkout({
        // @ts-expect-error intentional blank provider
        provider: "",
        amountCents: 100,
        shopify: {
          shopDomain: "demo.myshopify.com",
          lineItems: [{ variantId: "1", quantity: 1 }],
        },
      }),
    ).rejects.toThrow(/unknown provider/);
  });

  it("rejects missing adapter for selected provider", async () => {
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () => ({
        status: "completed",
        cost_cents: 1,
        shop: "demo.myshopify.com",
      }),
    });
    const checkout = createCommerceCheckoutRouter({
      providers: { shopify },
      defaultProvider: "shopify",
      binding: () => binding,
    });

    await expect(
      checkout({
        provider: "zinc",
        amountCents: 100,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00", quantity: 1, price_cents: 100 }],
        },
      }),
    ).rejects.toThrow(/no adapter registered/);
  });

  it("fails closed when Paybond binding is missing", async () => {
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const checkout = createCommerceCheckoutRouter({
      providers: { zinc },
      defaultProvider: "zinc",
      binding: () => ({ tenantId: "", intentId: "" }),
    });

    await expect(
      checkout({
        amountCents: 100,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00", quantity: 1, price_cents: 100 }],
        },
      }),
    ).rejects.toThrow(/Paybond session binding is required/);
  });

  it("requires defaultProvider adapter at construction", () => {
    expect(() =>
      createCommerceCheckoutRouter({
        providers: {},
        defaultProvider: "shopify",
        binding: () => binding,
      }),
    ).toThrow(/defaultProvider/);
  });
});

describe("deriveZincProductsCostCents", () => {
  it("sums unit price times quantity", () => {
    expect(
      deriveZincProductsCostCents([
        { product_id: "A", quantity: 2, price_cents: 1500 },
        { product_id: "B", quantity: 1, price_cents: 200 },
      ]),
    ).toBe(3200);
  });
});

describe("resolveCommerceCheckoutProvider", () => {
  it("selects explicit provider over default", () => {
    const shopify = createShopifyCommerceProvider({
      executeCheckout: async () => ({
        status: "completed",
        cost_cents: 1,
        shop: "demo.myshopify.com",
      }),
    });
    const zinc = createZincCommerceProvider({ mode: "sandbox" });
    const resolved = resolveCommerceCheckoutProvider(
      { provider: "zinc", amountCents: 1 },
      { providers: { shopify, zinc }, defaultProvider: "shopify" },
    );
    expect(resolved.providerId).toBe("zinc");
  });
});

describe("createZincCommerceProvider live mode", () => {
  it("requires httpClient in live mode", () => {
    expect(() => createZincCommerceProvider({ mode: "live" })).toThrow(/httpClient/);
  });

  it("rejects unknown mode instead of falling through to live httpClient", () => {
    expect(() =>
      createZincCommerceProvider({
        // @ts-expect-error intentional invalid mode
        mode: "staging",
        httpClient: async () => {
          throw new Error("httpClient must not run");
        },
      }),
    ).toThrow(/mode must be "sandbox" or "live"/);
  });

  it("rejects Live and production mode strings", () => {
    expect(() =>
      createZincCommerceProvider({
        // @ts-expect-error intentional invalid casing
        mode: "Live",
      }),
    ).toThrow(/mode must be "sandbox" or "live"/);
    expect(() =>
      createZincCommerceProvider({
        // @ts-expect-error intentional invalid mode
        mode: "production",
      }),
    ).toThrow(/mode must be "sandbox" or "live"/);
  });

  it("delegates to pluggable httpClient without default network", async () => {
    const httpClient = vi.fn(async (request) => {
      expect(request.tenantId).toBe("tenant-a");
      expect(request.intentId).toBe("00000000-0000-0000-0000-000000000111");
      return {
        status: "completed" as const,
        cost_cents: 2200,
        order_id: "live_ord_1",
        zinc_request_id: "req_live_1",
      };
    });

    const zinc = createZincCommerceProvider({ mode: "live", httpClient });
    const result = await zinc.checkout(
      {
        amountCents: 1100,
        zinc: {
          retailer: "amazon",
          products: [{ product_id: "B00LIVE", quantity: 2 }],
        },
      },
      {
        tenantId: "tenant-a",
        intentId: "00000000-0000-0000-0000-000000000111",
      },
    );

    expect(result).toMatchObject({
      status: "completed",
      cost_cents: 2200,
      provider: "zinc",
      order_id: "live_ord_1",
      zinc_request_id: "req_live_1",
    });
    expect(httpClient).toHaveBeenCalledOnce();
  });
});
