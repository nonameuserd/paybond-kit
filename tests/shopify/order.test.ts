import { describe, expect, it } from "vitest";

import { getOrder } from "../../src/shopify/order.js";

describe("shopify getOrder", () => {
  it("parses UCP order/get responses and decodes binding metadata", async () => {
    const summary = await getOrder({
      shopDomain: "paybond-agent-commerce-dev.myshopify.com",
      orderId: "123",
      fetchUcp: async () =>
        new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            id: "paybond-kit-get-order",
            result: {
              id: "gid://shopify/Order/123",
              financial_status: "authorized",
              note_attributes: [
                { name: "tenant_id", value: "tenant-a" },
                { name: "paybond_intent_id", value: "00000000-0000-0000-0000-000000000111" },
              ],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });

    expect(summary.order_id).toBe("gid://shopify/Order/123");
    expect(summary.financial_status).toBe("authorized");
    expect(summary.binding).toEqual({
      tenant_id: "tenant-a",
      paybond_intent_id: "00000000-0000-0000-0000-000000000111",
    });
  });
});
