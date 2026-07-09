/**
 * Shopify shopping agent — guarded `commerce.checkout` with binding injection.
 *
 * Uses `instrumentShopifyCheckout` from @paybond/kit. No live LLM required for sandbox smoke.
 */
import {
  instrumentShopifyCheckout,
  mapShopifyToolResultToEvidence,
  type ShopifyCheckoutExecuteInput,
  type ShopifyCheckoutToolResult,
} from "@paybond/kit";
import { createPaybondClient } from "./paybond.config.js";

const REQUESTED_SPEND_CENTS = 4500;
const SHOP_DOMAIN = process.env.SHOPIFY_DEV_STORE?.trim() ?? "paybond-agent-commerce-dev.myshopify.com";

async function executeCheckout(input: ShopifyCheckoutExecuteInput): Promise<ShopifyCheckoutToolResult> {
  // Offline demo path — replace with UCP Checkout MCP call using input.checkoutPayload.
  return {
    status: "completed",
    cost_cents: input.amountCents,
    order_id: "gid://shopify/Order/123",
    shop: input.shopDomain,
  };
}

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const bindingRef = { tenantId: "", intentId: "" };
    const instrumented = await instrumentShopifyCheckout(paybond, {
      policy: "./paybond.policy.yaml",
      framework: "generic",
      executeCheckout,
      bindingRef,
      sandbox: true,
    });

    bindingRef.tenantId = instrumented.run.tenantId;
    bindingRef.intentId = instrumented.run.intentId;

    const tool = instrumented.tools.find((entry) => entry.name === "commerce.checkout");
    if (!tool) {
      throw new Error("missing commerce.checkout tool");
    }

    const result = await tool.execute({
      toolName: "commerce.checkout",
      toolCallId: "shopify-demo-1",
      arguments: {
        shopDomain: SHOP_DOMAIN,
        lineItems: [{ variantId: "gid://shopify/ProductVariant/1", quantity: 1 }],
        amountCents: REQUESTED_SPEND_CENTS,
      },
    });

    const toolResult =
      typeof result.toolResult === "object" && result.toolResult !== null
        ? (result.toolResult as Record<string, unknown>)
        : {};

    console.log(
      JSON.stringify(
        {
          runId: instrumented.run.runId,
          intentId: instrumented.run.intentId,
          tenantId: instrumented.run.tenantId,
          authorization: result.authorization,
          evidence: result.evidence,
          mappedEvidence: mapShopifyToolResultToEvidence(toolResult, {
            preset: "cost_and_completion",
          }),
          toolResult: result.toolResult,
        },
        null,
        2,
      ),
    );
  } finally {
    await paybond.aclose();
  }
}

void main();
