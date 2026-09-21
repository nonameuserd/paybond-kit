/**
 * Multi-provider commerce.checkout agent — Shopify + Stripe + Zinc (sandbox).
 * Uses instrumentCommerceCheckout from @paybond/kit/commerce.
 * No live LLM or live merchant network required for the sandbox smoke path.
 */
import type {
  PaybondGenericToolCall,
  PaybondGenericWrappedToolDefinition,
} from "@paybond/kit";
import {
  createShopifyCommerceProvider,
  createStripeCommerceProvider,
  createZincCommerceProvider,
  instrumentCommerceCheckout,
  type CommerceCheckoutToolArgs,
  type CommerceCheckoutToolResult,
  type ShopifyCommerceCheckoutExecutor,
  type StripeCommerceCheckoutExecuteInput,
  type StripeCommerceCheckoutExecutor,
} from "@paybond/kit/commerce";
import { createPaybondClient } from "./paybond.config.js";

const PRIMARY_OPERATION = "commerce.checkout";
const REQUESTED_SPEND_CENTS = 4500;

/** Binding-injected input for the Shopify sandbox executor (parameters of the kit type). */
type ShopifyCommerceCheckoutExecuteInput = Parameters<ShopifyCommerceCheckoutExecutor>[0];

type CommerceCheckoutWrappedTool = PaybondGenericWrappedToolDefinition<
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult
>;

/**
 * Sandbox/generic instrument returns a `{ name, execute }[]` array at runtime,
 * while the public instrument type still reflects the pre-wrap tool record.
 */
function requireCommerceCheckoutTools(tools: unknown): CommerceCheckoutWrappedTool[] {
  if (!Array.isArray(tools)) {
    throw new Error(
      "expected generic { name, execute } tools after instrumentCommerceCheckout (sandbox)",
    );
  }
  return tools as CommerceCheckoutWrappedTool[];
}

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const shopifyExecuteCheckout: ShopifyCommerceCheckoutExecutor = async (
      input: ShopifyCommerceCheckoutExecuteInput,
    ) => ({
      status: "completed",
      cost_cents: input.amountCents,
      order_id: "gid://shopify/Order/demo",
      shop: input.shopDomain,
    });
    const shopify = createShopifyCommerceProvider({
      executeCheckout: shopifyExecuteCheckout,
    });

    const stripeExecuteCheckout: StripeCommerceCheckoutExecutor = async (
      input: StripeCommerceCheckoutExecuteInput,
    ) => ({
      status: "completed",
      cost_cents: input.amountCents,
      payment_intent_id: "pi_demo_sandbox",
    });
    const stripe = createStripeCommerceProvider({
      executeCheckout: stripeExecuteCheckout,
    });

    // Offline mock — no Zinc credentials or Gateway buy-proxy.
    const zinc = createZincCommerceProvider({
      mode: "sandbox",
      sandboxOrderIdPrefix: "zinc_sandbox_",
    });

    const instrumented = await instrumentCommerceCheckout(paybond, {
      policy: "./paybond.policy.yaml",
      providers: { shopify, stripe, zinc },
      defaultProvider: "zinc",
      sandbox: true,
      framework: "generic",
    });

    if (!("run" in instrumented)) {
      throw new Error("expected sandbox-bound runtime; pass sandbox: true");
    }

    // Tenant / intent from Paybond session bind — never from tool args.
    instrumented.bindingRef.tenantId = instrumented.run.tenantId;
    instrumented.bindingRef.intentId = instrumented.run.intentId;

    const tools = requireCommerceCheckoutTools(instrumented.tools);
    const tool = tools.find((entry) => entry.name === PRIMARY_OPERATION);
    if (!tool) {
      throw new Error(`missing tool ${PRIMARY_OPERATION}`);
    }

    const call: PaybondGenericToolCall<CommerceCheckoutToolArgs> = {
      toolName: PRIMARY_OPERATION,
      toolCallId: "demo-1",
      // Align Harbor authorized amount with product-derived zinc cost.
      requestedSpendCents: REQUESTED_SPEND_CENTS,
      arguments: {
        provider: "zinc",
        amountCents: REQUESTED_SPEND_CENTS,
        zinc: {
          retailer: "amazon",
          products: [
            {
              product_id: "B00SMOKE",
              quantity: 1,
              price_cents: REQUESTED_SPEND_CENTS,
            },
          ],
          max_price_cents: 10000,
        },
      },
    };

    const result = await tool.execute(call);

    console.log(
      JSON.stringify(
        {
          runId: instrumented.run.runId,
          intentId: instrumented.run.intentId,
          tenantId: instrumented.run.tenantId,
          authorization: result.authorization,
          evidence: result.evidence,
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
