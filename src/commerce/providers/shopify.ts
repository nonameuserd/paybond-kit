import { createCheckoutWithBinding } from "../../shopify/checkout.js";
import type {
  ShopifyCheckoutExecuteInput,
  ShopifyCheckoutToolResult,
} from "../../shopify/types.js";
import { PAYBOND_UCP_AGENT_PROFILE_URL } from "../../shopify/types.js";
import {
  requireAmountCents,
  requireCommerceSessionBinding,
  type CommerceCheckoutProvider,
} from "../provider.js";
import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
} from "../types.js";

/**
 * Executes a Shopify checkout after Paybond binding has been injected into the
 * UCP payload. Mirrors {@link ShopifyCheckoutExecutor} from the Shopify helpers.
 */
export type ShopifyCommerceCheckoutExecutor = (
  input: ShopifyCheckoutExecuteInput,
) => Promise<ShopifyCheckoutToolResult>;

export type CreateShopifyCommerceProviderOptions = {
  executeCheckout: ShopifyCommerceCheckoutExecutor;
  agentProfileUrl?: string;
};

/**
 * Creates a Shopify adapter for the multi-provider commerce checkout router.
 *
 * Reuses {@link createCheckoutWithBinding} so `tenant_id` / `paybond_intent_id`
 * note attributes always come from session binding — never from tool args.
 */
export function createShopifyCommerceProvider(
  options: CreateShopifyCommerceProviderOptions,
): CommerceCheckoutProvider {
  const profileUrl = (options.agentProfileUrl ?? PAYBOND_UCP_AGENT_PROFILE_URL).trim();

  return {
    id: "shopify",
    async checkout(
      args: CommerceCheckoutToolArgs,
      binding: CommerceCheckoutSessionBinding,
    ): Promise<CommerceCheckoutToolResult> {
      const session = requireCommerceSessionBinding(binding);
      const amountCents = requireAmountCents(args.amountCents);
      const shopifyArgs = args.shopify;
      if (!shopifyArgs) {
        throw new Error('commerce.checkout: shopify payload is required when provider is "shopify"');
      }
      if (!shopifyArgs.shopDomain?.trim()) {
        throw new Error("commerce.checkout: shopify.shopDomain is required");
      }
      if (!Array.isArray(shopifyArgs.lineItems) || shopifyArgs.lineItems.length === 0) {
        throw new Error("commerce.checkout: shopify.lineItems must include at least one item");
      }

      const checkoutPayload = createCheckoutWithBinding({
        tenantId: session.tenantId,
        intentId: session.intentId,
        lineItems: shopifyArgs.lineItems,
        existingNoteAttributes: shopifyArgs.noteAttributes,
        cartId: shopifyArgs.cartId,
        agentProfileUrl: profileUrl,
      });

      const result = await options.executeCheckout({
        shopDomain: shopifyArgs.shopDomain,
        lineItems: shopifyArgs.lineItems,
        amountCents,
        cartId: shopifyArgs.cartId,
        // Bound attributes only — never forward unbound client noteAttributes.
        noteAttributes: checkoutPayload.note_attributes,
        tenantId: session.tenantId,
        intentId: session.intentId,
        checkoutPayload,
        agentProfileUrl: profileUrl,
      });

      const costCents = result.cost_cents;
      if (
        typeof costCents !== "number" ||
        !Number.isInteger(costCents) ||
        costCents < 0
      ) {
        throw new Error(
          "commerce.checkout: shopify executor result cost_cents must be a non-negative integer",
        );
      }

      return {
        status: result.status,
        cost_cents: costCents,
        order_id: result.order_id,
        provider: "shopify",
        shop: result.shop,
        continue_url: result.continue_url,
      };
    },
  };
}
