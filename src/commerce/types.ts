import type { ShopifyNoteAttribute } from "../commerce-binding.js";
import type { ShopifyCheckoutLineItemInput } from "../shopify/types.js";
import type { PaybondStripeSettlementRail } from "../stripe-commerce/types.js";

/** Supported commerce.checkout provider identifiers. */
export type CommerceProviderId = "shopify" | "stripe" | "zinc";

/** Paybond session binding for multi-provider checkout — never sourced from client input. */
export type CommerceCheckoutSessionBinding = {
  tenantId: string;
  intentId: string;
};

/** Canonical completion envelope returned by every commerce provider adapter. */
export type CommerceCheckoutToolResult = {
  status: "completed" | "requires_escalation" | "failed";
  cost_cents: number;
  order_id?: string;
  provider: CommerceProviderId;
  /** Provider-specific continuation URL (e.g. Shopify hosted checkout). */
  continue_url?: string;
  /** Shopify shop domain when provider is `shopify`. */
  shop?: string;
  /** Stripe PaymentIntent id when provider is `stripe`. */
  payment_intent_id?: string;
  /** Zinc request id when provider is `zinc`. */
  zinc_request_id?: string;
};

/** Shopify-specific args accepted on the shared commerce.checkout tool. */
export type CommerceShopifyCheckoutArgs = {
  shopDomain: string;
  lineItems: readonly ShopifyCheckoutLineItemInput[];
  cartId?: string;
  noteAttributes?: readonly ShopifyNoteAttribute[];
};

/** Stripe-specific args accepted on the shared commerce.checkout tool. */
export type CommerceStripeCheckoutArgs = {
  currency?: string;
  description?: string;
  existingMetadata?: Record<string, string>;
  rail?: PaybondStripeSettlementRail;
  /** Optional existing PaymentIntent to confirm/capture. */
  paymentIntentId?: string;
};

/** Zinc product line for the shared commerce.checkout tool. */
export type CommerceZincProductInput = {
  product_id: string;
  quantity: number;
  /**
   * Unit price in cents. Required in Zinc sandbox so `cost_cents` is
   * product-derived (not trusted from agent `amountCents` alone).
   */
  price_cents?: number;
};

/** Zinc-specific args accepted on the shared commerce.checkout tool. */
export type CommerceZincCheckoutArgs = {
  retailer: string;
  products: readonly CommerceZincProductInput[];
  shipping_address?: Record<string, string>;
  /** Optional max price cap in cents (sandbox enforces; live maps to Zinc max_price). */
  max_price_cents?: number;
};

/**
 * Arguments accepted by the multi-provider `commerce.checkout` tool handler.
 *
 * `provider` selects the adapter; when omitted the router's `defaultProvider` is used.
 * Provider-specific payloads live under `shopify` / `stripe` / `zinc` — never pass
 * `tenantId` or `intentId` here (those come from Paybond session binding).
 */
export type CommerceCheckoutToolArgs = {
  provider?: CommerceProviderId;
  amountCents: number;
  shopify?: CommerceShopifyCheckoutArgs;
  stripe?: CommerceStripeCheckoutArgs;
  zinc?: CommerceZincCheckoutArgs;
};

/** Commerce evidence presets supported by {@link mapCommerceCheckoutResultToEvidence}. */
export type CommerceCheckoutEvidencePreset = "cost_and_completion";

export type MapCommerceCheckoutResultToEvidenceOptions = {
  preset: CommerceCheckoutEvidencePreset;
};
