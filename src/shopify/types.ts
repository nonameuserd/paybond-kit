import type { ShopifyNoteAttribute } from "../commerce-binding.js";

/** Canonical Paybond UCP agent profile URL for Shopify partner registration. */
export const PAYBOND_UCP_AGENT_PROFILE_URL = "https://paybond.ai/.well-known/ucp/profile.json";

/** Default UCP protocol version supported by Paybond Kit Shopify helpers. */
export const PAYBOND_SHOPIFY_UCP_VERSION = "2026-04-08";

/** Shopify commerce evidence presets supported by {@link mapShopifyToolResultToEvidence}. */
export type ShopifyCommerceEvidencePreset = "cost_and_completion";

export type MapShopifyToolResultToEvidenceOptions = {
  preset: ShopifyCommerceEvidencePreset;
};

/** Line item input for {@link createCheckoutWithBinding}. */
export type ShopifyCheckoutLineItemInput = {
  variantId: string;
  quantity: number;
};

/** UCP checkout line item shape (Shopify Checkout MCP). */
export type ShopifyUcpCheckoutLineItem = {
  item: { id: string };
  quantity: number;
};

/** Inputs for {@link createCheckoutWithBinding}. Binding ids must come from Paybond session context. */
export type CreateCheckoutWithBindingParams = {
  intentId: string;
  tenantId: string;
  lineItems: readonly ShopifyCheckoutLineItemInput[];
  existingNoteAttributes?: readonly ShopifyNoteAttribute[];
  cartId?: string;
  agentProfileUrl?: string;
};

/** UCP `create_checkout` payload with binding metadata injected. */
export type ShopifyCheckoutCreatePayload = {
  line_items: ShopifyUcpCheckoutLineItem[];
  note_attributes: ShopifyNoteAttribute[];
  cart_id?: string;
  meta?: {
    profile_url: string;
  };
};

/** Checkout tool completion envelope for `commerce.checkout` evidence mapping. */
export type ShopifyCheckoutToolResult = {
  status: "completed" | "requires_escalation" | "failed";
  cost_cents: number;
  order_id?: string;
  shop: string;
  continue_url?: string;
};

/** Arguments accepted by guarded `commerce.checkout` tool handlers. */
export type ShopifyCheckoutToolArgs = {
  shopDomain: string;
  lineItems: readonly ShopifyCheckoutLineItemInput[];
  amountCents: number;
  cartId?: string;
  noteAttributes?: readonly ShopifyNoteAttribute[];
};

/** Arguments passed to the checkout executor after binding injection. */
export type ShopifyCheckoutExecuteInput = ShopifyCheckoutToolArgs & {
  tenantId: string;
  intentId: string;
  checkoutPayload: ShopifyCheckoutCreatePayload;
  agentProfileUrl: string;
};

export type ShopifyUcpFetch = (
  url: string,
  init: RequestInit,
) => Promise<Response>;

/** Inputs for {@link getOrder}. Agents must not pass Shopify offline access tokens. */
export type GetShopifyOrderParams = {
  shopDomain: string;
  orderId: string;
  agentProfileUrl?: string;
  fetchUcp?: ShopifyUcpFetch;
};

/** Normalized order view for reconciliation helpers. */
export type ShopifyOrderSummary = {
  order_id: string;
  shop: string;
  financial_status?: string;
  note_attributes: ShopifyNoteAttribute[];
  binding: {
    tenant_id: string | null;
    paybond_intent_id: string | null;
  };
};
