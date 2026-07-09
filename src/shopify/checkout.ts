import {
  encodeCommerceBindingToShopifyNoteAttributes,
  type ShopifyNoteAttribute,
} from "../commerce-binding.js";
import type {
  CreateCheckoutWithBindingParams,
  ShopifyCheckoutCreatePayload,
  ShopifyCheckoutLineItemInput,
  ShopifyUcpCheckoutLineItem,
} from "./types.js";
import { PAYBOND_UCP_AGENT_PROFILE_URL } from "./types.js";

function requireNonEmptyTrimmed(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`shopify checkout: ${label} is required`);
  }
  return trimmed;
}

function normalizeVariantGid(variantId: string): string {
  const trimmed = variantId.trim();
  if (!trimmed) {
    throw new Error("shopify checkout: line item variantId is required");
  }
  if (trimmed.startsWith("gid://shopify/ProductVariant/")) {
    return trimmed;
  }
  if (/^\d+$/.test(trimmed)) {
    return `gid://shopify/ProductVariant/${trimmed}`;
  }
  return trimmed;
}

function assertPositiveQuantity(quantity: number): number {
  if (!Number.isInteger(quantity) || quantity <= 0) {
    throw new Error("shopify checkout: line item quantity must be a positive integer");
  }
  return quantity;
}

/**
 * Converts developer-friendly line items into UCP checkout `line_items`.
 */
export function toUcpCheckoutLineItems(
  lineItems: readonly ShopifyCheckoutLineItemInput[],
): ShopifyUcpCheckoutLineItem[] {
  if (!Array.isArray(lineItems) || lineItems.length === 0) {
    throw new Error("shopify checkout: at least one line item is required");
  }
  return lineItems.map((entry) => ({
    item: { id: normalizeVariantGid(entry.variantId) },
    quantity: assertPositiveQuantity(entry.quantity),
  }));
}

/**
 * Builds a UCP checkout create payload with canonical Paybond binding metadata in
 * `note_attributes`.
 *
 * `tenantId` and `intentId` must be sourced from authenticated Paybond session context —
 * never from unauthenticated client input.
 */
export function createCheckoutWithBinding(
  params: CreateCheckoutWithBindingParams,
): ShopifyCheckoutCreatePayload {
  const tenantId = requireNonEmptyTrimmed(params.tenantId, "tenantId");
  const intentId = requireNonEmptyTrimmed(params.intentId, "intentId");
  const noteAttributes = encodeCommerceBindingToShopifyNoteAttributes(
    { tenantId, intentId },
    params.existingNoteAttributes,
  );

  const payload: ShopifyCheckoutCreatePayload = {
    line_items: toUcpCheckoutLineItems(params.lineItems),
    note_attributes: noteAttributes,
  };

  const cartId = params.cartId?.trim();
  if (cartId) {
    payload.cart_id = cartId;
  }

  const profileUrl = (params.agentProfileUrl ?? PAYBOND_UCP_AGENT_PROFILE_URL).trim();
  payload.meta = { profile_url: profileUrl };
  return payload;
}

/**
 * Merges binding metadata into an existing UCP checkout mutation payload.
 *
 * Use for `update_checkout` and other checkout mutations so binding cannot be dropped.
 */
export function mergeBindingIntoCheckoutPayload(
  binding: { tenantId: string; intentId: string },
  checkoutPayload: {
    note_attributes?: readonly ShopifyNoteAttribute[];
    meta?: { profile_url?: string };
    [key: string]: unknown;
  },
  agentProfileUrl: string = PAYBOND_UCP_AGENT_PROFILE_URL,
): Record<string, unknown> {
  const noteAttributes = encodeCommerceBindingToShopifyNoteAttributes(
    binding,
    checkoutPayload.note_attributes,
  );
  return {
    ...checkoutPayload,
    note_attributes: noteAttributes,
    meta: {
      ...(checkoutPayload.meta ?? {}),
      profile_url: (checkoutPayload.meta?.profile_url ?? agentProfileUrl).trim(),
    },
  };
}
