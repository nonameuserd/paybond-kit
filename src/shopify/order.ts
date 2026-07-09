import { decodeCommerceBindingFromShopifyNoteAttributes } from "../commerce-binding.js";
import type { ShopifyNoteAttribute } from "../commerce-binding.js";
import type {
  GetShopifyOrderParams,
  ShopifyOrderSummary,
  ShopifyUcpFetch,
} from "./types.js";
import { PAYBOND_SHOPIFY_UCP_VERSION, PAYBOND_UCP_AGENT_PROFILE_URL } from "./types.js";

function requireShopDomain(shopDomain: string): string {
  const trimmed = shopDomain.trim();
  if (!trimmed) {
    throw new Error("shopify order: shopDomain is required");
  }
  return trimmed.replace(/^https?:\/\//, "").replace(/\/$/, "");
}

function normalizeOrderGid(orderId: string): string {
  const trimmed = orderId.trim();
  if (!trimmed) {
    throw new Error("shopify order: orderId is required");
  }
  if (trimmed.startsWith("gid://shopify/Order/")) {
    return trimmed;
  }
  if (/^\d+$/.test(trimmed)) {
    return `gid://shopify/Order/${trimmed}`;
  }
  return trimmed;
}

function shopOrigin(shopDomain: string): string {
  const host = requireShopDomain(shopDomain);
  return host.includes(".") ? `https://${host}` : `https://${host}.myshopify.com`;
}

function defaultFetchUcp(url: string, init: RequestInit): Promise<Response> {
  return fetch(url, init);
}

function readNoteAttributes(value: unknown): ShopifyNoteAttribute[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const attrs: ShopifyNoteAttribute[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const name = (entry as { name?: unknown }).name;
    const attrValue = (entry as { value?: unknown }).value;
    if (typeof name === "string" && typeof attrValue === "string") {
      attrs.push({ name, value: attrValue });
    }
  }
  return attrs;
}

function orderSummaryFromPayload(
  shop: string,
  orderId: string,
  payload: Record<string, unknown>,
): ShopifyOrderSummary {
  const noteAttributes = readNoteAttributes(payload.note_attributes);
  const binding = decodeCommerceBindingFromShopifyNoteAttributes(noteAttributes);
  return {
    order_id: readString(payload, "id", "order_id", "admin_graphql_api_id") ?? orderId,
    shop,
    financial_status: readString(payload, "financial_status"),
    note_attributes: noteAttributes,
    binding: {
      tenant_id: binding?.tenantId ?? null,
      paybond_intent_id: binding?.intentId ?? null,
    },
  };
}

function readString(record: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
  }
  return undefined;
}

/**
 * Fetches an order via Shopify UCP Order MCP for reconciliation.
 *
 * Agents must not pass Shopify offline access tokens. This helper uses the UCP transport
 * at `{shop}/api/ucp/mcp` with the Paybond agent profile URL.
 */
export async function getOrder(params: GetShopifyOrderParams): Promise<ShopifyOrderSummary> {
  const shop = requireShopDomain(params.shopDomain);
  const orderId = normalizeOrderGid(params.orderId);
  const profileUrl = (params.agentProfileUrl ?? PAYBOND_UCP_AGENT_PROFILE_URL).trim();
  const fetchUcp: ShopifyUcpFetch = params.fetchUcp ?? defaultFetchUcp;

  const response = await fetchUcp(`${shopOrigin(shop)}/api/ucp/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "UCP-Agent": profileUrl,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "paybond-kit-get-order",
      method: "order/get",
      params: {
        order_id: orderId,
        meta: {
          profile_url: profileUrl,
          ucp_version: PAYBOND_SHOPIFY_UCP_VERSION,
        },
      },
    }),
  });

  const body = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    const message = readString(body, "message", "error") ?? `UCP order/get failed (${response.status})`;
    throw new Error(message);
  }

  const result = body.result;
  if (!result || typeof result !== "object") {
    throw new Error("shopify order: UCP response missing result");
  }

  return orderSummaryFromPayload(shop, orderId, result as Record<string, unknown>);
}
