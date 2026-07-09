import type {
  MapShopifyToolResultToEvidenceOptions,
  ShopifyCheckoutToolResult,
  ShopifyCommerceEvidencePreset,
} from "./types.js";

export const SHOPIFY_COMMERCE_MAPPER_VERSION = "shopify_commerce_v1";

const SHOPIFY_FUNDING_TOPICS = new Set([
  "orders/create",
  "orders/paid",
  "orders/updated",
  "orders/cancelled",
  "orders/fulfilled",
  "refunds/create",
]);

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
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

function readNumber(record: Record<string, unknown>, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
  }
  return undefined;
}

/**
 * Rejects Shopify order webhook envelopes — those fund Harbor intents and must not
 * be submitted as tool-completion evidence.
 */
export function assertNotShopifyFundingWebhook(input: Record<string, unknown>): void {
  const topic = readString(input, "topic", "X-Shopify-Topic");
  if (topic && SHOPIFY_FUNDING_TOPICS.has(topic)) {
    throw new Error(`${topic} webhooks are funding signals, not tool-completion evidence`);
  }

  if (readString(input, "X-Shopify-Shop-Domain") && readString(input, "X-Shopify-Webhook-Id")) {
    throw new Error("Shopify webhook envelopes are funding signals, not tool-completion evidence");
  }

  const adminGraphqlId = readString(input, "admin_graphql_api_id");
  const orderNumber = readString(input, "order_number");
  if (adminGraphqlId?.includes("gid://shopify/Order/") && orderNumber && !("status" in input)) {
    throw new Error("Shopify order webhook payloads are funding signals, not tool-completion evidence");
  }
}

function resolveCostCents(record: Record<string, unknown>): number {
  const cost =
    readNumber(record, "cost_cents", "costCents", "amount_cents", "amountCents") ??
    readNumber(record, "total_price_cents", "totalPriceCents");
  if (cost === undefined) {
    throw new Error("Shopify tool result missing cost_cents");
  }
  if (!Number.isInteger(cost) || cost < 0) {
    throw new Error("Shopify tool result cost_cents must be a non-negative integer");
  }
  return cost;
}

function mapCostAndCompletionEvidence(
  record: Record<string, unknown>,
): Pick<ShopifyCheckoutToolResult, "status" | "cost_cents"> {
  const status = readString(record, "status");
  if (!status) {
    throw new Error("Shopify tool result missing status");
  }
  return {
    status: status as ShopifyCheckoutToolResult["status"],
    cost_cents: resolveCostCents(record),
  };
}

/**
 * Normalizes Shopify checkout tool results into completion-catalog evidence fields.
 *
 * Rejects webhook-shaped funding payloads before mapping.
 */
export function mapShopifyToolResultToEvidence(
  toolResult: Record<string, unknown>,
  options: MapShopifyToolResultToEvidenceOptions,
): Pick<ShopifyCheckoutToolResult, "status" | "cost_cents"> {
  assertNotShopifyFundingWebhook(toolResult);

  const preset: ShopifyCommerceEvidencePreset = options.preset;
  if (preset === "cost_and_completion") {
    return mapCostAndCompletionEvidence(toolResult);
  }
  throw new Error(`mapShopifyToolResultToEvidence: unsupported preset ${preset}`);
}
