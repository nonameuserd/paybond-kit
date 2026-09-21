import type {
  CommerceCheckoutEvidencePreset,
  CommerceCheckoutToolResult,
  MapCommerceCheckoutResultToEvidenceOptions,
} from "./types.js";

export const COMMERCE_CHECKOUT_MAPPER_VERSION = "commerce_checkout_v1";

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

function resolveCostCents(record: Record<string, unknown>): number {
  // Fail closed: never invent cost_cents from amount_cents / amountCents.
  if (!("cost_cents" in record) && !("costCents" in record)) {
    throw new Error("commerce.checkout tool result missing cost_cents");
  }
  const raw = "cost_cents" in record ? record.cost_cents : record.costCents;
  if (raw === null || raw === undefined) {
    throw new Error("commerce.checkout tool result missing cost_cents");
  }
  const cost = readNumber({ cost_cents: raw }, "cost_cents");
  if (cost === undefined) {
    throw new Error("commerce.checkout tool result cost_cents must be a non-negative integer");
  }
  if (!Number.isInteger(cost) || cost < 0) {
    throw new Error("commerce.checkout tool result cost_cents must be a non-negative integer");
  }
  return cost;
}

/** Evidence envelope for the `cost_and_completion` commerce preset. */
export type CommerceCheckoutEvidence = Pick<
  CommerceCheckoutToolResult,
  "status" | "cost_cents"
> &
  Partial<Pick<CommerceCheckoutToolResult, "provider" | "order_id">>;

/**
 * Normalizes multi-provider commerce.checkout results into completion-catalog evidence.
 *
 * Status + cost_cents are required. Optional `provider` and `order_id` are preserved when
 * present. Other provider-specific fields (`shop`, `payment_intent_id`, `zinc_request_id`)
 * are ignored for the `cost_and_completion` preset.
 */
export function mapCommerceCheckoutResultToEvidence(
  toolResult: Record<string, unknown>,
  options: MapCommerceCheckoutResultToEvidenceOptions,
): CommerceCheckoutEvidence {
  const record = readObject(toolResult);
  if (!record) {
    throw new Error("commerce.checkout tool result must be an object");
  }

  const preset: CommerceCheckoutEvidencePreset = options.preset;
  if (preset !== "cost_and_completion") {
    throw new Error(`mapCommerceCheckoutResultToEvidence: unsupported preset ${preset}`);
  }

  const status = readString(record, "status");
  if (!status) {
    throw new Error("commerce.checkout tool result missing status");
  }

  const evidence: CommerceCheckoutEvidence = {
    status: status as CommerceCheckoutToolResult["status"],
    cost_cents: resolveCostCents(record),
  };

  const provider = readString(record, "provider");
  if (
    provider === "shopify" ||
    provider === "stripe" ||
    provider === "zinc"
  ) {
    evidence.provider = provider;
  }

  const orderId = readString(record, "order_id", "orderId");
  if (orderId) {
    evidence.order_id = orderId;
  }

  return evidence;
}
