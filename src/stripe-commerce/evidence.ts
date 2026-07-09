import { jsonValueDigest } from "../json-digest.js";
import type {
  CostAndCompletionEvidence,
  MapStripeToolResultToEvidenceOptions,
  StripeChargeVendorEvidence,
  StripeCommerceEvidencePreset,
} from "./types.js";

export const STRIPE_COMMERCE_MAPPER_VERSION = "stripe_commerce_v1";

const STRIPE_FUNDING_EVENT_TYPES = new Set([
  "payment_intent.succeeded",
  "payment_intent.payment_failed",
  "payment_intent.canceled",
  "payment_intent.processing",
  "payment_intent.requires_action",
  "payment_intent.amount_capturable_updated",
  "charge.succeeded",
  "charge.failed",
  "charge.pending",
  "charge.refunded",
  "charge.updated",
  "charge.dispute.created",
  "charge.dispute.closed",
]);

const STRIPE_FUNDING_EVENT_PREFIXES = ["payment_intent.", "charge.", "payout.", "mandate."];

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

function isStripeFundingEventType(eventType: string): boolean {
  if (STRIPE_FUNDING_EVENT_TYPES.has(eventType)) {
    return true;
  }
  return STRIPE_FUNDING_EVENT_PREFIXES.some((prefix) => eventType.startsWith(prefix));
}

/**
 * Rejects Stripe funding webhook envelopes — those fund Harbor intents and must not
 * be submitted as tool-completion evidence.
 */
export function assertNotStripeFundingWebhook(input: Record<string, unknown>): void {
  const objectKind = readString(input, "object");
  if (objectKind === "event") {
    throw new Error(
      "Stripe event webhooks are funding signals, not tool-completion evidence",
    );
  }

  const eventType = readString(input, "type", "event_type", "eventType");
  if (eventType && isStripeFundingEventType(eventType)) {
    throw new Error(
      `${eventType} webhooks are funding signals, not tool-completion evidence`,
    );
  }

  const eventId = readString(input, "id");
  if (eventId?.startsWith("evt_") && eventType) {
    throw new Error(
      "Stripe event webhooks are funding signals, not tool-completion evidence",
    );
  }

  const data = readObject(input.data);
  if (data && readObject(data.object)) {
    throw new Error(
      "Stripe webhook data.object envelopes are funding signals, not tool-completion evidence",
    );
  }

  if (
    Object.prototype.hasOwnProperty.call(input, "pending_webhooks") &&
    eventType !== undefined
  ) {
    throw new Error(
      "Stripe event webhooks are funding signals, not tool-completion evidence",
    );
  }
}

function resolveChargeId(record: Record<string, unknown>): string {
  const direct = readString(record, "charge_id", "chargeId");
  if (direct) {
    return direct;
  }

  const latestCharge = record.latest_charge;
  if (typeof latestCharge === "string" && latestCharge.startsWith("ch_")) {
    return latestCharge;
  }
  const latestChargeObject = readObject(latestCharge);
  if (latestChargeObject) {
    const nestedId = readString(latestChargeObject, "id");
    if (nestedId?.startsWith("ch_")) {
      return nestedId;
    }
  }

  const topLevelId = readString(record, "id");
  if (topLevelId?.startsWith("ch_")) {
    return topLevelId;
  }

  throw new Error("Stripe tool result missing charge_id");
}

function resolveCostCents(record: Record<string, unknown>): number {
  const cost =
    readNumber(record, "cost_cents", "costCents", "amount_cents", "amountCents") ??
    readNumber(record, "amount_received", "amountReceived");
  if (cost === undefined) {
    throw new Error("Stripe tool result missing cost_cents");
  }
  if (!Number.isInteger(cost) || cost < 0) {
    throw new Error("Stripe tool result cost_cents must be a non-negative integer");
  }
  return cost;
}

function normalizeCompletionStatus(status: string): string {
  const normalized = status.trim().toLowerCase();
  if (normalized === "succeeded" || normalized === "requires_capture") {
    return "completed";
  }
  return normalized;
}

function resolveHttpStatus(record: Record<string, unknown>, status: string): number {
  const explicit = readNumber(record, "http_status", "httpStatus");
  if (explicit !== undefined) {
    return explicit;
  }
  const normalized = status.trim().toLowerCase();
  if (normalized === "succeeded" || normalized === "requires_capture") {
    return 200;
  }
  return 402;
}

function stripeResponseDigestHex(chargeId: string, costCents: number): string {
  const digestBytes = jsonValueDigest({ charge_id: chargeId, cost_cents: costCents });
  return `blake3:${Buffer.from(digestBytes).toString("hex")}`;
}

function mapStripeChargeEvidence(record: Record<string, unknown>): StripeChargeVendorEvidence {
  const chargeId = resolveChargeId(record);
  const status = readString(record, "status") ?? "succeeded";
  const costCents = resolveCostCents(record);
  return {
    charge_id: chargeId,
    http_status: resolveHttpStatus(record, status),
    response_digest: stripeResponseDigestHex(chargeId, costCents),
  };
}

function mapCostAndCompletionEvidence(record: Record<string, unknown>): CostAndCompletionEvidence {
  const status = readString(record, "status");
  if (!status) {
    throw new Error("Stripe tool result missing status");
  }
  return {
    status: normalizeCompletionStatus(status),
    cost_cents: resolveCostCents(record),
  };
}

/**
 * Normalizes Stripe SDK tool results into completion-catalog evidence fields.
 *
 * Rejects webhook-shaped funding payloads before mapping.
 */
export function mapStripeToolResultToEvidence(
  toolResult: Record<string, unknown>,
  options: MapStripeToolResultToEvidenceOptions,
): StripeChargeVendorEvidence | CostAndCompletionEvidence {
  assertNotStripeFundingWebhook(toolResult);

  if (options.preset === "stripe_charge") {
    return mapStripeChargeEvidence(toolResult);
  }
  if (options.preset === "cost_and_completion") {
    return mapCostAndCompletionEvidence(toolResult);
  }
  throw new Error(
    `mapStripeToolResultToEvidence: unsupported preset ${options.preset as StripeCommerceEvidencePreset}`,
  );
}
