import type {
  BuildPaybondStripeMetadataParams,
  PaybondStripeSettlementRail,
} from "./types.js";

export const PAYBOND_STRIPE_METADATA_TENANT_ID_KEY = "tenant_id";
export const PAYBOND_STRIPE_METADATA_INTENT_ID_KEY = "paybond_intent_id";
export const PAYBOND_STRIPE_METADATA_RAIL_KEY = "paybond_settlement_rail";

const STRIPE_METADATA_RAILS = new Set<PaybondStripeSettlementRail>([
  "stripe_connect",
  "stripe_ach_debit",
]);

/**
 * Builds Stripe PaymentIntent metadata bound to a Harbor intent and tenant realm.
 *
 * Values must be sourced from authenticated Paybond session context — never from
 * unauthenticated client input.
 */
export function buildPaybondStripeMetadata(
  params: BuildPaybondStripeMetadataParams,
): Record<string, string> {
  const tenantId = params.tenantId.trim();
  const intentId = params.intentId.trim();
  if (!tenantId) {
    throw new Error("buildPaybondStripeMetadata: tenantId is required");
  }
  if (!intentId) {
    throw new Error("buildPaybondStripeMetadata: intentId is required");
  }

  const metadata: Record<string, string> = {
    [PAYBOND_STRIPE_METADATA_TENANT_ID_KEY]: tenantId,
    [PAYBOND_STRIPE_METADATA_INTENT_ID_KEY]: intentId,
  };

  if (params.rail !== undefined) {
    if (!STRIPE_METADATA_RAILS.has(params.rail)) {
      throw new Error(
        "buildPaybondStripeMetadata: rail must be stripe_connect or stripe_ach_debit",
      );
    }
    metadata[PAYBOND_STRIPE_METADATA_RAIL_KEY] = params.rail;
  }

  return metadata;
}
