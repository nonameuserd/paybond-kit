/** Settlement rails allowed on Stripe PaymentIntent metadata (Harbor webhook preflight). */
export type PaybondStripeSettlementRail = "stripe_connect" | "stripe_ach_debit";

/** Canonical Paybond metadata keys written to Stripe PaymentIntent.metadata. */
export type PaybondStripeMetadata = {
  tenant_id: string;
  paybond_intent_id: string;
  paybond_settlement_rail?: PaybondStripeSettlementRail;
};

/** Inputs for {@link buildPaybondStripeMetadata}. Tenant id must come from Paybond session credentials. */
export type BuildPaybondStripeMetadataParams = {
  tenantId: string;
  intentId: string;
  rail?: PaybondStripeSettlementRail;
};

/** Completion presets supported by {@link mapStripeToolResultToEvidence}. */
export type StripeCommerceEvidencePreset = "stripe_charge" | "cost_and_completion";

export type MapStripeToolResultToEvidenceOptions = {
  preset: StripeCommerceEvidencePreset;
};

/** Vendor evidence shape for the `stripe_charge` completion preset. */
export type StripeChargeVendorEvidence = {
  charge_id: string;
  http_status: number;
  response_digest: string;
};

/** Evidence shape for the `cost_and_completion` archetype preset. */
export type CostAndCompletionEvidence = {
  status: string;
  cost_cents: number;
};

/** Normalized Stripe SDK tool result fields accepted by the evidence mapper. */
export type StripeToolResultInput = {
  payment_intent_id?: string;
  charge_id?: string;
  cost_cents?: number;
  status?: string;
  http_status?: number;
};
