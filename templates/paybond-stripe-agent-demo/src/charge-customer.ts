import {
  buildPaybondStripeMetadata,
  mapStripeToolResultToEvidence,
  type PaybondEnvironment,
  type PaybondStripeSettlementRail,
  type StripeCommerceEvidencePreset,
  type StripeToolResultInput,
} from "@paybond/kit";

/**
 * Resolved Paybond session environment used to gate the optional Stripe test-mode charge.
 * `"unknown"` when the gateway did not report one — treated as non-sandbox (fail closed).
 */
export type PaybondSessionEnvironment = PaybondEnvironment | "unknown";

/**
 * Paybond session binding for Stripe metadata — never sourced from client input.
 *
 * Tenant isolation + sandbox-only invariant: `tenantId`/`intentId` come from the authenticated
 * Paybond session (populated after sandbox bind), and `environment` is the server-derived session
 * environment. The optional Stripe test-mode charge is a per-tenant capability that is only valid
 * when `environment === "sandbox"` — a live session must never forward a template-held secret to
 * Stripe.
 */
export type PaybondSessionBinding = {
  tenantId: string;
  intentId: string;
  environment: PaybondSessionEnvironment;
};

export type ChargeCustomerArgs = {
  amountCents: number;
  customerId?: string;
  rail?: PaybondStripeSettlementRail;
};

export type ChargeCustomerResult = StripeToolResultInput & {
  payment_intent_id: string;
  charge_id: string;
  cost_cents: number;
  status: string;
  metadata: Record<string, string>;
  mode: "mock" | "stripe_test";
};

function assertPositiveIntegerAmount(amountCents: number): void {
  if (!Number.isInteger(amountCents) || amountCents <= 0) {
    throw new Error("amountCents must be a positive integer");
  }
}

function mockSuffix(intentId: string): string {
  return intentId.replace(/-/g, "").slice(0, 12) || "demo";
}

/**
 * Offline mock charge — no Stripe secret required.
 */
export function mockChargeCustomer(
  metadata: Record<string, string>,
  args: ChargeCustomerArgs,
  intentId: string,
): ChargeCustomerResult {
  assertPositiveIntegerAmount(args.amountCents);
  const suffix = mockSuffix(intentId);
  return {
    payment_intent_id: `pi_mock_${suffix}`,
    charge_id: `ch_mock_${suffix}`,
    cost_cents: args.amountCents,
    status: "succeeded",
    metadata,
    mode: "mock",
  };
}

function stripeMetadataParams(metadata: Record<string, string>): URLSearchParams {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(metadata)) {
    params.set(`metadata[${key}]`, value);
  }
  return params;
}

/**
 * Optional Stripe test-mode PaymentIntent create + confirm via REST (requires `STRIPE_SECRET_KEY`).
 */
export async function stripeTestChargeCustomer(
  secretKey: string,
  metadata: Record<string, string>,
  args: ChargeCustomerArgs,
): Promise<ChargeCustomerResult> {
  assertPositiveIntegerAmount(args.amountCents);

  const body = stripeMetadataParams(metadata);
  body.set("amount", String(args.amountCents));
  body.set("currency", "usd");
  body.set("confirm", "true");
  body.set("payment_method", "pm_card_visa");
  if (args.customerId?.trim()) {
    body.set("customer", args.customerId.trim());
  }

  const response = await fetch("https://api.stripe.com/v1/payment_intents", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secretKey}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const payload = (await response.json()) as Record<string, unknown>;
  if (!response.ok) {
    const message =
      typeof payload.error === "object" &&
      payload.error !== null &&
      "message" in payload.error &&
      typeof payload.error.message === "string"
        ? payload.error.message
        : `Stripe API error (${response.status})`;
    throw new Error(message);
  }

  const paymentIntentId =
    typeof payload.id === "string" && payload.id.startsWith("pi_") ? payload.id : undefined;
  if (!paymentIntentId) {
    throw new Error("Stripe response missing payment_intent id");
  }

  let chargeId: string | undefined;
  const latestCharge = payload.latest_charge;
  if (typeof latestCharge === "string" && latestCharge.startsWith("ch_")) {
    chargeId = latestCharge;
  } else if (
    typeof latestCharge === "object" &&
    latestCharge !== null &&
    "id" in latestCharge &&
    typeof latestCharge.id === "string"
  ) {
    chargeId = latestCharge.id;
  }
  if (!chargeId) {
    throw new Error("Stripe response missing charge id");
  }

  const status = typeof payload.status === "string" ? payload.status : "succeeded";
  return {
    payment_intent_id: paymentIntentId,
    charge_id: chargeId,
    cost_cents: args.amountCents,
    status,
    metadata,
    mode: "stripe_test",
  };
}

/**
 * Resolve the sandbox-only Stripe test key, enforcing the per-tenant + sandbox-only invariant.
 *
 * Returns the validated `sk_test_...` secret only when a secret is present AND the bound Paybond
 * session environment is `sandbox`. Returns `undefined` when no secret is configured (the default
 * offline mock path). Fails closed with an explanatory message when:
 *   - a secret is set but the session is not sandbox (live or unknown environment), or
 *   - the secret is not a Stripe TEST key (e.g. a live `sk_live_...` key).
 *
 * This guarantees a live tenant can never forward a template-held secret to Stripe.
 *
 * @param environment Server-derived Paybond session environment (preferred over client hints).
 * @returns The validated Stripe test secret, or `undefined` to use the offline mock.
 */
export function resolveSandboxStripeTestKey(
  environment: PaybondSessionEnvironment,
): string | undefined {
  const stripeSecretKey = process.env.STRIPE_SECRET_KEY?.trim();
  if (!stripeSecretKey) {
    // Default offline path: no secret required, so `paybond dev loop --offline` and the sandbox
    // smoke run with zero secrets.
    return undefined;
  }

  if (environment !== "sandbox") {
    throw new Error(
      `STRIPE_SECRET_KEY is set but the Paybond session environment is "${environment}". ` +
        "The Stripe test-mode charge is a per-tenant, sandbox-only capability; unset " +
        "STRIPE_SECRET_KEY for live (or unconfirmed) sessions — the mock path needs no secret.",
    );
  }

  if (!stripeSecretKey.startsWith("sk_test_")) {
    throw new Error(
      "STRIPE_SECRET_KEY must be a Stripe TEST key (sk_test_...). " +
        "Live keys (sk_live_...) are refused: this sandbox-only demo never charges live Stripe.",
    );
  }

  return stripeSecretKey;
}

/**
 * Instrumented `payments.charge_customer` handler: binds Harbor metadata, then charges (mock or Stripe test).
 *
 * `tenantId` and `intentId` must come from Paybond session context after sandbox bind — never from
 * unauthenticated client input. The Stripe test-mode charge is per-tenant + sandbox-only: it is used
 * only when a `sk_test_...` secret is configured AND `binding.environment === "sandbox"`; otherwise
 * this falls back to the offline mock (and fails closed if a secret is misconfigured for live).
 */
export async function chargeCustomer(
  binding: PaybondSessionBinding,
  args: ChargeCustomerArgs,
): Promise<ChargeCustomerResult> {
  if (!binding.tenantId.trim() || !binding.intentId.trim()) {
    throw new Error("Paybond session binding is required before charging");
  }

  const metadata = buildPaybondStripeMetadata({
    tenantId: binding.tenantId,
    intentId: binding.intentId,
    rail: args.rail ?? "stripe_connect",
  });

  const sandboxStripeTestKey = resolveSandboxStripeTestKey(binding.environment);
  if (sandboxStripeTestKey) {
    return stripeTestChargeCustomer(sandboxStripeTestKey, metadata, args);
  }

  return mockChargeCustomer(metadata, args, binding.intentId);
}

/**
 * Maps a charge tool result into completion-catalog evidence for the configured preset.
 */
export function mapChargeEvidence(
  toolResult: Record<string, unknown>,
  preset: StripeCommerceEvidencePreset = "stripe_charge",
): ReturnType<typeof mapStripeToolResultToEvidence> {
  return mapStripeToolResultToEvidence(toolResult, { preset });
}
