/**
 * Resolved Paybond session environment used to gate optional Stripe test-mode charges.
 * `"unknown"` when the gateway did not report one — treated as non-sandbox (fail closed).
 */
export type PaybondSessionEnvironment = "live" | "sandbox" | "unknown";

/**
 * Resolve the sandbox-only Stripe test key, enforcing the per-tenant + sandbox-only invariant.
 *
 * Returns the validated `sk_test_...` secret only when a secret is present AND the bound Paybond
 * session environment is `sandbox`. Returns `undefined` when no secret is configured (the default
 * offline mock path). Fails closed when:
 *   - a secret is set but the session is not sandbox (live or unknown environment), or
 *   - the secret is not a Stripe TEST key (e.g. a live `sk_live_...` key).
 *
 * @param environment Server-derived Paybond session environment (preferred over client hints).
 * @param secretKey Optional explicit secret; defaults to `process.env.STRIPE_SECRET_KEY`.
 * @returns The validated Stripe test secret, or `undefined` to use an offline mock.
 */
export function resolveSandboxStripeTestKey(
  environment: PaybondSessionEnvironment,
  secretKey: string | undefined = process.env.STRIPE_SECRET_KEY,
): string | undefined {
  const stripeSecretKey = secretKey?.trim();
  if (!stripeSecretKey) {
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
        "Live keys (sk_live_...) are refused: sandbox-only helpers never charge live Stripe.",
    );
  }

  return stripeSecretKey;
}

export type MockStripeChargeInput = {
  amountCents: number;
  intentId: string;
  metadata: Record<string, string>;
};

export type MockStripeChargeResult = {
  payment_intent_id: string;
  charge_id: string;
  cost_cents: number;
  status: string;
  metadata: Record<string, string>;
  mode: "mock";
};

/**
 * Offline mock Stripe charge — no Stripe secret required.
 */
export function mockStripeCharge(input: MockStripeChargeInput): MockStripeChargeResult {
  if (!Number.isInteger(input.amountCents) || input.amountCents <= 0) {
    throw new Error("amountCents must be a positive integer");
  }
  const suffix = input.intentId.replace(/-/g, "").slice(0, 12) || "demo";
  return {
    payment_intent_id: `pi_mock_${suffix}`,
    charge_id: `ch_mock_${suffix}`,
    cost_cents: input.amountCents,
    status: "succeeded",
    metadata: input.metadata,
    mode: "mock",
  };
}
