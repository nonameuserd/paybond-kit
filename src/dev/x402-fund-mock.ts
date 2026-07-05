/**
 * Deterministic x402 `/fund` sequence for WireMock and offline dev gateway mocks.
 * Simulates Harbor: 402 challenge → 202 pending → 200 funded with capability token.
 */

export const X402_DEV_WIREMOCK_INTENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const X402_DEV_WIREMOCK_TENANT_ID = "dry-run-tenant";

export const X402_DEV_PAYMENT_REQUIRED =
  '{"asset":"usdc","network":"base","amount":"0.02","payTo":"0xabc1230000000000000000000000000000000000"}';

export const X402_DEV_CAPABILITY_TOKEN = "cap-x402-dev-mock-1";

export type X402FundMockPhase = "challenge" | "pending" | "funded";

export type X402FundMockResponse = {
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  phase: X402FundMockPhase;
};

function fundingBase(intentId: string): Record<string, unknown> {
  return {
    settlement_rail: "x402_usdc_base",
    harbor_fund_endpoint: `/harbor/intents/${intentId}/fund`,
    payment_session_id: `paymentSession_${intentId}`,
    payment_url: `https://pay.coinbase.com/payment-sessions/paymentSession_${intentId}`,
    asset: "usdc",
    network: "base",
    capture_expires_at: "2027-12-31T23:59:59Z",
    refund_expires_at: "2028-01-31T23:59:59Z",
  };
}

function intentShell(
  intentId: string,
  tenantId: string,
  extra: Record<string, unknown>,
): Record<string, unknown> {
  return {
    intent_id: intentId,
    tenant: tenantId,
    settlement_rail: "x402_usdc_base",
    currency: "usd",
    amount_cents: 2000,
    ...extra,
  };
}

/** Build the 402 payment challenge response body. */
export function buildX402FundChallengeBody(
  intentId: string,
  tenantId: string,
): Record<string, unknown> {
  return intentShell(intentId, tenantId, {
    state: "open",
    funded: false,
    funding: {
      ...fundingBase(intentId),
      status: "created",
    },
  });
}

/** Build the 202 authorization_pending response body. */
export function buildX402FundPendingBody(
  intentId: string,
  tenantId: string,
): Record<string, unknown> {
  return intentShell(intentId, tenantId, {
    state: "open",
    funded: false,
    funding: {
      ...fundingBase(intentId),
      status: "authorization_pending",
      authorization_id: `auth_${intentId}`,
      source_address: "0xsource0000000000000000000000000000000001",
    },
  });
}

/** Build the 200 funded response body with capability token. */
export function buildX402FundSuccessBody(
  intentId: string,
  tenantId: string,
  capabilityToken: string = X402_DEV_CAPABILITY_TOKEN,
): Record<string, unknown> {
  return intentShell(intentId, tenantId, {
    state: "funded",
    funded: true,
    capability_token: capabilityToken,
    funding: {
      ...fundingBase(intentId),
      status: "authorization_succeeded",
      authorization_id: `auth_${intentId}`,
      source_address: "0xsource0000000000000000000000000000000001",
    },
  });
}

/** In-memory x402 fund sequence keyed by intent id (one sequence per intent). */
export class X402FundStateMachine {
  private readonly phases = new Map<string, X402FundMockPhase>();

  reset(intentId?: string): void {
    if (intentId === undefined) {
      this.phases.clear();
      return;
    }
    this.phases.delete(intentId);
  }

  /** Advance the mock fund sequence for ``intentId`` and return the next Harbor-shaped response. */
  next(
    intentId: string,
    tenantId: string,
    paymentSignature: string | undefined,
  ): X402FundMockResponse | null {
    const trimmedIntent = intentId.trim();
    if (!trimmedIntent) {
      return null;
    }

    const phase = this.phases.get(trimmedIntent) ?? "challenge";
    const hasSignature = Boolean(paymentSignature?.trim());

    if (phase === "challenge" && !hasSignature) {
      this.phases.set(trimmedIntent, "pending");
      return {
        status: 402,
        headers: {
          "content-type": "application/json",
          "payment-required": X402_DEV_PAYMENT_REQUIRED,
        },
        body: buildX402FundChallengeBody(trimmedIntent, tenantId),
        phase: "challenge",
      };
    }

    if (phase === "pending" && hasSignature) {
      this.phases.set(trimmedIntent, "funded");
      return {
        status: 202,
        headers: {
          "content-type": "application/json",
          "payment-response": "simulated-x402-payment-response",
        },
        body: buildX402FundPendingBody(trimmedIntent, tenantId),
        phase: "pending",
      };
    }

    if (phase === "funded" && hasSignature) {
      return {
        status: 200,
        headers: {
          "content-type": "application/json",
          "payment-response": "simulated-x402-payment-response",
        },
        body: buildX402FundSuccessBody(trimmedIntent, tenantId),
        phase: "funded",
      };
    }

    return null;
  }
}
