import { describe, expect, it } from "vitest";

import {
  X402FundStateMachine,
  X402_DEV_CAPABILITY_TOKEN,
  X402_DEV_PAYMENT_REQUIRED,
  X402_DEV_WIREMOCK_INTENT_ID,
  X402_DEV_WIREMOCK_TENANT_ID,
} from "../src/dev/x402-fund-mock.js";
import { createOfflineDevGatewayFetch, OFFLINE_DEV_TENANT_ID } from "../src/dev/offline-gateway.js";
import { executeFundWithX402 } from "../src/x402-funding.js";
import type { FundIntentResult } from "../src/index.js";

const INTENT_ID = X402_DEV_WIREMOCK_INTENT_ID;

describe("X402FundStateMachine", () => {
  it("returns 402, 202, then 200 with capability token", () => {
    const machine = new X402FundStateMachine();

    const challenge = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, undefined);
    expect(challenge?.status).toBe(402);
    expect(challenge?.headers["payment-required"]).toBe(X402_DEV_PAYMENT_REQUIRED);
    expect(challenge?.body.funded).toBe(false);

    const pending = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, "signed-payment");
    expect(pending?.status).toBe(202);
    expect(pending?.headers["payment-response"]).toBeTruthy();
    expect((pending?.body.funding as Record<string, unknown>).status).toBe("authorization_pending");

    const funded = machine.next(INTENT_ID, X402_DEV_WIREMOCK_TENANT_ID, "signed-payment");
    expect(funded?.status).toBe(200);
    expect(funded?.body.capability_token).toBe(X402_DEV_CAPABILITY_TOKEN);
    expect(funded?.body.funded).toBe(true);
  });
});

describe("createOfflineDevGatewayFetch x402 fund", () => {
  it("supports fundWithX402 end-to-end against the offline gateway", async () => {
    const fetchMock = createOfflineDevGatewayFetch();
    const gatewayBase = "https://offline.dev";
    let callCount = 0;

    const fund = async (args: {
      recognitionProof: Record<string, unknown>;
      paymentSignature?: string;
    }): Promise<FundIntentResult> => {
      callCount += 1;
      const headers: Record<string, string> = {
        "content-type": "application/json",
        "x-tenant-id": OFFLINE_DEV_TENANT_ID,
        "x-paybond-agent-recognition-proof": JSON.stringify(args.recognitionProof),
      };
      if (args.paymentSignature) {
        headers["payment-signature"] = args.paymentSignature;
      }
      const res = await fetchMock(`${gatewayBase}/harbor/intents/${INTENT_ID}/fund`, {
        method: "POST",
        headers,
        body: JSON.stringify({}),
      });
      const body = (await res.json()) as Record<string, unknown>;
      const funding =
        body.funding && typeof body.funding === "object" && !Array.isArray(body.funding)
          ? (body.funding as FundIntentResult["funding"])
          : undefined;
      return {
        statusCode: res.status as 200 | 202 | 402,
        paymentRequired: res.headers.get("payment-required") ?? undefined,
        paymentResponse: res.headers.get("payment-response") ?? undefined,
        intentId: String(body.intent_id ?? INTENT_ID),
        tenant: String(body.tenant ?? OFFLINE_DEV_TENANT_ID),
        state: String(body.state ?? ""),
        settlementRail: "x402_usdc_base",
        currency: String(body.currency ?? "usd"),
        amountCents: Number(body.amount_cents ?? 0),
        funded: Boolean(body.funded),
        capabilityToken:
          typeof body.capability_token === "string" ? body.capability_token : undefined,
        funding,
      };
    };

    const result = await executeFundWithX402({
      intentId: INTENT_ID,
      recognitionProof: { proof: "initial" },
      signPayment: async (challenge) => {
        expect(challenge).toBe(X402_DEV_PAYMENT_REQUIRED);
        return "signed-payment";
      },
      issueRecognitionProof: async () => ({ proof: "fresh" }),
      pollOptions: { maxAttempts: 3, intervalMs: 0 },
      fund,
    });

    expect(result.statusCode).toBe(200);
    expect(result.capabilityToken).toBe(X402_DEV_CAPABILITY_TOKEN);
    expect(callCount).toBe(3);
  });
});
