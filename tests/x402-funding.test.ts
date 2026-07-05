import { describe, expect, it, vi } from "vitest";

import type { FundIntentResult } from "../src/index.js";
import {
  PaybondX402FundingFailedError,
  PaybondX402FundingPendingError,
  buildX402FundRequestEnvelope,
  executeFundWithX402,
} from "../src/x402-funding.js";

const INTENT_ID = "550e8400-e29b-41d4-a716-446655440010";

function fundResult(
  overrides: Partial<FundIntentResult> & Pick<FundIntentResult, "statusCode">,
): FundIntentResult {
  return {
    intentId: INTENT_ID,
    tenant: "tenant-a",
    state: "open",
    settlementRail: "x402_usdc_base",
    currency: "usd",
    amountCents: 2000,
    funded: false,
    ...overrides,
  };
}

describe("executeFundWithX402", () => {
  it("returns immediately when the first fund call is already funded", async () => {
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi.fn(async () => funded);

    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment: vi.fn(),
        issueRecognitionProof: vi.fn(),
        fund,
      }),
    ).resolves.toBe(funded);
    expect(fund).toHaveBeenCalledTimes(1);
  });

  it("signs a 402 challenge, retries with payment-signature, and returns 200", async () => {
    const challenge = fundResult({
      statusCode: 402,
      paymentRequired: "x402-requirements",
    });
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi
      .fn()
      .mockResolvedValueOnce(challenge)
      .mockResolvedValueOnce(funded);
    const signPayment = vi.fn(async () => "signed-payment");
    const issueRecognitionProof = vi.fn(async () => ({ nonce: "retry" }));

    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment,
        issueRecognitionProof,
        fund,
      }),
    ).resolves.toBe(funded);

    expect(signPayment).toHaveBeenCalledWith("x402-requirements");
    expect(issueRecognitionProof).toHaveBeenCalledWith(buildX402FundRequestEnvelope(INTENT_ID));
    expect(fund).toHaveBeenNthCalledWith(1, { recognitionProof: { nonce: "initial" } });
    expect(fund).toHaveBeenNthCalledWith(2, {
      recognitionProof: { nonce: "retry" },
      paymentSignature: "signed-payment",
    });
  });

  it("polls 202 responses until a capability token is returned", async () => {
    const pending = fundResult({ statusCode: 202, funding: { status: "authorization_pending" } as never });
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi
      .fn()
      .mockResolvedValueOnce(pending)
      .mockResolvedValueOnce(pending)
      .mockResolvedValueOnce(funded);
    const issueRecognitionProof = vi
      .fn()
      .mockResolvedValueOnce({ nonce: "poll-1" })
      .mockResolvedValueOnce({ nonce: "poll-2" });

    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment: vi.fn(),
        issueRecognitionProof,
        pollOptions: { maxAttempts: 5, intervalMs: 0 },
        fund,
      }),
    ).resolves.toBe(funded);

    expect(fund).toHaveBeenCalledTimes(3);
    expect(issueRecognitionProof).toHaveBeenCalledTimes(2);
  });

  it("raises PaybondX402FundingPendingError when polling exhausts maxAttempts", async () => {
    const pending = fundResult({ statusCode: 202, funding: { status: "authorization_pending" } as never });
    const fund = vi.fn(async () => pending);
    const issueRecognitionProof = vi.fn(async () => ({ nonce: "poll" }));

    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment: vi.fn(),
        issueRecognitionProof,
        pollOptions: { maxAttempts: 2, intervalMs: 0 },
        fund,
      }),
    ).rejects.toBeInstanceOf(PaybondX402FundingPendingError);
  });

  it("raises PaybondX402FundingFailedError when 402 is missing payment-required", async () => {
    const challenge = fundResult({ statusCode: 402 });
    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment: vi.fn(),
        issueRecognitionProof: vi.fn(),
        fund: vi.fn(async () => challenge),
      }),
    ).rejects.toBeInstanceOf(PaybondX402FundingFailedError);
  });

  it("raises PaybondX402FundingFailedError on terminal authorization_failed status", async () => {
    const failed = fundResult({
      statusCode: 202,
      funding: { status: "authorization_failed" } as never,
    });
    await expect(
      executeFundWithX402({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        signPayment: vi.fn(),
        issueRecognitionProof: vi.fn(),
        fund: vi.fn(async () => failed),
      }),
    ).rejects.toBeInstanceOf(PaybondX402FundingFailedError);
  });
});
