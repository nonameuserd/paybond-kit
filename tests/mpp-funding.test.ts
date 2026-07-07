import { describe, expect, it, vi } from "vitest";

import type { FundIntentResult } from "../src/index.js";
import {
  PaybondMppFundingFailedError,
  PaybondMppFundingPendingError,
  buildMppFundRequestEnvelope,
  executeFundWithMppCharge,
  executeFundWithMppSession,
  parsePaymentAuthChallenge,
  selectMppChargeChallenge,
  selectMppSessionChallenge,
} from "../src/mpp-funding.js";

const INTENT_ID = "550e8400-e29b-41d4-a716-446655440011";

const CHARGE_CHALLENGE =
  'Payment id="abc", realm="api.example.com", method="stripe", intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"';
const SESSION_CHALLENGE =
  'Payment id="def", realm="api.example.com", method="tempo", intent="session", request="eyJ0ZXN0Ijoic2VzcyJ9"';

function fundResult(
  overrides: Partial<FundIntentResult> & Pick<FundIntentResult, "statusCode">,
): FundIntentResult {
  return {
    intentId: INTENT_ID,
    tenant: "tenant-a",
    state: "open",
    settlementRail: "stripe_mpp",
    currency: "usd",
    amountCents: 2000,
    funded: false,
    ...overrides,
  };
}

describe("parsePaymentAuthChallenge", () => {
  it("parses Payment Auth challenge parameters", () => {
    expect(parsePaymentAuthChallenge(CHARGE_CHALLENGE)).toMatchObject({
      id: "abc",
      realm: "api.example.com",
      method: "stripe",
      intent: "charge",
      request: "eyJ0ZXN0IjoidHJ1ZSJ9",
    });
  });
});

describe("selectMppChargeChallenge", () => {
  it("selects the charge challenge when both charge and session are present", () => {
    expect(selectMppChargeChallenge([CHARGE_CHALLENGE, SESSION_CHALLENGE])).toBe(CHARGE_CHALLENGE);
  });
});

describe("selectMppSessionChallenge", () => {
  it("selects the session challenge when both charge and session are present", () => {
    expect(selectMppSessionChallenge([CHARGE_CHALLENGE, SESSION_CHALLENGE])).toBe(SESSION_CHALLENGE);
  });
});

describe("executeFundWithMppCharge", () => {
  it("returns immediately when the first fund call is already funded", async () => {
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi.fn(async () => funded);

    await expect(
      executeFundWithMppCharge({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential: vi.fn(),
        issueRecognitionProof: vi.fn(),
        fund,
      }),
    ).resolves.toBe(funded);
    expect(fund).toHaveBeenCalledTimes(1);
  });

  it("creates a credential from a 402 challenge and retries with paymentAuthorization", async () => {
    const challenge = fundResult({
      statusCode: 402,
      wwwAuthenticate: [CHARGE_CHALLENGE],
    });
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi.fn().mockResolvedValueOnce(challenge).mockResolvedValueOnce(funded);
    const createPaymentCredential = vi.fn(async () => "mpp-credential");
    const issueRecognitionProof = vi.fn(async () => ({ nonce: "retry" }));

    await expect(
      executeFundWithMppCharge({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential,
        issueRecognitionProof,
        fund,
      }),
    ).resolves.toBe(funded);

    expect(createPaymentCredential).toHaveBeenCalledWith(CHARGE_CHALLENGE);
    expect(issueRecognitionProof).toHaveBeenCalledWith(buildMppFundRequestEnvelope(INTENT_ID));
    expect(fund).toHaveBeenNthCalledWith(1, { recognitionProof: { nonce: "initial" } });
    expect(fund).toHaveBeenNthCalledWith(2, {
      recognitionProof: { nonce: "retry" },
      paymentAuthorization: "mpp-credential",
    });
  });

  it("polls until funded when Harbor returns 202", async () => {
    const challenge = fundResult({
      statusCode: 402,
      wwwAuthenticate: [CHARGE_CHALLENGE],
    });
    const pending = fundResult({
      statusCode: 202,
      funding: { settlementRail: "stripe_mpp", status: "authorization_pending" },
    });
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi
      .fn()
      .mockResolvedValueOnce(challenge)
      .mockResolvedValueOnce(pending)
      .mockResolvedValueOnce(funded);
    const createPaymentCredential = vi.fn(async () => "mpp-credential");
    const issueRecognitionProof = vi
      .fn()
      .mockResolvedValueOnce({ nonce: "retry" })
      .mockResolvedValueOnce({ nonce: "poll" });

    await expect(
      executeFundWithMppCharge({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential,
        issueRecognitionProof,
        pollOptions: { maxAttempts: 3, intervalMs: 0 },
        fund,
      }),
    ).resolves.toBe(funded);

    expect(fund).toHaveBeenCalledTimes(3);
    expect(fund).toHaveBeenLastCalledWith({
      recognitionProof: { nonce: "poll" },
      paymentAuthorization: "mpp-credential",
    });
  });

  it("throws PaybondMppFundingPendingError after max poll attempts", async () => {
    const pending = fundResult({
      statusCode: 202,
      funding: { settlementRail: "stripe_mpp", status: "authorization_pending" },
    });
    const fund = vi.fn(async () => pending);

    await expect(
      executeFundWithMppCharge({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential: vi.fn(),
        issueRecognitionProof: vi.fn(async () => ({ nonce: "poll" })),
        pollOptions: { maxAttempts: 2, intervalMs: 0 },
        fund,
      }),
    ).rejects.toBeInstanceOf(PaybondMppFundingPendingError);
  });

  it("throws PaybondMppFundingFailedError on terminal funding status", async () => {
    const failed = fundResult({
      statusCode: 200,
      funding: { settlementRail: "stripe_mpp", status: "authorization_failed" },
    });
    const fund = vi.fn(async () => failed);

    await expect(
      executeFundWithMppCharge({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential: vi.fn(),
        issueRecognitionProof: vi.fn(),
        fund,
      }),
    ).rejects.toBeInstanceOf(PaybondMppFundingFailedError);
  });
});

describe("executeFundWithMppSession", () => {
  it("selects the session challenge on 402", async () => {
    const challenge = fundResult({
      statusCode: 402,
      wwwAuthenticate: [CHARGE_CHALLENGE, SESSION_CHALLENGE],
    });
    const funded = fundResult({
      statusCode: 200,
      funded: true,
      capabilityToken: "cap-token",
    });
    const fund = vi.fn().mockResolvedValueOnce(challenge).mockResolvedValueOnce(funded);
    const createPaymentCredential = vi.fn(async () => "session-credential");
    const issueRecognitionProof = vi.fn(async () => ({ nonce: "retry" }));

    await expect(
      executeFundWithMppSession({
        intentId: INTENT_ID,
        recognitionProof: { nonce: "initial" },
        createPaymentCredential,
        issueRecognitionProof,
        fund,
      }),
    ).resolves.toBe(funded);

    expect(createPaymentCredential).toHaveBeenCalledWith(SESSION_CHALLENGE);
  });
});
