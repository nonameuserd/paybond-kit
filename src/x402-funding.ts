import type { AgentRecognitionProofV1, FundIntentResult } from "./index.js";

/** Value of the Harbor `payment-required` response header on x402 fund challenges. */
export type PaymentRequired = string;

/** Request metadata bound by each fresh `AgentRecognitionProofV1` for `/fund`. */
export type FundRequestEnvelope = {
  intentId: string;
  method: "POST";
  path: string;
  body: Record<string, unknown>;
};

export type X402FundPollOptions = {
  maxAttempts?: number;
  intervalMs?: number;
};

const DEFAULT_MAX_ATTEMPTS = 30;
const DEFAULT_INTERVAL_MS = 2_000;
const FUND_REQUEST_BODY: Record<string, unknown> = {};

const TERMINAL_X402_FUNDING_STATUSES = new Set([
  "authorization_failed",
  "capture_failed",
  "void_failed",
]);

/** Raised when x402 funding cannot complete (missing challenge, terminal rail status, unexpected HTTP). */
export class PaybondX402FundingFailedError extends Error {
  readonly intentId: string;
  readonly lastResult?: FundIntentResult;

  constructor(
    message: string,
    init: { intentId: string; lastResult?: FundIntentResult; cause?: unknown },
  ) {
    super(message, { cause: init.cause });
    this.name = "PaybondX402FundingFailedError";
    this.intentId = init.intentId;
    this.lastResult = init.lastResult;
  }
}

/** Raised when polling exhausts `maxAttempts` before Harbor returns a funded capability token. */
export class PaybondX402FundingPendingError extends Error {
  readonly intentId: string;
  readonly lastResult: FundIntentResult;
  readonly attempts: number;

  constructor(
    message: string,
    init: { intentId: string; lastResult: FundIntentResult; attempts: number },
  ) {
    super(message);
    this.name = "PaybondX402FundingPendingError";
    this.intentId = init.intentId;
    this.lastResult = init.lastResult;
    this.attempts = init.attempts;
  }
}

/** Canonical `/fund` request envelope for Gateway `POST /harbor/intents/{intentId}/fund`. */
export function buildX402FundRequestEnvelope(intentId: string): FundRequestEnvelope {
  const trimmed = intentId.trim();
  if (!trimmed) {
    throw new Error("fundWithX402: intentId is required");
  }
  return {
    intentId: trimmed,
    method: "POST",
    path: `/harbor/intents/${trimmed}/fund`,
    body: FUND_REQUEST_BODY,
  };
}

function isFundingComplete(result: FundIntentResult): boolean {
  if (result.capabilityToken?.trim()) {
    return true;
  }
  return result.statusCode === 200 && result.funded;
}

function isTerminalFundingFailure(result: FundIntentResult): boolean {
  const status = result.funding?.status?.trim();
  return status !== undefined && TERMINAL_X402_FUNDING_STATUSES.has(status);
}

function failureMessage(result: FundIntentResult): string {
  const status = result.funding?.status ?? result.state;
  return `x402 funding failed for intent ${result.intentId} (status=${status})`;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export type ExecuteFundWithX402Params = {
  intentId: string;
  recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
  signPayment: (challenge: PaymentRequired) => Promise<string>;
  issueRecognitionProof: (
    envelope: FundRequestEnvelope,
  ) => Promise<AgentRecognitionProofV1 | Record<string, unknown>>;
  pollOptions?: X402FundPollOptions;
  fund: (args: {
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    paymentSignature?: string;
  }) => Promise<FundIntentResult>;
};

/**
 * Orchestrate x402 `/fund`: handle 402 signing, retry with `payment-signature`, and poll 202 until funded.
 */
export async function executeFundWithX402(params: ExecuteFundWithX402Params): Promise<FundIntentResult> {
  const intentId = params.intentId.trim();
  if (!intentId) {
    throw new Error("fundWithX402: intentId is required");
  }

  const maxAttempts = Math.max(1, params.pollOptions?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
  const intervalMs = Math.max(0, params.pollOptions?.intervalMs ?? DEFAULT_INTERVAL_MS);
  const envelope = buildX402FundRequestEnvelope(intentId);

  let paymentSignature: string | undefined;
  let result = await params.fund({ recognitionProof: params.recognitionProof });

  if (result.statusCode === 402) {
    if (!result.paymentRequired?.trim()) {
      throw new PaybondX402FundingFailedError(
        "x402 fund challenge missing payment-required header",
        { intentId, lastResult: result },
      );
    }
    paymentSignature = (await params.signPayment(result.paymentRequired)).trim();
    if (!paymentSignature) {
      throw new PaybondX402FundingFailedError("x402 signPayment returned an empty payment signature", {
        intentId,
        lastResult: result,
      });
    }
    const retryProof = await params.issueRecognitionProof(envelope);
    result = await params.fund({
      recognitionProof: retryProof,
      paymentSignature,
    });
  }

  if (isTerminalFundingFailure(result)) {
    throw new PaybondX402FundingFailedError(failureMessage(result), { intentId, lastResult: result });
  }
  if (isFundingComplete(result)) {
    return result;
  }

  let attempts = 0;
  while (result.statusCode === 202 || (!isFundingComplete(result) && result.statusCode === 200)) {
    attempts += 1;
    if (attempts > maxAttempts) {
      throw new PaybondX402FundingPendingError(
        `x402 funding still pending after ${maxAttempts} poll attempt(s) for intent ${intentId}`,
        { intentId, lastResult: result, attempts: maxAttempts },
      );
    }
    if (intervalMs > 0) {
      await sleep(intervalMs);
    }
    const pollProof = await params.issueRecognitionProof(envelope);
    result = await params.fund({
      recognitionProof: pollProof,
      ...(paymentSignature ? { paymentSignature } : {}),
    });
    if (isTerminalFundingFailure(result)) {
      throw new PaybondX402FundingFailedError(failureMessage(result), { intentId, lastResult: result });
    }
    if (isFundingComplete(result)) {
      return result;
    }
  }

  if (isFundingComplete(result)) {
    return result;
  }

  throw new PaybondX402FundingFailedError(
    `unexpected x402 fund response HTTP ${result.statusCode} for intent ${intentId}`,
    { intentId, lastResult: result },
  );
}
