import type { AgentRecognitionProofV1, FundIntentResult } from "./index.js";
import {
  buildX402FundRequestEnvelope,
  type FundRequestEnvelope,
  type X402FundPollOptions,
} from "./x402-funding.js";

/** Raw `WWW-Authenticate: Payment …` challenge value from Harbor or the gateway. */
export type PaymentAuthChallenge = string;

/** Parsed Payment Auth challenge parameters from a `WWW-Authenticate` header value. */
export type ParsedPaymentAuthChallenge = {
  raw: string;
  id?: string;
  realm?: string;
  method?: string;
  intent?: string;
  request?: string;
};

export type MppFundPollOptions = X402FundPollOptions;

const DEFAULT_MAX_ATTEMPTS = 30;
const DEFAULT_INTERVAL_MS = 2_000;

const TERMINAL_MPP_FUNDING_STATUSES = new Set([
  "authorization_failed",
  "capture_failed",
  "void_failed",
  "credential_rejected",
  "payment_failed",
  "charge_failed",
  "session_open_failed",
]);

const MPP_CHARGE_EXPECTED = { intent: "charge", method: "stripe" } as const;
const MPP_SESSION_EXPECTED = { intent: "session", method: "tempo" } as const;

/** Raised when MPP funding cannot complete (missing challenge, terminal rail status, unexpected HTTP). */
export class PaybondMppFundingFailedError extends Error {
  readonly intentId: string;
  readonly lastResult?: FundIntentResult;

  constructor(
    message: string,
    init: { intentId: string; lastResult?: FundIntentResult; cause?: unknown },
  ) {
    super(message, { cause: init.cause });
    this.name = "PaybondMppFundingFailedError";
    this.intentId = init.intentId;
    this.lastResult = init.lastResult;
  }
}

/** Raised when polling exhausts `maxAttempts` before Harbor returns a funded capability token. */
export class PaybondMppFundingPendingError extends Error {
  readonly intentId: string;
  readonly lastResult: FundIntentResult;
  readonly attempts: number;

  constructor(
    message: string,
    init: { intentId: string; lastResult: FundIntentResult; attempts: number },
  ) {
    super(message);
    this.name = "PaybondMppFundingPendingError";
    this.intentId = init.intentId;
    this.lastResult = init.lastResult;
    this.attempts = init.attempts;
  }
}

/**
 * Parses a `WWW-Authenticate: Payment …` challenge into structured parameters.
 *
 * @throws Error when the value is empty or does not start with the Payment scheme.
 */
export function parsePaymentAuthChallenge(raw: string): ParsedPaymentAuthChallenge {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("Payment Auth challenge must be non-empty");
  }
  if (!/^payment\b/i.test(trimmed)) {
    throw new Error("expected Payment Auth challenge");
  }

  const params: Record<string, string> = {};
  const afterScheme = trimmed.replace(/^payment\s+/i, "");
  const paramRe = /([a-zA-Z_][\w-]*)=(?:"([^"]*)"|([^,\s]+))/g;
  let match: RegExpExecArray | null;
  while ((match = paramRe.exec(afterScheme)) !== null) {
    params[match[1].toLowerCase()] = match[2] ?? match[3] ?? "";
  }

  return {
    raw: trimmed,
    id: params.id,
    realm: params.realm,
    method: params.method,
    intent: params.intent,
    request: params.request,
  };
}

function selectMppPaymentChallenge(
  wwwAuthenticate: string[] | undefined,
  expected: { intent: string; method: string },
): PaymentAuthChallenge {
  if (!wwwAuthenticate?.length) {
    throw new Error("MPP fund challenge missing WWW-Authenticate Payment header");
  }

  for (const header of wwwAuthenticate) {
    const parsed = parsePaymentAuthChallenge(header);
    if (parsed.intent === expected.intent && parsed.method === expected.method) {
      return parsed.raw;
    }
  }

  if (wwwAuthenticate.length === 1) {
    const parsed = parsePaymentAuthChallenge(wwwAuthenticate[0]);
    if (parsed.intent !== expected.intent || parsed.method !== expected.method) {
      throw new Error(
        `MPP fund challenge intent/method mismatch: expected intent=${expected.intent} method=${expected.method}, got intent=${parsed.intent ?? "unknown"} method=${parsed.method ?? "unknown"}`,
      );
    }
    return parsed.raw;
  }

  throw new Error(
    `MPP fund challenge missing Payment Auth header for intent=${expected.intent} method=${expected.method}`,
  );
}

/** Selects the Stripe MPP charge challenge from `WWW-Authenticate` values. */
export function selectMppChargeChallenge(wwwAuthenticate: string[] | undefined): PaymentAuthChallenge {
  return selectMppPaymentChallenge(wwwAuthenticate, MPP_CHARGE_EXPECTED);
}

/** Selects the Tempo MPP session challenge from `WWW-Authenticate` values. */
export function selectMppSessionChallenge(wwwAuthenticate: string[] | undefined): PaymentAuthChallenge {
  return selectMppPaymentChallenge(wwwAuthenticate, MPP_SESSION_EXPECTED);
}

/** Canonical `/fund` request envelope for Gateway `POST /harbor/intents/{intentId}/fund`. */
export function buildMppFundRequestEnvelope(intentId: string): FundRequestEnvelope {
  return buildX402FundRequestEnvelope(intentId);
}

function isFundingComplete(result: FundIntentResult): boolean {
  if (result.capabilityToken?.trim()) {
    return true;
  }
  return result.statusCode === 200 && result.funded;
}

function isTerminalFundingFailure(result: FundIntentResult): boolean {
  const status = result.funding?.status?.trim();
  return status !== undefined && TERMINAL_MPP_FUNDING_STATUSES.has(status);
}

function failureMessage(result: FundIntentResult): string {
  const status = result.funding?.status ?? result.state;
  return `MPP funding failed for intent ${result.intentId} (status=${status})`;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export type ExecuteFundWithMppParams = {
  intentId: string;
  recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
  /** App-owned callback that turns a Payment Auth challenge into a credential token or header value. */
  createPaymentCredential: (challenge: PaymentAuthChallenge) => Promise<string>;
  issueRecognitionProof: (
    envelope: FundRequestEnvelope,
  ) => Promise<AgentRecognitionProofV1 | Record<string, unknown>>;
  pollOptions?: MppFundPollOptions;
  selectChallenge: (wwwAuthenticate: string[] | undefined) => PaymentAuthChallenge;
  fund: (args: {
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    paymentAuthorization?: string;
  }) => Promise<FundIntentResult>;
};

/**
 * Orchestrate MPP `/fund`: handle 402 Payment Auth challenges, retry with credentials, poll until funded.
 *
 * Wallet and SPT secrets stay app-owned — pass injectable `createPaymentCredential` and
 * `issueRecognitionProof` callbacks; Paybond never stores MPP signing material.
 */
export async function executeFundWithMpp(params: ExecuteFundWithMppParams): Promise<FundIntentResult> {
  const intentId = params.intentId.trim();
  if (!intentId) {
    throw new Error("fundWithMpp: intentId is required");
  }

  const maxAttempts = Math.max(1, params.pollOptions?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS);
  const intervalMs = Math.max(0, params.pollOptions?.intervalMs ?? DEFAULT_INTERVAL_MS);
  const envelope = buildMppFundRequestEnvelope(intentId);

  let paymentAuthorization: string | undefined;
  let result = await params.fund({ recognitionProof: params.recognitionProof });

  if (result.statusCode === 402) {
    const challenge = params.selectChallenge(result.wwwAuthenticate);
    paymentAuthorization = (await params.createPaymentCredential(challenge)).trim();
    if (!paymentAuthorization) {
      throw new PaybondMppFundingFailedError("MPP createPaymentCredential returned an empty credential", {
        intentId,
        lastResult: result,
      });
    }
    const retryProof = await params.issueRecognitionProof(envelope);
    result = await params.fund({
      recognitionProof: retryProof,
      paymentAuthorization,
    });
  }

  if (isTerminalFundingFailure(result)) {
    throw new PaybondMppFundingFailedError(failureMessage(result), { intentId, lastResult: result });
  }
  if (isFundingComplete(result)) {
    return result;
  }

  let attempts = 0;
  while (result.statusCode === 202 || (!isFundingComplete(result) && result.statusCode === 200)) {
    attempts += 1;
    if (attempts > maxAttempts) {
      throw new PaybondMppFundingPendingError(
        `MPP funding still pending after ${maxAttempts} poll attempt(s) for intent ${intentId}`,
        { intentId, lastResult: result, attempts: maxAttempts },
      );
    }
    if (intervalMs > 0) {
      await sleep(intervalMs);
    }
    const pollProof = await params.issueRecognitionProof(envelope);
    result = await params.fund({
      recognitionProof: pollProof,
      ...(paymentAuthorization ? { paymentAuthorization } : {}),
    });
    if (isTerminalFundingFailure(result)) {
      throw new PaybondMppFundingFailedError(failureMessage(result), { intentId, lastResult: result });
    }
    if (isFundingComplete(result)) {
      return result;
    }
  }

  if (isFundingComplete(result)) {
    return result;
  }

  throw new PaybondMppFundingFailedError(
    `unexpected MPP fund response HTTP ${result.statusCode} for intent ${intentId}`,
    { intentId, lastResult: result },
  );
}

/** One-shot Stripe MPP charge funding through Payment Auth semantics. */
export async function executeFundWithMppCharge(
  params: Omit<ExecuteFundWithMppParams, "selectChallenge">,
): Promise<FundIntentResult> {
  return executeFundWithMpp({
    ...params,
    selectChallenge: selectMppChargeChallenge,
  });
}

/** Tempo MPP session funding through Payment Auth semantics. */
export async function executeFundWithMppSession(
  params: Omit<ExecuteFundWithMppParams, "selectChallenge">,
): Promise<FundIntentResult> {
  return executeFundWithMpp({
    ...params,
    selectChallenge: selectMppSessionChallenge,
  });
}
