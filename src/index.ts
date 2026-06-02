/**
 * Paybond Kit — TypeScript Gateway client with tenant binding, retries, capability verification,
 * and signed intent/evidence helpers.
 */

import {
  buildSignedCreateIntentBody,
  type BuildSignedCreateIntentParams,
  type SettlementRail,
} from "./principal-intent.js";
import { signPayeeEvidenceBinding, type SignPayeeEvidenceParams } from "./payee-evidence.js";

declare const Buffer: {
  from(input: string, encoding?: string): {
    toString(encoding?: string): string;
  };
};

export type VerifyCapabilityResult = {
  allow: boolean;
  auditId: string;
  tenant: string;
  intentId: string;
  code?: string;
  message?: string;
};

export type SubmitEvidenceResult = {
  intentId: string;
  tenant: string;
  state: string;
  predicatePassed?: boolean;
};

export type IntentFundingResult = {
  settlementRail: SettlementRail;
  harborFundEndpoint?: string;
  status?: string;
  paymentSessionId?: string;
  paymentUrl?: string;
  stripePaymentIntentId?: string;
  clientSecret?: string;
  stripeConnectDestination?: string;
  stripeCustomerId?: string;
  latestChargeId?: string;
  paymentMethodId?: string;
  mandateId?: string;
  financialConnectionsAccountId?: string;
  bankLast4?: string;
  bankFingerprint?: string;
  bankName?: string;
  asset?: string;
  network?: string;
  authorizationId?: string;
  captureId?: string;
  voidId?: string;
  transferId?: string;
  refundId?: string;
  expectedDebitDate?: string;
  paymentReference?: string;
  refundReference?: string;
  refundReferenceStatus?: string;
  sourceAddress?: string;
  targetAddress?: string;
  authorizationExpiresAt?: string;
  captureExpiresAt?: string;
  refundExpiresAt?: string;
  onchainTransactionHashes?: {
    authorizations?: string[];
    captures?: string[];
    voids?: string[];
    refunds?: string[];
  };
};

export type FundIntentResult = {
  statusCode: 200 | 202 | 402;
  paymentRequired?: string;
  paymentResponse?: string;
  intentId: string;
  tenant: string;
  state: string;
  settlementRail: SettlementRail;
  currency: string;
  amountCents: number;
  funded: boolean;
  capabilityToken?: string;
  funding?: IntentFundingResult;
};

export const DEFAULT_PAYBOND_GATEWAY_BASE_URL = "https://api.paybond.ai";

function defaultGatewayBaseUrl(value?: string): string {
  const trimmed = value?.trim();
  return trimmed ? trimmed : DEFAULT_PAYBOND_GATEWAY_BASE_URL;
}

/** Async supplier for upstream Harbor bearer tokens on low-level direct clients. */
export type HarborBearerSupplier = () => Promise<string | null | undefined>;

/**
 * Structured HTTP failure from Harbor with operator-facing diagnostics.
 */
export class HarborHttpError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;

  constructor(message: string, init: { statusCode: number; url: string; bodyText: string }) {
    super(message);
    this.name = "HarborHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
  }
}

/**
 * Gateway rejected service-account credentials or returned an unusable tenant-principal payload.
 */
export class GatewayAuthError extends Error {
  readonly statusCode: number | undefined;
  readonly bodyText: string | undefined;

  constructor(
    message: string,
    init?: { statusCode?: number; bodyText?: string },
  ) {
    super(message);
    this.name = "GatewayAuthError";
    this.statusCode = init?.statusCode;
    this.bodyText = init?.bodyText;
  }
}

/**
 * Structured HTTP failure from gateway Signal read routes.
 */
export class SignalHttpError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;

  constructor(message: string, init: { statusCode: number; url: string; bodyText: string }) {
    super(message);
    this.name = "SignalHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
  }
}

export type SignalMetrics = {
  terminal_intents: number;
  released: number;
  refunded: number;
  disputed: number;
  success_rate_bps: number;
  dispute_rate_bps: number;
  refund_rate_bps: number;
  mean_latency_nanos: number;
  latency_sample_count: number;
  receipted_volume_cents: number;
};

export type SignalConfidence = {
  band: string;
  support_score: number;
  summary: string;
};

export type SignalSupportDepth = {
  band: string;
  terminal_intents: number;
  receipted_volume_cents: number;
  history_depth: number;
  latency_sample_count: number;
};

export type SignalExplanationMetricDelta = {
  metric: string;
  previous: number;
  current: number;
  delta: number;
};

export type SignalExplanationDelta = {
  basis: string;
  previous_score: number;
  score_delta: number;
  previous_ledger_watermark_seq: number;
  changed_metrics: SignalExplanationMetricDelta[];
  reason_codes_added: string[];
  reason_codes_removed: string[];
  summary: string;
};

export type SignalSignedReceipt = {
  schema_version: number;
  receipt_version: string;
  tenant_id: string;
  operator_did: string;
  score_version: string;
  scoring_model: string;
  scoring_narrative: string;
  explanation_summary: string;
  ledger_watermark_seq: number;
  reason_codes: string[];
  confidence?: SignalConfidence;
  support_depth?: SignalSupportDepth;
  review_state?: string;
  explanation_delta?: SignalExplanationDelta;
  metrics: SignalMetrics;
  score: number;
  signing_algorithm: string;
  message_digest_hex: string;
  signing_public_key_hex: string;
  signature_hex: string;
};

export type SignalReceiptEnvelope = {
  schema_version: number;
  updated_at: string;
  receipt: SignalSignedReceipt;
};

export type SignalPortfolioOperator = {
  operator_did: string;
  receipt_version?: string;
  score: number;
  ledger_watermark_seq: number;
  receipt_message_digest_hex: string;
  confidence?: SignalConfidence;
  support_depth?: SignalSupportDepth;
  review_state?: string;
  explanation_delta?: SignalExplanationDelta;
};

export type SignalSignedPortfolioArtifact = {
  schema_version: number;
  artifact_version: string;
  kind: string;
  tenant_id: string;
  score_model_version: string;
  scoring_model: string;
  checkpoint_last_ledger_seq: number;
  operators: SignalPortfolioOperator[];
  signing_algorithm: string;
  message_digest_hex: string;
  signing_public_key_hex: string;
  signature_hex: string;
};

export type SignalPortfolioSummary = {
  schema_version: number;
  tenant_id: string;
  score_model_version: string;
  scoring_model: string;
  checkpoint_last_ledger_seq: number;
  operator_count: number;
  average_score: number;
  total_terminal_intents: number;
  total_receipted_volume_cents: number;
  operators_under_review: number;
};

export type SignalFraudSeverity = "elevated" | "high" | "critical";

export type SignalReviewState = "none" | "open" | "in_review" | "closed" | "all";

export type SignalFraudSignal = {
  code: string;
  severity: SignalFraudSeverity | string;
  category: string;
  window: string;
  evidence_count: number;
  summary: string;
  affects_score: false;
  signal_source?: string;
  first_seen_at?: string;
  last_seen_at?: string;
  evidence_binding_strength?: string;
  provider_event_refs?: string[];
  intent_refs?: string[];
};

export type SignalFraudAssessment = {
  fraud_signal_version: string;
  level: "none" | SignalFraudSeverity | string;
  highest_severity: "none" | SignalFraudSeverity | string;
  review_priority: "normal" | "elevated" | "high" | "urgent" | string;
  signal_count: number;
  severe_signal_count: number;
  summary: string;
};

export type SignalFraudReleaseGateMode = "review_only" | "critical_hold";

export type SignalFraudReleaseGateConfig = {
  mode: SignalFraudReleaseGateMode | string;
};

export type SignalFraudSignalFamilyReliability = {
  signal_family: string;
  reliable: boolean;
  stale: boolean;
  sparse: boolean;
  reviewed_count: number;
  labeled_outcome_count: number;
  review_precision_bps: number;
  min_signal_family_labeled_outcome_count: number;
  last_labeled_at?: string;
  reasons: string[];
  summary: string;
};

export type SignalFraudReleaseGateMetricsReliability = {
  reliable: boolean;
  stale: boolean;
  sparse: boolean;
  reviewed_count: number;
  labeled_outcome_count: number;
  review_precision_bps: number;
  min_reviewed_count: number;
  min_labeled_outcome_count: number;
  min_signal_family_labeled_outcome_count: number;
  min_review_precision_bps: number;
  last_labeled_at?: string;
  signal_families?: SignalFraudSignalFamilyReliability[];
  reasons: string[];
  summary: string;
};

export type SignalFraudReleaseGateDecision = {
  mode: SignalFraudReleaseGateMode | string;
  enforcement_enabled: boolean;
  metrics_reliable: boolean;
  release_allowed: boolean;
  hold_required: boolean;
  critical_signal_count: number;
  critical_signal_codes: string[];
  blocking_signal_codes?: string[];
  blocking_evidence_refs?: string[];
  reliability_reasons?: string[];
  reasons: string[];
  summary: string;
};

export type SignalFraudAssessmentResponse = {
  schema_version: number;
  tenant_id: string;
  operator_did: string;
  score_model_version: string;
  review_state: string;
  review_outcome: string;
  review_reasons: string[];
  fraud_signals: SignalFraudSignal[];
  fraud_assessment: SignalFraudAssessment;
  release_gate?: SignalFraudReleaseGateDecision;
  [key: string]: unknown;
};

export type SignalFraudReviewQueueItem = {
  operator_did: string;
  review_state: string;
  review_outcome: string;
  review_reasons: string[];
  anomaly_flagged: boolean;
  opened_at: string;
  reviewed_at: string;
  updated_at: string;
  last_receipt_message_digest_hex: string;
  fraud_signals: SignalFraudSignal[];
  fraud_assessment: SignalFraudAssessment;
  release_gate?: SignalFraudReleaseGateDecision;
  [key: string]: unknown;
};

export type SignalFraudReviewQueueResponse = {
  schema_version: number;
  tenant_id: string;
  score_model_version: string;
  items: SignalFraudReviewQueueItem[];
};

export type SignalFraudMetricsWindow = "24h" | "7d" | "30d";

export type SignalFraudMetricsResponse = {
  schema_version: number;
  tenant_id: string;
  score_model_version: string;
  fraud_signal_version: string;
  window: SignalFraudMetricsWindow | string;
  window_started_at: string;
  window_ended_at: string;
  generated_at: string;
  flagged_operator_count: number;
  critical_signal_count: number;
  high_signal_count: number;
  elevated_signal_count: number;
  review_open_count: number;
  review_load_count: number;
  reviewed_count: number;
  labeled_outcome_count: number;
  confirmed_risk_count: number;
  false_positive_count: number;
  needs_more_evidence_count: number;
  review_precision_bps: number;
  false_positive_rate_bps: number;
  confirmed_risk_rate_bps: number;
  labeled_coverage_bps: number;
  median_time_to_review_seconds: number;
  refund_burst_count: number;
  dispute_cluster_count: number;
  replay_appeal_abuse_count: number;
  critical_signal_hold_candidate_count: number;
  provider_signal_count: number;
  stale_label_gap_seconds: number;
  stale_signal_family_label_gap_count: number;
  backtest_summary: string;
  release_gate_config?: SignalFraudReleaseGateConfig;
  release_gate_metrics_reliability?: SignalFraudReleaseGateMetricsReliability;
};

export type SignalFraudReleaseGateConfigResponse = {
  schema_version: number;
  tenant_id: string;
  score_model_version: string;
  fraud_signal_version: string;
  generated_at: string;
  config: SignalFraudReleaseGateConfig;
  metrics_reliability: SignalFraudReleaseGateMetricsReliability;
};

export type SignalFraudReviewEventType =
  | "review_open_requested"
  | "appeal_requested"
  | "replay_requested"
  | "review_outcome_recorded"
  | SignalFraudReviewOutcome;

export type SignalFraudReviewOutcome = "confirmed_risk" | "false_positive" | "needs_more_evidence";

export type SignalFraudReviewEventInput = {
  eventType: SignalFraudReviewEventType | string;
  reviewOutcome?: SignalFraudReviewOutcome | string;
  review_outcome?: SignalFraudReviewOutcome | string;
  signalCode?: string;
  signal_code?: string;
  intentId?: string;
  intent_id?: string;
  providerEventId?: string;
  provider_event_id?: string;
  summary: string;
};

export type SignalFraudReviewEventResponse = {
  schema_version: number;
  tenant_id: string;
  operator_did: string;
  score_model_version: string;
  requested_event_type: string;
  recorded_event_type: string;
  review_outcome?: string;
  signal_code?: string;
  intent_id?: string;
  provider_event_id?: string;
  accepted: boolean;
  next_eligible_at?: string;
  [key: string]: unknown;
};

export type ListFraudReviewQueueOptions = {
  state?: SignalReviewState | string;
  severity?: SignalFraudSeverity | string;
  limit?: number;
  scoreVersion?: string;
};

export type GetFraudMetricsOptions = {
  window?: SignalFraudMetricsWindow | string;
  scoreVersion?: string;
};

export type A2AAgentCard = {
  name: string;
  description: string;
  supportedInterfaces: Array<{
    url: string;
    protocolBinding: string;
    protocolVersion: string;
    tenant?: string;
  }>;
  provider?: {
    url: string;
    organization: string;
  };
  version: string;
  documentationUrl?: string;
  capabilities: {
    streaming?: boolean;
    pushNotifications?: boolean;
    extendedAgentCard?: boolean;
    extensions?: Array<{
      uri?: string;
      description?: string;
      required?: boolean;
      params?: Record<string, unknown>;
    }>;
  };
  securitySchemes?: Record<string, unknown>;
  defaultInputModes: string[];
  defaultOutputModes: string[];
  skills: Array<{
    id: string;
    name: string;
    description: string;
    tags: string[];
    examples?: string[];
    inputModes?: string[];
    outputModes?: string[];
    securityRequirements?: Array<Record<string, string[]>>;
  }>;
};

export type A2ATaskField = {
  name: string;
  type: string;
  required: boolean;
  description: string;
};

export type A2ATaskParticipant = {
  role: string;
  required: boolean;
  description: string;
};

export type A2ATaskExample = {
  name: string;
  description: string;
  sampleInput?: Record<string, unknown>;
  sampleResponse?: Record<string, unknown>;
};

export type A2ASettlementTaskContractV1 = {
  schemaVersion: number;
  kind: string;
  id: string;
  name: string;
  description: string;
  url: string;
  routeBindings: string[];
  requiredTrustArtifacts: string[];
  settlementPhases: string[];
  participants: A2ATaskParticipant[];
  inputModes: string[];
  outputModes: string[];
  taskMetadataFields?: A2ATaskField[];
  inputFields: A2ATaskField[];
  resultFields: A2ATaskField[];
  examples?: A2ATaskExample[];
};

export type A2ATaskContractCatalogV1 = {
  schemaVersion: number;
  kind: string;
  agentCardUrl: string;
  documentationUrl?: string;
  contracts: A2ASettlementTaskContractV1[];
};

export type AgentMandateAuthorization = {
  kind: string;
  tenant_id: string;
  principal_subject?: string;
  principal_type?: string;
};

export type AgentMandateAgentIdentity = {
  subject: string;
  issuer?: string;
  key_id?: string;
  display_name?: string;
};

export type AgentMandateSpendCeiling = {
  amount_minor: number;
  currency: string;
};

export type AgentMandateSettlementRailPolicy = {
  default_rail: string;
  allowed_rails: string[];
};

export type AgentMandateConstraintReference = {
  kind: string;
  id?: string;
  version?: string;
  digest_sha256_hex?: string;
  uri?: string;
};

export type AgentMandateV1 = {
  schema_version: number;
  kind: string;
  authorization: AgentMandateAuthorization;
  agent: AgentMandateAgentIdentity;
  allowed_actions: string[];
  allowed_tools: string[];
  spend_ceiling: AgentMandateSpendCeiling;
  settlement: AgentMandateSettlementRailPolicy;
  constraint: AgentMandateConstraintReference;
  expires_at: string;
  nonce: string;
  human_presence_mode: string;
};

export type SignedAgentMandateV1 = AgentMandateV1 & {
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

export type AgentRecognitionVerifierContext = {
  tenant_id: string;
  verifier_id: string;
};

export type AgentRecognitionRequestEnvelope = {
  method: string;
  path: string;
  body_digest_sha256_hex: string;
};

export type AgentRecognitionProofV1 = {
  schema_version?: number;
  kind?: string;
  key_id: string;
  signature_algorithm?: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  purpose: string;
  verifier_context: AgentRecognitionVerifierContext;
  request_envelope: AgentRecognitionRequestEnvelope;
  message_digest_sha256_hex?: string;
  signing_public_key_ed25519_hex?: string;
  ed25519_signature_hex?: string;
};

export type ProtocolTransportBindingV1 = {
  source_protocol?: string;
  partner_platform?: string;
  external_authorization_id?: string;
  request_id?: string;
};

export type ProtocolAuthorizationReceiptV1 = {
  schema_version: number;
  kind: string;
  receipt_version: string;
  receipt_id: string;
  issued_at: string;
  status: string;
  intent_id: string;
  tenant_id: string;
  verifier_id: string;
  transport_binding: ProtocolTransportBindingV1;
  mandate_digest_sha256_hex: string;
  imported_mandate_signing_public_key_ed25519_hex: string;
  authorization: AgentMandateAuthorization;
  agent: AgentMandateAgentIdentity;
  allowed_actions: string[];
  allowed_tools: string[];
  spend_ceiling: AgentMandateSpendCeiling;
  settlement: AgentMandateSettlementRailPolicy;
  constraint: AgentMandateConstraintReference;
  expires_at: string;
  nonce: string;
  human_presence_mode: string;
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

export type ProtocolSettlementReceiptV1 = {
  schema_version: number;
  kind: string;
  receipt_version: string;
  receipt_id: string;
  issued_at: string;
  intent_id: string;
  tenant_id: string;
  verifier_id: string;
  transport_binding: ProtocolTransportBindingV1;
  authorization_receipt_id: string;
  mandate_digest_sha256_hex: string;
  harbor_state: string;
  predicate_passed?: boolean;
  settlement_rail: string;
  settlement_mode: string;
  principal_did: string;
  payee_did: string;
  currency: string;
  amount_cents: number;
  terminal_observed_at: string;
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

export type ImportAgentMandateV1Result = {
  valid: boolean;
  intent_id: string;
  mandate_digest_sha256_hex: string;
  mandate: AgentMandateV1;
  authorization_receipt: ProtocolAuthorizationReceiptV1;
};

export type VerifyProtocolReceiptV1Result = {
  valid: boolean;
  kind: string;
  receipt_id: string;
  tenant_id: string;
  receipt: ProtocolAuthorizationReceiptV1 | ProtocolSettlementReceiptV1 | Record<string, unknown>;
};

const agentRecognitionProofHeader = "x-paybond-agent-recognition-proof";

export class A2AHttpError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;

  constructor(message: string, init: { statusCode: number; url: string; bodyText: string }) {
    super(message);
    this.name = "A2AHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
  }
}

export class ProtocolHttpError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;
  readonly errorCode?: string;
  readonly errorMessage?: string;

  constructor(
    message: string,
    init: { statusCode: number; url: string; bodyText: string; errorCode?: string; errorMessage?: string },
  ) {
    super(message);
    this.name = "ProtocolHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
    const parsed = parseGatewayErrorEnvelope(init.bodyText);
    this.errorCode = init.errorCode ?? parsed.errorCode;
    this.errorMessage = init.errorMessage ?? parsed.errorMessage;
  }
}

function parseGatewayErrorEnvelope(text: string): { errorCode?: string; errorMessage?: string } {
  if (!text.trim().startsWith("{")) {
    return {};
  }
  try {
    const body = JSON.parse(text);
    if (body === null || Array.isArray(body) || typeof body !== "object") {
      return {};
    }
    const errorCode = typeof body.error === "string" && body.error.trim() ? body.error.trim() : undefined;
    const errorMessage = typeof body.message === "string" && body.message.trim() ? body.message.trim() : undefined;
    return { errorCode, errorMessage };
  } catch {
    return {};
  }
}

function protocolHTTPErrorMessage(prefix: string, statusCode: number, bodyText: string): string {
  const parsed = parseGatewayErrorEnvelope(bodyText);
  if (parsed.errorCode) {
    return `${prefix} HTTP ${statusCode} (${parsed.errorCode}): ${parsed.errorMessage ?? bodyText}`;
  }
  return `${prefix} HTTP ${statusCode}: ${bodyText}`;
}

function normalizeBase(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

function backoffMs(attempt: number): number {
  const base = 200 * 2 ** attempt;
  const jitter = Math.random() * 100;
  return Math.min(base + jitter, 5000);
}

function parseRetryAfterSeconds(v: string | null): number | null {
  if (!v) return null;
  const n = Number.parseFloat(v.trim());
  if (!Number.isFinite(n)) return null;
  return Math.min(n, 30);
}

export type PaybondEnvironment = "live" | "sandbox";

function normalizeExpectedEnvironment(value: PaybondEnvironment | undefined): PaybondEnvironment | null {
  if (value === undefined) return null;
  const env = String(value).trim();
  if (env === "live" || env === "sandbox") {
    return env;
  }
  throw new GatewayAuthError(`expectedEnvironment must be "live" or "sandbox", got ${JSON.stringify(value)}`);
}

function assertExpectedEnvironment(
  source: string,
  actualRaw: unknown,
  expected: PaybondEnvironment | null,
  bodyText?: string,
): void {
  if (!expected) return;
  const actual = typeof actualRaw === "string" ? actualRaw.trim() : "";
  if (!actual) {
    throw new GatewayAuthError(`${source} response missing environment`, { bodyText });
  }
  if (actual !== expected) {
    throw new GatewayAuthError(`${source} environment mismatch: expected=${expected} gateway=${actual}`, {
      bodyText,
    });
  }
}

/**
 * Tenant-scoped Harbor binding for one funded intent and one Biscuit capability token.
 */
export class PaybondCapabilityBinding {
  constructor(
    public readonly harbor: Pick<HarborClient | GatewayHarborClient, "tenantId" | "verifyCapability">,
    public readonly intentId: string,
    public readonly capabilityToken: string,
  ) {}

  async verifySpendCapability(input: PaybondSpendAuthorizationInput): Promise<VerifyCapabilityResult> {
    return this.harbor.verifyCapability({
      intentId: this.intentId,
      token: this.capabilityToken,
      operation: input.operation,
      requestedSpendCents: input.requestedSpendCents,
    });
  }

  async authorizeSpend(input: PaybondSpendAuthorizationInput): Promise<VerifyCapabilityResult> {
    return this.verifySpendCapability(input);
  }
}

export type PaybondSpendGuardInit = {
  harbor: Pick<HarborClient | GatewayHarborClient, "tenantId" | "verifyCapability">;
  intentId: string;
  capabilityToken: string;
};

export type PaybondSpendAuthorizationInput = {
  operation: string;
  requestedSpendCents?: number;
};

export class PaybondSpendDeniedError extends Error {
  readonly result: VerifyCapabilityResult;

  constructor(result: VerifyCapabilityResult) {
    const reason = result.message ?? result.code ?? "denied";
    super(`Paybond spend authorization denied: ${reason}`);
    this.name = "PaybondSpendDeniedError";
    this.result = result;
  }
}

export type PaybondToolHandler<TArgs extends unknown[], TResult> = (
  ...args: TArgs
) => TResult | Promise<TResult>;

export type PaybondGuardedToolHandler<TArgs extends unknown[], TResult> = (
  ...args: TArgs
) => Promise<Awaited<TResult>>;

export class PaybondSpendGuard {
  public readonly harbor: Pick<HarborClient | GatewayHarborClient, "tenantId" | "verifyCapability">;
  public readonly intentId: string;
  public readonly capabilityToken: string;

  constructor(init: PaybondSpendGuardInit | PaybondCapabilityBinding) {
    this.harbor = init.harbor;
    this.intentId = init.intentId;
    this.capabilityToken = init.capabilityToken;
  }

  async verifySpendCapability(input: PaybondSpendAuthorizationInput): Promise<VerifyCapabilityResult> {
    return this.harbor.verifyCapability({
      intentId: this.intentId,
      token: this.capabilityToken,
      operation: input.operation,
      requestedSpendCents: input.requestedSpendCents,
    });
  }

  async authorizeSpend(input: PaybondSpendAuthorizationInput): Promise<VerifyCapabilityResult> {
    return this.verifySpendCapability(input);
  }

  async assertSpendAuthorized(input: PaybondSpendAuthorizationInput): Promise<VerifyCapabilityResult> {
    const result = await this.authorizeSpend(input);
    if (!result.allow) {
      throw new PaybondSpendDeniedError(result);
    }
    return result;
  }

  guardTool<TArgs extends unknown[], TResult>(
    input: PaybondSpendAuthorizationInput,
    handler: PaybondToolHandler<TArgs, TResult>,
  ): PaybondGuardedToolHandler<TArgs, TResult> {
    return async (...args: TArgs): Promise<Awaited<TResult>> => {
      await this.assertSpendAuthorized(input);
      return await handler(...args);
    };
  }
}

export async function authorizeSpend(
  source: PaybondSpendGuardInit | PaybondCapabilityBinding,
  input: PaybondSpendAuthorizationInput,
): Promise<VerifyCapabilityResult> {
  return new PaybondSpendGuard(source).authorizeSpend(input);
}

export function guardTool<TArgs extends unknown[], TResult>(
  source: PaybondSpendGuardInit | PaybondCapabilityBinding,
  input: PaybondSpendAuthorizationInput,
  handler: PaybondToolHandler<TArgs, TResult>,
): PaybondGuardedToolHandler<TArgs, TResult> {
  return new PaybondSpendGuard(source).guardTool(input, handler);
}

export const paybondAgentToolSpendGuard = guardTool;
export const paybondRuntimeNeutralToolSpendGuard = guardTool;
export const paybondLangGraphToolSpendGuard = guardTool;
export const paybondMCPToolSpendGuard = guardTool;

export type PaybondRuntimeOperation<TCall> = string | ((call: TCall) => string);
export type PaybondRuntimeSpendCents<TCall> = number | ((call: TCall) => number | undefined);
export type PaybondRuntimeToolExecutor<TCall, TResult> = (
  call: TCall,
) => TResult | Promise<TResult>;
export type PaybondRuntimeDenyHandler<TCall, TResult> = (
  result: VerifyCapabilityResult,
  call: TCall,
) => TResult | Promise<TResult>;

export type PaybondRuntimeToolCallAdapterInit<TCall, TResult> = {
  source: PaybondSpendGuardInit | PaybondCapabilityBinding;
  operation: PaybondRuntimeOperation<TCall>;
  execute: PaybondRuntimeToolExecutor<TCall, TResult>;
  requestedSpendCents?: PaybondRuntimeSpendCents<TCall>;
  onDeny?: PaybondRuntimeDenyHandler<TCall, TResult>;
};

function resolveRuntimeOperation<TCall>(operation: PaybondRuntimeOperation<TCall>, call: TCall): string {
  const value = typeof operation === "function" ? operation(call) : operation;
  const trimmed = String(value).trim();
  if (!trimmed) {
    throw new Error("Paybond operation must be a non-empty string");
  }
  return trimmed;
}

function resolveRuntimeSpendCents<TCall>(
  requestedSpendCents: PaybondRuntimeSpendCents<TCall> | undefined,
  call: TCall,
): number | undefined {
  if (requestedSpendCents === undefined) {
    return undefined;
  }
  return typeof requestedSpendCents === "function" ? requestedSpendCents(call) : requestedSpendCents;
}

export function paybondRuntimeToolCallAdapter<TCall, TResult>(
  init: PaybondRuntimeToolCallAdapterInit<TCall, TResult>,
): (call: TCall) => Promise<Awaited<TResult>> {
  const guard = new PaybondSpendGuard(init.source);
  return async (call: TCall): Promise<Awaited<TResult>> => {
    const operation = resolveRuntimeOperation(init.operation, call);
    const requestedSpendCents = resolveRuntimeSpendCents(init.requestedSpendCents, call);
    const result = await guard.authorizeSpend({ operation, requestedSpendCents });
    if (!result.allow) {
      if (init.onDeny) {
        return await init.onDeny(result, call);
      }
      throw new PaybondSpendDeniedError(result);
    }
    return await init.execute(call);
  };
}

export type PaybondOpenOptions = {
  apiKey: string;
  gatewayBaseUrl?: string;
  principalPath?: string;
  expectedEnvironment?: PaybondEnvironment;
  maxRetries?: number;
};

type HarborClientOptions = {
  harborBearerSupplier?: HarborBearerSupplier;
  staticHarborBearerToken?: string;
  maxRetries?: number;
};

/**
 * HTTP client for Harbor: capability verify, intents, evidence, and tenant-scoped ledger reads
 * (`GET /ledger/v1/*`, PAYBOND-007).
 */
export class HarborClient {
  private readonly base: string;
  /** Tenant realm from the gateway exchange; sent as `x-tenant-id` on every Harbor request. */
  readonly tenantId: string;
  private readonly bearerSupplier?: HarborBearerSupplier;
  private readonly staticBearer?: string;
  private readonly maxRetries: number;

  /**
   * @param harborBase - Harbor origin, e.g. `https://harbor.example.com` (trailing slash optional)
   * @param tenantId - Tenant realm; sent as `x-tenant-id` on every request
   */
  constructor(harborBase: string, tenantId: string, options?: HarborClientOptions) {
    if (options?.harborBearerSupplier && options?.staticHarborBearerToken) {
      throw new Error("pass at most one of harborBearerSupplier or staticHarborBearerToken");
    }
    this.base = normalizeBase(harborBase) + "/";
    this.tenantId = tenantId.trim();
    this.bearerSupplier = options?.harborBearerSupplier;
    this.staticBearer = options?.staticHarborBearerToken?.trim();
    this.maxRetries = Math.max(1, options?.maxRetries ?? 3);
  }

  private async authHeader(): Promise<Record<string, string>> {
    if (this.staticBearer) {
      return { authorization: `Bearer ${this.staticBearer}` };
    }
    if (this.bearerSupplier) {
      const tok = await this.bearerSupplier();
      if (tok && String(tok).trim()) {
        return { authorization: `Bearer ${String(tok).trim()}` };
      }
    }
    return {};
  }

  /**
   * Ledger JSON responses include `tenant_id`; reject if it drifts from the bound client tenant.
   */
  private assertLedgerTenant(body: Record<string, unknown>, url: string): void {
    const tid = String(body.tenant_id ?? "");
    if (tid !== this.tenantId) {
      throw new Error(
        `ledger tenant mismatch: client=${this.tenantId} harbor=${tid} url=${url}`,
      );
    }
  }

  /** GET with the same 429/5xx retry behavior as {@link HarborClient.fetchWithRetries}. */
  private async fetchGetWithRetries(url: string): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers = new Headers({
          accept: "application/json",
          "x-tenant-id": this.tenantId,
        });
        const auth = await this.authHeader();
        for (const [k, v] of Object.entries(auth)) {
          headers.set(k, v);
        }
        res = await fetch(url, { method: "GET", headers });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private async fetchWithRetries(
    url: string,
    init: RequestInit,
    {
      retryBody,
      retryBodyText,
    }: { retryBody?: unknown; retryBodyText?: string },
  ): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers = new Headers(init.headers);
        const auth = await this.authHeader();
        for (const [k, v] of Object.entries(auth)) {
          headers.set(k, v);
        }
        res = await fetch(url, { ...init, headers });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        if (retryBodyText !== undefined) {
          init = {
            ...init,
            body: retryBodyText,
          };
        } else if (retryBody !== undefined) {
          init = {
            ...init,
            body: JSON.stringify(retryBody),
          };
        }
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  /**
   * POST `/verify` with a Biscuit capability token (PAYBOND-006).
   *
   * @throws HarborHttpError when HTTP fails
   * @throws Error when Harbor echoes a different tenant / intent than requested
   */
  async verifyCapability(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    const url = `${this.base}verify`;
    const payload = {
      intent_id: input.intentId,
      token: input.token,
      operation: input.operation,
      requested_spend_cents: input.requestedSpendCents ?? 0,
    };
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tenant-id": this.tenantId,
        },
        body: JSON.stringify(payload),
      },
      { retryBody: payload },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor verify HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as {
      allow: boolean;
      audit_id: string;
      tenant: string;
      intent_id: string;
      code?: string;
      message?: string;
    };
    if (body.tenant !== this.tenantId) {
      throw new Error(
        `verify tenant mismatch: client=${this.tenantId} harbor=${body.tenant}`,
      );
    }
    if (body.intent_id !== input.intentId) {
      throw new Error(
        `verify intent mismatch: requested=${input.intentId} harbor=${body.intent_id}`,
      );
    }
    return {
      allow: body.allow,
      auditId: body.audit_id,
      tenant: body.tenant,
      intentId: body.intent_id,
      code: body.code,
      message: body.message,
    };
  }

  async verifySpendCapability(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    return this.verifyCapability(input);
  }

  async authorizeSpend(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    return this.verifyCapability(input);
  }

  /**
   * POST `/intents` with a principal-signed `CreateIntentRequest` JSON body.
   *
   * @throws HarborHttpError when HTTP fails
   */
  async createIntent(
    body: Record<string, unknown>,
    options?: { idempotencyKey?: string },
  ): Promise<Record<string, unknown>> {
    const url = `${this.base}intents`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-tenant-id": this.tenantId,
    };
    if (options?.idempotencyKey?.trim()) {
      headers["idempotency-key"] = options.idempotencyKey.trim();
    }
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      },
      { retryBody: body },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor create intent HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return JSON.parse(text) as Record<string, unknown>;
  }

  /**
   * POST `/intents/{intentId}/fund` for x402 / USDC-on-Base funding.
   *
   * Harbor returns:
   * - `402` with `paymentRequired` details when a facilitator or wallet must sign
   * - `202` while authorization is pending
   * - `200` once the intent is funded and any capability token is available
   *
   * @throws HarborHttpError for non-funding HTTP errors
   * @throws Error when Harbor echoes a different tenant or intent than requested
   */
  async fundIntent(
    intentId: string,
    options?: { paymentSignature?: string; idempotencyKey?: string },
  ): Promise<FundIntentResult> {
    const url = `${this.base}intents/${intentId}/fund`;
    const headers: Record<string, string> = {
      "x-tenant-id": this.tenantId,
    };
    if (options?.idempotencyKey?.trim()) {
      headers["idempotency-key"] = options.idempotencyKey.trim();
    }
    if (options?.paymentSignature?.trim()) {
      headers["payment-signature"] = options.paymentSignature.trim();
    }
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers,
        body: "",
      },
      { retryBodyText: "" },
    );
    const text = await res.text();
    if (![200, 202, 402].includes(res.status)) {
      throw new HarborHttpError(`Harbor fund intent HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }

    const body = assertJSONObject(JSON.parse(text));
    const tenant = String(body.tenant ?? "");
    if (tenant !== this.tenantId) {
      throw new Error(`fund tenant mismatch: client=${this.tenantId} harbor=${tenant}`);
    }
    const echoedIntentId = String(body.intent_id ?? "");
    if (echoedIntentId !== intentId) {
      throw new Error(`fund intent mismatch: requested=${intentId} harbor=${echoedIntentId}`);
    }
    if (typeof body.state !== "string" || !body.state.trim()) {
      throw new Error("fund response missing state");
    }
    if (typeof body.currency !== "string" || !body.currency.trim()) {
      throw new Error("fund response missing currency");
    }
    const amountCents = Number(body.amount_cents);
    if (!Number.isFinite(amountCents)) {
      throw new Error("fund response missing amount_cents");
    }

    return {
      statusCode: res.status as 200 | 202 | 402,
      paymentRequired: res.headers.get("payment-required") ?? undefined,
      paymentResponse: res.headers.get("payment-response") ?? undefined,
      intentId: echoedIntentId,
      tenant,
      state: body.state,
      settlementRail: readSettlementRailValue(body.settlement_rail, "fund settlement_rail"),
      currency: body.currency,
      amountCents,
      funded: Boolean(body.funded),
      capabilityToken:
        typeof body.capability_token === "string" && body.capability_token.trim()
          ? body.capability_token
          : undefined,
      funding:
        body.funding === undefined || body.funding === null
          ? undefined
          : parseIntentFundingResult(body.funding),
    };
  }

  /**
   * POST `/intents/{intentId}/evidence` with a signed evidence JSON body.
   *
   * @param idempotencyKey - Optional Harbor idempotency header for safe retries
   */
  async submitEvidence(
    intentId: string,
    evidenceBody: Record<string, unknown>,
    options?: { idempotencyKey?: string },
  ): Promise<SubmitEvidenceResult> {
    const url = `${this.base}intents/${intentId}/evidence`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-tenant-id": this.tenantId,
    };
    if (options?.idempotencyKey?.trim()) {
      headers["idempotency-key"] = options.idempotencyKey.trim();
    }
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers,
        body: JSON.stringify(evidenceBody),
      },
      { retryBody: evidenceBody },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor evidence HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as {
      intent_id: string;
      tenant: string;
      state: string;
      predicate_passed?: boolean;
    };
    return {
      intentId: body.intent_id,
      tenant: body.tenant,
      state: body.state,
      predicatePassed: body.predicate_passed,
    };
  }

  /**
   * `GET /ledger/v1/tip` — latest sequence and entry commitment for the authenticated tenant.
   *
   * @throws HarborHttpError on HTTP failure
   * @throws Error when JSON `tenant_id` does not match the bound client tenant
   */
  async getLedgerTip(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/tip`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger tip HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/authority` — hex-encoded Ed25519 verifying key for this Harbor deployment.
   */
  async getLedgerAuthority(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/authority`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger authority HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/events` - protected Harbor append-only history for trusted clients.
   * `afterSeq` is an exclusive cursor; `limit` is clamped to 1..256 to match Harbor.
   */
  async getLedgerEvents(options?: { afterSeq?: number; limit?: number }): Promise<Record<string, unknown>> {
    const afterSeq = Math.max(0, Math.floor(options?.afterSeq ?? 0));
    const rawLimit = options?.limit ?? 64;
    const limit = Math.max(1, Math.min(Math.floor(rawLimit), 256));
    const qs = new URLSearchParams({
      after_seq: String(afterSeq),
      limit: String(limit),
    });
    const url = `${this.base}ledger/v1/events?${qs.toString()}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger events HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/merkle/latest` — last Merkle checkpoint envelope for the tenant (checkpoint may be null).
   */
  async getLedgerMerkleLatest(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/merkle/latest`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger merkle HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }
}

type GatewayHarborClientOptions = {
  staticGatewayBearerToken: string;
  maxRetries?: number;
};

type GatewayHarborMutationOptions = {
  idempotencyKey?: string;
  recognitionProof?: AgentRecognitionProofV1 | Record<string, unknown>;
};

/**
 * Gateway-backed Harbor surface for hosted Paybond integrations.
 *
 * This client sends the service-account API key to the public Gateway. Gateway derives tenant,
 * mints upstream Harbor credentials internally, and applies recognition/guardrail checks before
 * forwarding state-changing Harbor requests.
 */
export class GatewayHarborClient {
  private readonly base: string;
  readonly tenantId: string;
  private readonly staticGatewayBearerToken: string;
  private readonly maxRetries: number;

  constructor(gatewayBaseUrl: string, tenantId: string, options: GatewayHarborClientOptions) {
    this.base = `${normalizeBase(gatewayBaseUrl)}/`;
    this.tenantId = tenantId.trim();
    this.staticGatewayBearerToken = options.staticGatewayBearerToken.trim();
    this.maxRetries = Math.max(1, options.maxRetries ?? 3);
  }

  private headers(extra?: HeadersInit): Headers {
    const headers = new Headers(extra);
    headers.set("accept", "application/json");
    headers.set("x-tenant-id", this.tenantId);
    headers.set("authorization", `Bearer ${this.staticGatewayBearerToken}`);
    return headers;
  }

  private async fetchWithRetries(url: string, init: RequestInit): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, init);
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status) && attempt + 1 < this.maxRetries) {
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private async postJSON(
    path: string,
    payload: Record<string, unknown>,
    extraHeaders?: HeadersInit,
  ): Promise<{ res: Response; text: string; url: string }> {
    const url = `${this.base}${path.replace(/^\/+/, "")}`;
    const res = await this.fetchWithRetries(url, {
      method: "POST",
      headers: this.headers({
        "content-type": "application/json",
        ...(extraHeaders ?? {}),
      }),
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    return { res, text, url };
  }

  private mutationHeaders(
    operation: string,
    options?: GatewayHarborMutationOptions,
    headers?: Record<string, string>,
  ): Record<string, string> {
    const proof = options?.recognitionProof;
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
      throw new Error(`${operation} requires recognitionProof`);
    }
    return gatewayMutationHeaders(proof, {
      ...(headers ?? {}),
      ...(options?.idempotencyKey?.trim() ? { "idempotency-key": options.idempotencyKey.trim() } : {}),
    });
  }

  async verifyCapability(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    const payload = {
      intent_id: input.intentId,
      token: input.token,
      operation: input.operation,
      requested_spend_cents: input.requestedSpendCents ?? 0,
    };
    const { res, text, url } = await this.postJSON("/verify", payload);
    if (!res.ok) {
      throw new HarborHttpError(`Gateway verify HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as {
      allow: boolean;
      audit_id: string;
      tenant: string;
      intent_id: string;
      code?: string;
      message?: string;
    };
    if (body.tenant !== this.tenantId) {
      throw new Error(`verify tenant mismatch: client=${this.tenantId} gateway=${body.tenant}`);
    }
    if (body.intent_id !== input.intentId) {
      throw new Error(`verify intent mismatch: requested=${input.intentId} gateway=${body.intent_id}`);
    }
    return {
      allow: body.allow,
      auditId: body.audit_id,
      tenant: body.tenant,
      intentId: body.intent_id,
      code: body.code,
      message: body.message,
    };
  }

  async verifySpendCapability(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    return this.verifyCapability(input);
  }

  async authorizeSpend(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    return this.verifyCapability(input);
  }

  async createIntent(
    body: Record<string, unknown>,
    options: GatewayHarborMutationOptions,
  ): Promise<Record<string, unknown>> {
    const { res, text, url } = await this.postJSON(
      "/harbor/intents",
      body,
      this.mutationHeaders("createIntent", options),
    );
    if (!res.ok) {
      throw new HarborHttpError(`Gateway Harbor create intent HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return JSON.parse(text) as Record<string, unknown>;
  }

  async fundIntent(
    intentId: string,
    options: GatewayHarborMutationOptions & { paymentSignature?: string },
  ): Promise<FundIntentResult> {
    const { res, text, url } = await this.postJSON(
      `/harbor/intents/${encodeURIComponent(intentId)}/fund`,
      {},
      this.mutationHeaders("fundIntent", options, {
        ...(options.paymentSignature?.trim() ? { "payment-signature": options.paymentSignature.trim() } : {}),
      }),
    );
    if (![200, 202, 402].includes(res.status)) {
      throw new HarborHttpError(`Gateway Harbor fund intent HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return parseFundIntentResponse(assertJSONObject(JSON.parse(text)), {
      tenantId: this.tenantId,
      intentId,
      statusCode: res.status as 200 | 202 | 402,
      paymentRequired: res.headers.get("payment-required") ?? undefined,
      paymentResponse: res.headers.get("payment-response") ?? undefined,
      source: "gateway",
    });
  }

  async submitEvidence(
    intentId: string,
    evidenceBody: Record<string, unknown>,
    options: GatewayHarborMutationOptions,
  ): Promise<SubmitEvidenceResult> {
    const { res, text, url } = await this.postJSON(
      `/harbor/intents/${encodeURIComponent(intentId)}/evidence`,
      evidenceBody,
      this.mutationHeaders("submitEvidence", options),
    );
    if (!res.ok) {
      throw new HarborHttpError(`Gateway Harbor evidence HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return parseSubmitEvidenceResponse(JSON.parse(text));
  }
}

type GatewaySignalClientOptions = {
  staticGatewayBearerToken: string;
  maxRetries?: number;
};

type GatewayFraudClientOptions = {
  staticGatewayBearerToken: string;
  maxRetries?: number;
};

const DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal";
const SETTLEMENT_RAIL_VALUES = new Set<SettlementRail>(["stripe_connect", "stripe_ach_debit", "x402_usdc_base"]);
const FRAUD_REVIEW_EVENT_TYPES = new Set<string>([
  "review_open_requested",
  "appeal_requested",
  "replay_requested",
  "review_outcome_recorded",
  "confirmed_risk",
  "false_positive",
  "needs_more_evidence",
]);
const FRAUD_REVIEW_OUTCOMES = new Set<string>(["confirmed_risk", "false_positive", "needs_more_evidence"]);

function assertJSONObject(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("expected JSON object");
  }
  return value as Record<string, unknown>;
}

function readSettlementRailValue(value: unknown, field: string): SettlementRail {
  if (typeof value !== "string" || !SETTLEMENT_RAIL_VALUES.has(value as SettlementRail)) {
    throw new Error(`invalid ${field}`);
  }
  return value as SettlementRail;
}

function readStringArrayValue(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error(`invalid ${field}`);
  }
  return [...value];
}

function parseFundIntentResponse(
  body: Record<string, unknown>,
  init: {
    tenantId: string;
    intentId: string;
    statusCode: 200 | 202 | 402;
    paymentRequired?: string;
    paymentResponse?: string;
    source: "harbor" | "gateway";
  },
): FundIntentResult {
  const tenant = String(body.tenant ?? "");
  if (tenant !== init.tenantId) {
    throw new Error(`fund tenant mismatch: client=${init.tenantId} ${init.source}=${tenant}`);
  }
  const echoedIntentId = String(body.intent_id ?? "");
  if (echoedIntentId !== init.intentId) {
    throw new Error(`fund intent mismatch: requested=${init.intentId} ${init.source}=${echoedIntentId}`);
  }
  if (typeof body.state !== "string" || !body.state.trim()) {
    throw new Error("fund response missing state");
  }
  if (typeof body.currency !== "string" || !body.currency.trim()) {
    throw new Error("fund response missing currency");
  }
  const amountCents = Number(body.amount_cents);
  if (!Number.isFinite(amountCents)) {
    throw new Error("fund response missing amount_cents");
  }

  return {
    statusCode: init.statusCode,
    paymentRequired: init.paymentRequired,
    paymentResponse: init.paymentResponse,
    intentId: echoedIntentId,
    tenant,
    state: body.state,
    settlementRail: readSettlementRailValue(body.settlement_rail, "fund settlement_rail"),
    currency: body.currency,
    amountCents,
    funded: Boolean(body.funded),
    capabilityToken:
      typeof body.capability_token === "string" && body.capability_token.trim()
        ? body.capability_token
        : undefined,
    funding:
      body.funding === undefined || body.funding === null
        ? undefined
        : parseIntentFundingResult(body.funding),
  };
}

function parseSubmitEvidenceResponse(value: unknown): SubmitEvidenceResult {
  const body = assertJSONObject(value);
  return {
    intentId: String(body.intent_id ?? ""),
    tenant: String(body.tenant ?? ""),
    state: String(body.state ?? ""),
    predicatePassed:
      typeof body.predicate_passed === "boolean" ? body.predicate_passed : undefined,
  };
}

function parseIntentFundingResult(value: unknown): IntentFundingResult {
  const body = assertJSONObject(value);
  const onchainRaw = body.onchain_transaction_hashes;
  const onchain =
    onchainRaw === undefined || onchainRaw === null
      ? undefined
      : (() => {
          const parsed = assertJSONObject(onchainRaw);
          return {
            authorizations:
              parsed.authorizations === undefined
                ? undefined
                : readStringArrayValue(parsed.authorizations, "funding.onchain_transaction_hashes.authorizations"),
            captures:
              parsed.captures === undefined
                ? undefined
                : readStringArrayValue(parsed.captures, "funding.onchain_transaction_hashes.captures"),
            voids:
              parsed.voids === undefined
                ? undefined
                : readStringArrayValue(parsed.voids, "funding.onchain_transaction_hashes.voids"),
            refunds:
              parsed.refunds === undefined
                ? undefined
                : readStringArrayValue(parsed.refunds, "funding.onchain_transaction_hashes.refunds"),
          };
        })();
  const readOptionalString = (field: string): string | undefined => {
    const raw = body[field];
    return typeof raw === "string" && raw.trim() ? raw : undefined;
  };
  return {
    settlementRail: readSettlementRailValue(body.settlement_rail, "funding.settlement_rail"),
    harborFundEndpoint: readOptionalString("harbor_fund_endpoint"),
    status: readOptionalString("status"),
    paymentSessionId: readOptionalString("payment_session_id"),
    paymentUrl: readOptionalString("payment_url"),
    stripePaymentIntentId: readOptionalString("stripe_payment_intent_id"),
    clientSecret: readOptionalString("client_secret"),
    stripeConnectDestination: readOptionalString("stripe_connect_destination"),
    stripeCustomerId: readOptionalString("stripe_customer_id"),
    latestChargeId: readOptionalString("latest_charge_id"),
    paymentMethodId: readOptionalString("payment_method_id"),
    mandateId: readOptionalString("mandate_id"),
    financialConnectionsAccountId: readOptionalString("financial_connections_account_id"),
    bankLast4: readOptionalString("bank_last4"),
    bankFingerprint: readOptionalString("bank_fingerprint"),
    bankName: readOptionalString("bank_name"),
    asset: readOptionalString("asset"),
    network: readOptionalString("network"),
    authorizationId: readOptionalString("authorization_id"),
    captureId: readOptionalString("capture_id"),
    voidId: readOptionalString("void_id"),
    transferId: readOptionalString("transfer_id"),
    refundId: readOptionalString("refund_id"),
    expectedDebitDate: readOptionalString("expected_debit_date"),
    paymentReference: readOptionalString("payment_reference"),
    refundReference: readOptionalString("refund_reference"),
    refundReferenceStatus: readOptionalString("refund_reference_status"),
    sourceAddress: readOptionalString("source_address"),
    targetAddress: readOptionalString("target_address"),
    authorizationExpiresAt: readOptionalString("authorization_expires_at"),
    captureExpiresAt: readOptionalString("capture_expires_at"),
    refundExpiresAt: readOptionalString("refund_expires_at"),
    onchainTransactionHashes: onchain,
  };
}

/**
 * Tenant-bound reader for gateway Signal routes.
 */
export class GatewaySignalClient {
  private readonly base: string;
  readonly tenantId: string;
  private readonly bearerToken: string;
  private readonly maxRetries: number;

  constructor(gatewayBaseUrl: string, tenantId: string, options: GatewaySignalClientOptions) {
    this.base = normalizeBase(gatewayBaseUrl) + "/";
    this.tenantId = tenantId.trim();
    this.bearerToken = options.staticGatewayBearerToken.trim();
    this.maxRetries = Math.max(1, options.maxRetries ?? 3);
  }

  private async fetchGetWithRetries(url: string): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, {
          method: "GET",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${this.bearerToken}`,
          },
        });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private assertTenant(body: Record<string, unknown>, url: string): void {
    const tid = String(body.tenant_id ?? "");
    if (tid !== this.tenantId) {
      throw new Error(
        `signal tenant mismatch: client=${this.tenantId} gateway=${tid} url=${url}`,
      );
    }
  }

  private scoreQuery(scoreVersion?: string): string {
    if (!scoreVersion || !scoreVersion.trim()) {
      return "";
    }
    return `?score_version=${encodeURIComponent(scoreVersion.trim())}`;
  }

  async getReputationReceipt(operatorDid: string, scoreVersion?: string): Promise<SignalReceiptEnvelope | null> {
    const enc = encodeURIComponent(operatorDid);
    const url = `${this.base}reputation/${enc}${this.scoreQuery(scoreVersion)}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new SignalHttpError(`Signal receipt HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    const receipt = assertJSONObject(body.receipt);
    const tenant = String(receipt.tenant_id ?? "");
    const echoedOperator = String(receipt.operator_did ?? "");
    if (tenant !== this.tenantId) {
      throw new Error(`signal receipt tenant mismatch: client=${this.tenantId} gateway=${tenant}`);
    }
    if (echoedOperator !== operatorDid) {
      throw new Error(`signal receipt operator mismatch: requested=${operatorDid} gateway=${echoedOperator}`);
    }
    return body as unknown as SignalReceiptEnvelope;
  }

  async getPortfolioSummary(scoreVersion?: string): Promise<SignalPortfolioSummary> {
    const url = `${this.base}signal/v1/portfolio/summary${this.scoreQuery(scoreVersion)}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Signal portfolio summary HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as unknown as SignalPortfolioSummary;
  }

  async getSignedPortfolioArtifact(scoreVersion?: string): Promise<SignalSignedPortfolioArtifact> {
    const url = `${this.base}signal/v1/portfolio/signed-export${this.scoreQuery(scoreVersion)}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Signal signed portfolio artifact HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as unknown as SignalSignedPortfolioArtifact;
  }

  async getOperatorExplanation(operatorDid: string, scoreVersion?: string): Promise<Record<string, unknown> | null> {
    const enc = encodeURIComponent(operatorDid);
    const url = `${this.base}signal/v1/operators/${enc}/explanation${this.scoreQuery(scoreVersion)}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new SignalHttpError(`Signal explanation HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    if (String(body.operator_did ?? "") !== operatorDid) {
      throw new Error(`signal explanation operator mismatch: requested=${operatorDid} gateway=${String(body.operator_did ?? "")}`);
    }
    return body;
  }

  async getOperatorReviewStatus(operatorDid: string, scoreVersion?: string): Promise<Record<string, unknown> | null> {
    const enc = encodeURIComponent(operatorDid);
    const url = `${this.base}signal/v1/operators/${enc}/review-status${this.scoreQuery(scoreVersion)}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new SignalHttpError(`Signal review status HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    if (String(body.operator_did ?? "") !== operatorDid) {
      throw new Error(`signal review operator mismatch: requested=${operatorDid} gateway=${String(body.operator_did ?? "")}`);
    }
    return body;
  }
}

/**
 * Tenant-bound client for gateway fraud review and metrics routes.
 */
export class GatewayFraudClient {
  private readonly base: string;
  readonly tenantId: string;
  private readonly bearerToken: string;
  private readonly maxRetries: number;

  constructor(gatewayBaseUrl: string, tenantId: string, options: GatewayFraudClientOptions) {
    this.base = normalizeBase(gatewayBaseUrl) + "/";
    this.tenantId = tenantId.trim();
    this.bearerToken = options.staticGatewayBearerToken.trim();
    this.maxRetries = Math.max(1, options.maxRetries ?? 3);
  }

  private async fetchGetWithRetries(url: string): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, {
          method: "GET",
          headers: {
            accept: "application/json",
            authorization: `Bearer ${this.bearerToken}`,
          },
        });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private async fetchPostJSON(url: string, payload: Record<string, unknown>): Promise<Response> {
    return fetch(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${this.bearerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }

  private async fetchPutJSON(url: string, payload: Record<string, unknown>): Promise<Response> {
    return fetch(url, {
      method: "PUT",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${this.bearerToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });
  }

  private assertTenant(body: Record<string, unknown>, url: string): void {
    const tid = String(body.tenant_id ?? "");
    if (tid !== this.tenantId) {
      throw new Error(`fraud tenant mismatch: client=${this.tenantId} gateway=${tid} url=${url}`);
    }
  }

  private assertOperator(body: Record<string, unknown>, operatorDid: string, label: string): void {
    const echoedOperator = String(body.operator_did ?? "");
    if (echoedOperator !== operatorDid) {
      throw new Error(`fraud ${label} operator mismatch: requested=${operatorDid} gateway=${echoedOperator}`);
    }
  }

  private query(params: Record<string, string | number | undefined>): string {
    const qs = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (typeof value === "number") {
        qs.set(key, String(value));
        continue;
      }
      if (typeof value === "string" && value.trim()) {
        qs.set(key, value.trim());
      }
    }
    const raw = qs.toString();
    return raw ? `?${raw}` : "";
  }

  private normalizedSeverity(severity?: string): string | undefined {
    const normalized = severity?.trim();
    if (!normalized) {
      return undefined;
    }
    if (!["elevated", "high", "critical"].includes(normalized)) {
      throw new Error("fraud severity must be one of elevated, high, or critical");
    }
    return normalized;
  }

  private normalizedWindow(window?: string): string | undefined {
    const normalized = window?.trim();
    if (!normalized) {
      return undefined;
    }
    if (!["24h", "7d", "30d"].includes(normalized)) {
      throw new Error("fraud metrics window must be one of 24h, 7d, or 30d");
    }
    return normalized;
  }

  private normalizedReleaseGateMode(mode: string): SignalFraudReleaseGateMode {
    const normalized = mode.trim();
    if (!["review_only", "critical_hold"].includes(normalized)) {
      throw new Error("fraud release gate mode must be one of review_only or critical_hold");
    }
    return normalized as SignalFraudReleaseGateMode;
  }

  private normalizedReviewEventType(eventType: string): SignalFraudReviewEventType {
    const normalized = eventType.trim();
    if (!FRAUD_REVIEW_EVENT_TYPES.has(normalized)) {
      throw new Error(
        "fraud review eventType must be one of review_open_requested, appeal_requested, replay_requested, review_outcome_recorded, confirmed_risk, false_positive, or needs_more_evidence",
      );
    }
    return normalized as SignalFraudReviewEventType;
  }

  private normalizedReviewOutcome(outcome: string): SignalFraudReviewOutcome {
    const normalized = outcome.trim();
    if (!FRAUD_REVIEW_OUTCOMES.has(normalized)) {
      throw new Error("fraud review outcome must be one of confirmed_risk, false_positive, or needs_more_evidence");
    }
    return normalized as SignalFraudReviewOutcome;
  }

  private optionalReviewContext(value: string | undefined): string | undefined {
    const normalized = value?.trim();
    return normalized || undefined;
  }

  async getFraudAssessment(
    operatorDid: string,
    scoreVersion?: string,
  ): Promise<SignalFraudAssessmentResponse | null> {
    const enc = encodeURIComponent(operatorDid);
    const url = `${this.base}signal/v1/operators/${enc}/review-status${this.query({
      score_version: scoreVersion,
    })}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (res.status === 404) {
      return null;
    }
    if (!res.ok) {
      throw new SignalHttpError(`Fraud assessment HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    this.assertOperator(body, operatorDid, "assessment");
    return body as SignalFraudAssessmentResponse;
  }

  async listFraudReviewQueue(
    options: ListFraudReviewQueueOptions = {},
  ): Promise<SignalFraudReviewQueueResponse> {
    let rawLimit: number | undefined;
    if (options.limit !== undefined) {
      if (!Number.isFinite(options.limit)) {
        throw new Error("fraud review queue limit must be a finite number");
      }
      rawLimit = Math.max(1, Math.min(Math.floor(options.limit), 500));
    }
    const url = `${this.base}signal/v1/review-queue${this.query({
      state: options.state,
      fraud_severity: this.normalizedSeverity(options.severity),
      limit: rawLimit,
      score_version: options.scoreVersion,
    })}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Fraud review queue HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as SignalFraudReviewQueueResponse;
  }

  async getFraudMetrics(options: GetFraudMetricsOptions = {}): Promise<SignalFraudMetricsResponse> {
    const url = `${this.base}signal/v1/fraud/metrics${this.query({
      window: this.normalizedWindow(options.window),
      score_version: options.scoreVersion,
    })}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Fraud metrics HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as SignalFraudMetricsResponse;
  }

  async getFraudReleaseGateConfig(scoreVersion?: string): Promise<SignalFraudReleaseGateConfigResponse> {
    const url = `${this.base}signal/v1/fraud/release-gate${this.query({
      score_version: scoreVersion,
    })}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Fraud release gate HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as SignalFraudReleaseGateConfigResponse;
  }

  async setFraudReleaseGateMode(mode: SignalFraudReleaseGateMode | string): Promise<SignalFraudReleaseGateConfigResponse> {
    const normalized = this.normalizedReleaseGateMode(mode);
    const url = `${this.base}signal/v1/fraud/release-gate`;
    const res = await this.fetchPutJSON(url, { mode: normalized });
    const text = await res.text();
    if (!res.ok) {
      throw new SignalHttpError(`Fraud release gate update HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    return body as SignalFraudReleaseGateConfigResponse;
  }

  async recordFraudReviewEvent(
    operatorDid: string,
    event: SignalFraudReviewEventInput,
    scoreVersion?: string,
  ): Promise<SignalFraudReviewEventResponse> {
    let eventType = this.normalizedReviewEventType(event.eventType);
    let reviewOutcome = event.reviewOutcome ?? event.review_outcome;
    if (FRAUD_REVIEW_OUTCOMES.has(eventType)) {
      reviewOutcome = eventType;
      eventType = "review_outcome_recorded";
    }
    const normalizedOutcome = reviewOutcome === undefined ? undefined : this.normalizedReviewOutcome(reviewOutcome);
    if (eventType === "review_outcome_recorded" && normalizedOutcome === undefined) {
      throw new Error("fraud review outcome must be one of confirmed_risk, false_positive, or needs_more_evidence");
    }
    const signalCode = this.optionalReviewContext(event.signalCode ?? event.signal_code);
    const intentId = this.optionalReviewContext(event.intentId ?? event.intent_id);
    const providerEventId = this.optionalReviewContext(event.providerEventId ?? event.provider_event_id);
    const enc = encodeURIComponent(operatorDid);
    const url = `${this.base}signal/v1/operators/${enc}/review-events${this.query({
      score_version: scoreVersion,
    })}`;
    const res = await this.fetchPostJSON(url, {
      event_type: eventType,
      ...(normalizedOutcome ? { review_outcome: normalizedOutcome } : {}),
      ...(signalCode ? { signal_code: signalCode } : {}),
      ...(intentId ? { intent_id: intentId } : {}),
      ...(providerEventId ? { provider_event_id: providerEventId } : {}),
      summary: event.summary,
    });
    const text = await res.text();
    if (!res.ok && res.status !== 429) {
      throw new SignalHttpError(`Fraud review event HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    this.assertTenant(body, url);
    this.assertOperator(body, operatorDid, "review event");
    return body as SignalFraudReviewEventResponse;
  }
}

type GatewayA2AClientOptions = {
  staticGatewayBearerToken?: string;
  maxRetries?: number;
};

/**
 * Public or optionally authenticated reader for the gateway's A2A discovery surface.
 */
export class GatewayA2AClient {
  private readonly base: string;
  private readonly bearerToken?: string;
  private readonly maxRetries: number;

  constructor(gatewayBaseUrl: string, options?: GatewayA2AClientOptions) {
    this.base = normalizeBase(gatewayBaseUrl) + "/";
    this.bearerToken = options?.staticGatewayBearerToken?.trim() || undefined;
    this.maxRetries = Math.max(1, options?.maxRetries ?? 3);
  }

  private async fetchGetWithRetries(url: string): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers = new Headers({
          accept: "application/json",
        });
        if (this.bearerToken) {
          headers.set("authorization", `Bearer ${this.bearerToken}`);
        }
        res = await fetch(url, {
          method: "GET",
          headers,
        });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  async getAgentCard(): Promise<A2AAgentCard> {
    const url = `${this.base}.well-known/agent-card.json`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new A2AHttpError(`A2A agent card HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return assertJSONObject(JSON.parse(text)) as unknown as A2AAgentCard;
  }

  async getTaskContracts(): Promise<A2ATaskContractCatalogV1> {
    const url = `${this.base}protocol/v2/a2a/task-contracts`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new A2AHttpError(`A2A task contracts HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return assertJSONObject(JSON.parse(text)) as unknown as A2ATaskContractCatalogV1;
  }

  async getTaskContract(contractId: string): Promise<A2ASettlementTaskContractV1> {
    const enc = encodeURIComponent(contractId);
    const url = `${this.base}protocol/v2/a2a/task-contracts/${enc}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new A2AHttpError(`A2A task contract HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return assertJSONObject(JSON.parse(text)) as unknown as A2ASettlementTaskContractV1;
  }
}

export class GatewayProtocolClient {
  readonly tenantId: string;
  private readonly base: string;
  private readonly staticGatewayBearerToken: string | null;
  private readonly maxRetries: number;

  constructor(
    gatewayBaseUrl: string,
    tenantId: string,
    init?: {
      staticGatewayBearerToken?: string;
      maxRetries?: number;
    },
  ) {
    this.base = `${normalizeBase(gatewayBaseUrl)}/`;
    this.tenantId = tenantId.trim();
    this.staticGatewayBearerToken = init?.staticGatewayBearerToken?.trim() || null;
    this.maxRetries = Math.max(1, init?.maxRetries ?? 3);
  }

  private async fetchWithRetries(
    url: string,
    init: RequestInit,
  ): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, init);
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) {
          throw e;
        }
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status) && attempt + 1 < this.maxRetries) {
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private headers(extra?: HeadersInit): Headers {
    const headers = new Headers(extra);
    headers.set("accept", "application/json");
    headers.set("x-tenant-id", this.tenantId);
    if (this.staticGatewayBearerToken) {
      headers.set("authorization", `Bearer ${this.staticGatewayBearerToken}`);
    }
    return headers;
  }

  private async postJSON(
    path: string,
    payload: Record<string, unknown>,
    extraHeaders?: HeadersInit,
  ): Promise<Record<string, unknown>> {
    const url = `${this.base}${path.replace(/^\/+/, "")}`;
    const res = await this.fetchWithRetries(url, {
      method: "POST",
      headers: this.headers({
        "content-type": "application/json",
        ...(extraHeaders ?? {}),
      }),
      body: JSON.stringify(payload),
    });
    const text = await res.text();
    if (!res.ok) {
      const parsed = parseGatewayErrorEnvelope(text);
      throw new ProtocolHttpError(protocolHTTPErrorMessage(`gateway POST ${path}`, res.status, text), {
        statusCode: res.status,
        url,
        bodyText: text,
        errorCode: parsed.errorCode,
        errorMessage: parsed.errorMessage,
      });
    }
    return assertJSONObject(JSON.parse(text));
  }

  async importAgentMandateV1(init: {
    signedMandate: SignedAgentMandateV1;
    intentId: string;
    transportBinding?: ProtocolTransportBindingV1;
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
  }): Promise<ImportAgentMandateV1Result> {
    const url = `${this.base}protocol/v2/mandates`;
    const res = await this.fetchWithRetries(url, {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify({
        signed_mandate: init.signedMandate,
        intent_id: init.intentId,
        transport_binding: init.transportBinding ?? {},
        recognition_proof: init.recognitionProof,
      }),
    });
    const text = await res.text();
    if (!res.ok) {
      const parsed = parseGatewayErrorEnvelope(text);
      throw new ProtocolHttpError(protocolHTTPErrorMessage("protocol mandate import", res.status, text), {
        statusCode: res.status,
        url,
        bodyText: text,
        errorCode: parsed.errorCode,
        errorMessage: parsed.errorMessage,
      });
    }
    const body = assertJSONObject(JSON.parse(text)) as unknown as ImportAgentMandateV1Result;
    if (String(body.intent_id ?? "").trim() !== init.intentId) {
      throw new Error(`protocol intent mismatch: requested=${init.intentId} gateway=${String(body.intent_id ?? "")}`);
    }
    if (String(body.mandate?.authorization?.tenant_id ?? "").trim() !== this.tenantId) {
      throw new Error(
        `protocol mandate tenant mismatch: client=${this.tenantId} gateway=${String(body.mandate?.authorization?.tenant_id ?? "")}`,
      );
    }
    return body;
  }

  async getSettlementReceiptV1(receiptId: string): Promise<ProtocolSettlementReceiptV1> {
    const enc = encodeURIComponent(receiptId);
    const url = `${this.base}protocol/v2/receipts/${enc}`;
    const res = await this.fetchWithRetries(url, {
      method: "GET",
      headers: this.headers(),
    });
    const text = await res.text();
    if (!res.ok) {
      const parsed = parseGatewayErrorEnvelope(text);
      throw new ProtocolHttpError(protocolHTTPErrorMessage("protocol settlement receipt", res.status, text), {
        statusCode: res.status,
        url,
        bodyText: text,
        errorCode: parsed.errorCode,
        errorMessage: parsed.errorMessage,
      });
    }
    const body = assertJSONObject(JSON.parse(text)) as unknown as ProtocolSettlementReceiptV1;
    if (String(body.receipt_id ?? "").trim() !== receiptId) {
      throw new Error(`protocol receipt mismatch: requested=${receiptId} gateway=${String(body.receipt_id ?? "")}`);
    }
    if (String(body.tenant_id ?? "").trim() !== this.tenantId) {
      throw new Error(`protocol receipt tenant mismatch: client=${this.tenantId} gateway=${String(body.tenant_id ?? "")}`);
    }
    return body;
  }

  async verifyProtocolReceiptV1(
    receipt: ProtocolAuthorizationReceiptV1 | ProtocolSettlementReceiptV1 | Record<string, unknown>,
  ): Promise<VerifyProtocolReceiptV1Result> {
    const url = `${this.base}protocol/v2/receipts/verify`;
    const res = await this.fetchWithRetries(url, {
      method: "POST",
      headers: this.headers({ "content-type": "application/json" }),
      body: JSON.stringify(receipt),
    });
    const text = await res.text();
    if (!res.ok) {
      const parsed = parseGatewayErrorEnvelope(text);
      throw new ProtocolHttpError(protocolHTTPErrorMessage("protocol receipt verify", res.status, text), {
        statusCode: res.status,
        url,
        bodyText: text,
        errorCode: parsed.errorCode,
        errorMessage: parsed.errorMessage,
      });
    }
    return assertJSONObject(JSON.parse(text)) as unknown as VerifyProtocolReceiptV1Result;
  }

  async createHarborIntent(init: {
    body: Record<string, unknown>;
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.postJSON("/harbor/intents", init.body, gatewayMutationHeaders(init.recognitionProof, {
      ...(init.idempotencyKey?.trim() ? { "idempotency-key": init.idempotencyKey.trim() } : {}),
    }));
  }

  async fundHarborIntent(init: {
    intentId: string;
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    paymentSignature?: string;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/fund`,
      {},
      gatewayMutationHeaders(init.recognitionProof, {
        ...(init.paymentSignature?.trim() ? { "payment-signature": init.paymentSignature.trim() } : {}),
        ...(init.idempotencyKey?.trim() ? { "idempotency-key": init.idempotencyKey.trim() } : {}),
      }),
    );
  }

  async submitHarborEvidence(init: {
    intentId: string;
    body: Record<string, unknown>;
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/evidence`,
      init.body,
      gatewayMutationHeaders(init.recognitionProof, {
        ...(init.idempotencyKey?.trim() ? { "idempotency-key": init.idempotencyKey.trim() } : {}),
      }),
    );
  }

  async confirmHarborSettlement(init: {
    intentId: string;
    body: Record<string, unknown>;
    recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/settlement/confirm`,
      init.body,
      gatewayMutationHeaders(init.recognitionProof, {
        ...(init.idempotencyKey?.trim() ? { "idempotency-key": init.idempotencyKey.trim() } : {}),
      }),
    );
  }
}

function gatewayMutationHeaders(
  recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>,
  headers?: Record<string, string>,
): Record<string, string> {
  return {
    ...(headers ?? {}),
    [agentRecognitionProofHeader]: encodeRecognitionProofHeader(recognitionProof),
  };
}

function encodeRecognitionProofHeader(proof: AgentRecognitionProofV1 | Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(proof), "utf8").toString("base64url");
}

export type ServiceAccountSignalSessionInit = {
  apiKey: string;
  gatewayBaseUrl?: string;
  principalPath?: string;
  expectedEnvironment?: PaybondEnvironment;
  maxRetries?: number;
};

export type ServiceAccountFraudSessionInit = ServiceAccountSignalSessionInit;

async function resolveGatewayTenantId(
  gatewayBaseUrl: string,
  apiKey: string,
  principalPath: string,
  maxRetries: number,
  expectedEnvironment?: PaybondEnvironment,
): Promise<string> {
  const base = normalizeBase(gatewayBaseUrl);
  const path = principalPath.startsWith("/") ? principalPath : `/${principalPath}`;
  const url = `${base}${path}`;
  const expected = normalizeExpectedEnvironment(expectedEnvironment);
  let lastErr: unknown;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        method: "GET",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${apiKey.trim()}`,
        },
      });
    } catch (e) {
      lastErr = e;
      if (attempt + 1 >= maxRetries) {
        throw e;
      }
      await new Promise((r) => setTimeout(r, backoffMs(attempt)));
      continue;
    }
    const text = await res.text();
    if (!res.ok) {
      if ([429, 500, 502, 503, 504].includes(res.status) && attempt + 1 < maxRetries) {
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      throw new GatewayAuthError(`gateway principal HTTP ${res.status}`, {
        statusCode: res.status,
        bodyText: text,
      });
    }
    const body = assertJSONObject(JSON.parse(text));
    const tenant = String(body.tenant_id ?? "").trim();
    if (!tenant) {
      throw new GatewayAuthError("gateway principal JSON missing tenant_id", {
        bodyText: text,
      });
    }
    assertExpectedEnvironment("gateway principal", body.environment, expected, text);
    return tenant;
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

/**
 * Read-only tenant-bound Signal session for one service-account API key.
 */
export class ServiceAccountSignalSession {
  readonly signal: GatewaySignalClient;

  private constructor(signal: GatewaySignalClient) {
    this.signal = signal;
  }

  static async open(init: ServiceAccountSignalSessionInit): Promise<ServiceAccountSignalSession> {
    const gatewayBaseUrl = defaultGatewayBaseUrl(init.gatewayBaseUrl);
    const tenantId = await resolveGatewayTenantId(
      gatewayBaseUrl,
      init.apiKey,
      init.principalPath ?? DEFAULT_PRINCIPAL_PATH,
      Math.max(1, init.maxRetries ?? 3),
      init.expectedEnvironment,
    );
    return new ServiceAccountSignalSession(
      new GatewaySignalClient(gatewayBaseUrl, tenantId, {
        staticGatewayBearerToken: init.apiKey,
        maxRetries: init.maxRetries ?? 3,
      }),
    );
  }

  async aclose(): Promise<void> {
    await Promise.resolve();
  }
}

/**
 * Tenant-bound fraud review and metrics session for one service-account API key.
 */
export class ServiceAccountFraudSession {
  readonly fraud: GatewayFraudClient;

  private constructor(fraud: GatewayFraudClient) {
    this.fraud = fraud;
  }

  static async open(init: ServiceAccountFraudSessionInit): Promise<ServiceAccountFraudSession> {
    const gatewayBaseUrl = defaultGatewayBaseUrl(init.gatewayBaseUrl);
    const tenantId = await resolveGatewayTenantId(
      gatewayBaseUrl,
      init.apiKey,
      init.principalPath ?? DEFAULT_PRINCIPAL_PATH,
      Math.max(1, init.maxRetries ?? 3),
      init.expectedEnvironment,
    );
    return new ServiceAccountFraudSession(
      new GatewayFraudClient(gatewayBaseUrl, tenantId, {
        staticGatewayBearerToken: init.apiKey,
        maxRetries: init.maxRetries ?? 3,
      }),
    );
  }

  async aclose(): Promise<void> {
    await Promise.resolve();
  }
}

/**
 * Parameters for {@link PaybondIntents.create} (tenant is taken from the bound Harbor client).
 * `settlementRail` is principal-signed and requests one allowed rail; Harbor still resolves the
 * destination from tenant-owned settlement config.
 */
export type PaybondCreateIntentParams = Omit<BuildSignedCreateIntentParams, "tenantId" | "intentId"> & {
  intentId?: string;
  recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
};

/** Parameters for {@link PaybondIntents.submitEvidence} (tenant is taken from the bound Harbor client). */
export type PaybondSubmitEvidenceParams = Omit<
  SignPayeeEvidenceParams,
  "tenantId" | "artifactsBlake3Hex" | "submittedAtRfc3339"
> & {
  artifactsBlake3Hex?: string[];
  submittedAtRfc3339?: string;
  recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
};

function nowRfc3339Seconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Ergonomic intent helpers: principal-signed intent create, x402 funding, and payee-signed evidence.
 */
export class PaybondIntents {
  constructor(private readonly harbor: HarborClient | GatewayHarborClient) {}

  /**
   * Build a principal-signed `POST /intents` body and submit it. `principalSigningSeed` must be
   * 32 bytes. `settlementRail` is signed as the requested rail; destinations stay server-owned.
   */
  async create(
    params: PaybondCreateIntentParams & { idempotencyKey?: string },
  ): Promise<Record<string, unknown>> {
    const { idempotencyKey, intentId: maybeIntentId, recognitionProof, ...fields } = params;
    const intentId = maybeIntentId ?? globalThis.crypto.randomUUID();
    const body = buildSignedCreateIntentBody({
      tenantId: this.harbor.tenantId,
      intentId,
      ...fields,
    });
    return this.harbor.createIntent(body, { idempotencyKey, recognitionProof } as never);
  }

  async createSpendIntent(
    params: PaybondCreateIntentParams & { idempotencyKey?: string },
  ): Promise<Record<string, unknown>> {
    return this.create(params);
  }

  /**
   * Advance Harbor `/intents/{id}/fund` for x402 / USDC-on-Base intents.
   */
  async fund(
    params: {
      intentId: string;
      recognitionProof: AgentRecognitionProofV1 | Record<string, unknown>;
      paymentSignature?: string;
      idempotencyKey?: string;
    },
  ): Promise<FundIntentResult> {
    return this.harbor.fundIntent(params.intentId, {
      paymentSignature: params.paymentSignature,
      idempotencyKey: params.idempotencyKey,
      recognitionProof: params.recognitionProof,
    } as never);
  }

  /**
   * Sign payee evidence and POST it. `payeeSigningSeed` must be 32 bytes.
   */
  async submitEvidence(
    params: PaybondSubmitEvidenceParams & { idempotencyKey?: string },
  ): Promise<SubmitEvidenceResult> {
    const {
      idempotencyKey,
      artifactsBlake3Hex = [],
      submittedAtRfc3339 = nowRfc3339Seconds(),
      recognitionProof,
      ...rest
    } = params;
    const wire = signPayeeEvidenceBinding({
      tenantId: this.harbor.tenantId,
      artifactsBlake3Hex,
      submittedAtRfc3339,
      ...rest,
    });
    return this.harbor.submitEvidence(rest.intentId, wire, { idempotencyKey, recognitionProof } as never);
  }
}

/**
 * High-level Kit entrypoint: tenant-bound Gateway clients plus ergonomic intent helpers.
 */
export class Paybond {
  readonly harbor: GatewayHarborClient;
  readonly signal: GatewaySignalClient;
  readonly fraud: GatewayFraudClient;
  readonly a2a: GatewayA2AClient;
  readonly protocol: GatewayProtocolClient;
  readonly intents: PaybondIntents;

  private constructor(
    harbor: GatewayHarborClient,
    signal: GatewaySignalClient,
    fraud: GatewayFraudClient,
    a2a: GatewayA2AClient,
    protocol: GatewayProtocolClient,
  ) {
    this.harbor = harbor;
    this.signal = signal;
    this.fraud = fraud;
    this.a2a = a2a;
    this.protocol = protocol;
    this.intents = new PaybondIntents(harbor);
  }

  /** Open a tenant-bound hosted Paybond session from a service-account API key. */
  static async open(init: PaybondOpenOptions): Promise<Paybond> {
    const gatewayBaseUrl = defaultGatewayBaseUrl(init.gatewayBaseUrl);
    const maxRetries = Math.max(1, init.maxRetries ?? 3);
    const tenantId = await resolveGatewayTenantId(
      gatewayBaseUrl,
      init.apiKey,
      init.principalPath ?? DEFAULT_PRINCIPAL_PATH,
      maxRetries,
      init.expectedEnvironment,
    );
    const harbor = new GatewayHarborClient(gatewayBaseUrl, tenantId, {
      staticGatewayBearerToken: init.apiKey,
      maxRetries,
    });
    const signal = new GatewaySignalClient(gatewayBaseUrl, tenantId, {
      staticGatewayBearerToken: init.apiKey,
      maxRetries,
    });
    const fraud = new GatewayFraudClient(gatewayBaseUrl, tenantId, {
      staticGatewayBearerToken: init.apiKey,
      maxRetries,
    });
    const a2a = new GatewayA2AClient(gatewayBaseUrl, {
      staticGatewayBearerToken: init.apiKey,
      maxRetries,
    });
    const protocol = new GatewayProtocolClient(gatewayBaseUrl, tenantId, {
      staticGatewayBearerToken: init.apiKey,
      maxRetries,
    });
    return new Paybond(harbor, signal, fraud, a2a, protocol);
  }

  /** Reserved for future HTTP client cleanup; safe to call after work completes. */
  async aclose(): Promise<void> {
    await Promise.resolve();
  }

  spendGuard(intentId: string, capabilityToken: string): PaybondSpendGuard {
    return new PaybondSpendGuard({ harbor: this.harbor, intentId, capabilityToken });
  }

  async authorizeSpend(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    return this.harbor.authorizeSpend(input);
  }
}

export { normalizeJson, jsonValueDigest } from "./json-digest.js";
export {
  buildSignedCreateIntentBody,
  intentCreationSignBytesRaw,
  type BuildSignedCreateIntentParams,
  type SettlementRail,
} from "./principal-intent.js";
export { artifactsDigest, signPayeeEvidenceBinding, type SignPayeeEvidenceParams } from "./payee-evidence.js";
