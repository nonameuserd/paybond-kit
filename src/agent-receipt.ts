import { createHash } from "node:crypto";

import { verify } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";
import { parseAgentReceiptJSON, validateAgentReceiptJSON } from "./agent-receipt-prevalidate.js";

export const AGENT_RECEIPT_SCHEMA_VERSION = 1;
export const AGENT_RECEIPT_KIND_V1 = "paybond.agent_receipt_v1";
export const AGENT_RECEIPT_VERSION_V1 = "1";
export const AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519 = "ed25519-sha256-json-v1";
export const AGENT_RECEIPT_SCOPE_ACTION = "action";
export const AGENT_RECEIPT_SCOPE_INTENT_TERMINAL = "intent_terminal";
export const AGENT_RECEIPT_WELL_KNOWN_PATH = "/.well-known/agent-receipt-v1.json";
export const AGENT_RECEIPT_SIGNING_KEYS_WELL_KNOWN_PATH =
  "/.well-known/agent-receipt-signing-keys.json";
/** Gateway evidence proxy header carrying Kit-verified external attestation digests. */
export const PAYBOND_AGENT_RECEIPT_ATTESTATIONS_HEADER = "x-paybond-agent-receipt-attestations";
/** Optional agent run id bound to the attestation header for server-side audit. */
export const PAYBOND_AGENT_RECEIPT_SOURCE_RUN_HEADER = "x-paybond-agent-run-id";

/** AP2 signed-mandate digest kind promoted into authorization.mandate_digest_sha256_hex. */
export const EXTERNAL_ATTESTATION_KIND_AGENT_MANDATE_V1 = "agent_mandate_v1";

export const SETTLEMENT_OUTCOME_SETTLED = "SETTLED";
export const SETTLEMENT_OUTCOME_PENDING_FINALITY = "PENDING_FINALITY";
export const SETTLEMENT_OUTCOME_REVERSED = "REVERSED";
export const SETTLEMENT_OUTCOME_FAILED = "FAILED";

export type AgentReceiptSettlementOutcome =
  | typeof SETTLEMENT_OUTCOME_SETTLED
  | typeof SETTLEMENT_OUTCOME_PENDING_FINALITY
  | typeof SETTLEMENT_OUTCOME_REVERSED
  | typeof SETTLEMENT_OUTCOME_FAILED;

const SCOPE_TOKEN_RE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const CURRENCY_RE = /^[a-z]{3}$/;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type AgentReceiptAgentV1 = {
  operator_did: string;
  model_family: string;
  model_instance_id?: string;
  config_hash_sha256_hex: string;
  prompt_hash_sha256_hex: string;
  deployment_epoch?: number;
};

export type AgentReceiptPolicyV1 = {
  template_id: string;
  version_seq?: number;
  content_digest_sha256_hex: string;
  spend_policy_version?: number;
};

export type AgentReceiptAuthorizationV1 = {
  principal_did: string;
  actor_subject: string;
  agent: AgentReceiptAgentV1;
  decision_id: string;
  audit_id?: string;
  policy: AgentReceiptPolicyV1;
  authorized_at: string;
  requested_spend_cents: number;
  currency: string;
  reason_codes?: string[];
  mandate_digest_sha256_hex?: string;
  mandate_reference_id?: string;
  /** Reserved ZK policy-compliance proof digest — schema-ready; not emitted by compose yet. */
  zk_policy_proof_digest_sha256_hex?: string;
};

export type AgentReceiptExecutionV1 = {
  run_id: string;
  tool_call_id: string;
  tool_name: string;
  operation: string;
  arguments_digest_sha256_hex: string;
  result_digest_sha256_hex?: string;
  outcome: "executed" | "denied" | "skipped" | "failed";
  started_at: string;
  completed_at: string;
  duration_ms?: number;
  /** Reserved TEE attestation digest — schema-ready; not emitted by compose yet. */
  tee_attestation_digest_sha256_hex?: string;
};

export type AgentReceiptMerchantV1 = {
  payee_did: string;
  vendor_id?: string;
  vendor_ref_id?: string;
};

export type AgentReceiptEvidenceV1 = {
  completion_preset_id: string;
  payload_digest_sha256_hex: string;
  artifacts_digest_sha256_hex?: string;
  predicate_passed: boolean;
  payee_did: string;
  payee_signature_digest_sha256_hex?: string;
};

export type AgentReceiptPaymentV1 = {
  intent_id: string;
  settlement_rail: string;
  funding_method?: string;
  funding_reference?: string;
  funding_receipt_digest_sha256_hex?: string;
};

export type AgentReceiptOutcomeV1 = {
  harbor_state: string;
  spend_reservation_outcome?: "consumed" | "released" | "pending" | "none";
  predicate_passed?: boolean;
  /** Categorical settlement claim for intent_terminal scope only. */
  settlement_outcome?: AgentReceiptSettlementOutcome;
};

export type AgentReceiptReferencesV1 = {
  intent_id: string;
  ledger_seq?: number;
  settlement_receipt_id?: string | null;
};

export type AgentReceiptExternalAttestationV1 = {
  source: string;
  kind: string;
  digest_sha256_hex: string;
  reference_id?: string;
};

export type AgentReceiptOperatorAttestationV1 = {
  operator_did: string;
  signing_public_key_ed25519_hex: string;
  message_digest_sha256_hex: string;
  ed25519_signature_hex: string;
};

export type AgentReceiptContinuityV1 = {
  prev_message_digest_sha256_hex?: string;
  sequence_number: number;
  run_id: string;
};

export const AGENT_RECEIPT_VALIDITY_TIER_OPERATIONAL = "operational";
export const AGENT_RECEIPT_VALIDITY_TIER_PRIMARY = "primary";
export const AGENT_RECEIPT_VALIDITY_TIER_ATTESTED = "attested";

export type AgentReceiptValidityTier =
  | typeof AGENT_RECEIPT_VALIDITY_TIER_OPERATIONAL
  | typeof AGENT_RECEIPT_VALIDITY_TIER_PRIMARY
  | typeof AGENT_RECEIPT_VALIDITY_TIER_ATTESTED;

export type AgentReceiptV1 = {
  schema_version: number;
  kind: string;
  receipt_version: string;
  scope: typeof AGENT_RECEIPT_SCOPE_ACTION | typeof AGENT_RECEIPT_SCOPE_INTENT_TERMINAL;
  receipt_id: string;
  issued_at: string;
  tenant_id: string;
  authorization: AgentReceiptAuthorizationV1;
  execution?: AgentReceiptExecutionV1;
  merchant?: AgentReceiptMerchantV1;
  evidence?: AgentReceiptEvidenceV1;
  payment?: AgentReceiptPaymentV1;
  outcome: AgentReceiptOutcomeV1;
  references: AgentReceiptReferencesV1;
  external_attestations: AgentReceiptExternalAttestationV1[];
  continuity?: AgentReceiptContinuityV1;
  operator_attestation?: AgentReceiptOperatorAttestationV1;
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

export type ConfigHashInput = {
  system_prompt: string;
  tools_manifest: unknown;
  policy_snapshot_id: string;
};

function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

function formatRfc3339Seconds(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    throw new Error("agent receipt: timestamp is invalid");
  }
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeJson(item));
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      out[key] = canonicalizeJson(record[key]);
    }
    return out;
  }
  return value;
}

function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(canonicalizeJson(value)));
}

/** Returns sha256(JCS({ system_prompt, tools_manifest, policy_snapshot_id })). */
export function configHashSha256Hex(input: ConfigHashInput): string {
  return sha256Hex(jcsBytes(input));
}

/** Returns sha256(normalized_user_prompt). */
export function promptHashSha256Hex(normalizedUserPrompt: string): string {
  return sha256Hex(normalizedUserPrompt);
}

/** Returns sha256(JCS(value)). */
export function valueDigestSha256Hex(value: unknown): string {
  return sha256Hex(jcsBytes(value));
}

/** Returns sha256(intent_id + "\\x00" + tool_call_id) as lowercase hex. */
export function actionReceiptId(intentId: string, toolCallId: string): string {
  return sha256Hex(`${intentId}\u0000${toolCallId}`);
}

function normalizeScopeToken(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    throw new Error(`agent receipt: ${field} is required`);
  }
  if (!SCOPE_TOKEN_RE.test(normalized)) {
    throw new Error(`agent receipt: ${field} ${JSON.stringify(normalized)} is not canonical`);
  }
  return normalized;
}

function requireHex64(value: string, field: string): void {
  if (!HEX64_RE.test(value)) {
    throw new Error(`agent receipt: ${field} must be a lowercase 64-byte hex SHA-256 digest`);
  }
}

function parseUuid(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!UUID_RE.test(normalized)) {
    throw new Error(`agent receipt: ${field} must be a canonical UUID`);
  }
  return normalized;
}

function normalizeScopeSet(values: string[] | undefined, field: string): string[] {
  if (!values?.length) {
    return [];
  }
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const normalized = normalizeScopeToken(value, field);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out;
}

function normalizeReceipt(receipt: AgentReceiptV1): AgentReceiptV1 {
  const schemaVersion = receipt.schema_version === 0 ? AGENT_RECEIPT_SCHEMA_VERSION : receipt.schema_version;
  if (schemaVersion !== AGENT_RECEIPT_SCHEMA_VERSION) {
    throw new Error(`agent receipt: unsupported schema_version ${schemaVersion}`);
  }

  const kind = receipt.kind.trim() || AGENT_RECEIPT_KIND_V1;
  if (kind !== AGENT_RECEIPT_KIND_V1) {
    throw new Error(`agent receipt: unsupported kind ${JSON.stringify(kind)}`);
  }

  const receiptVersion = receipt.receipt_version.trim() || AGENT_RECEIPT_VERSION_V1;
  if (receiptVersion !== AGENT_RECEIPT_VERSION_V1) {
    throw new Error(`agent receipt: unsupported receipt_version ${JSON.stringify(receiptVersion)}`);
  }

  const scope = receipt.scope.trim().toLowerCase();
  if (scope !== AGENT_RECEIPT_SCOPE_ACTION && scope !== AGENT_RECEIPT_SCOPE_INTENT_TERMINAL) {
    throw new Error(
      `agent receipt: scope must be ${AGENT_RECEIPT_SCOPE_ACTION} or ${AGENT_RECEIPT_SCOPE_INTENT_TERMINAL}`,
    );
  }

  const receiptId = receipt.receipt_id.trim().toLowerCase();
  if (!receiptId) {
    throw new Error("agent receipt: receipt_id is required");
  }

  const tenantId = receipt.tenant_id.trim();
  if (!tenantId) {
    throw new Error("agent receipt: tenant_id is required");
  }

  const authorization = normalizeAuthorization(receipt.authorization);
  const references = normalizeReferences(receipt.references);
  const externalAttestations = normalizeExternalAttestations(receipt.external_attestations ?? []);
  verifyMandateAuthorizationConsistency(authorization, externalAttestations);
  const outcome = normalizeOutcome(receipt.outcome, scope);

  let execution: AgentReceiptExecutionV1 | undefined;
  if (scope === AGENT_RECEIPT_SCOPE_ACTION) {
    if (!receipt.execution) {
      throw new Error("agent receipt: execution is required for action scope");
    }
    execution = normalizeExecution(receipt.execution);
  }

  const normalized: AgentReceiptV1 = {
    schema_version: AGENT_RECEIPT_SCHEMA_VERSION,
    kind: AGENT_RECEIPT_KIND_V1,
    receipt_version: AGENT_RECEIPT_VERSION_V1,
    scope: scope as AgentReceiptV1["scope"],
    receipt_id: receiptId,
    issued_at: formatRfc3339Seconds(receipt.issued_at),
    tenant_id: tenantId,
    authorization,
    execution,
    merchant: receipt.merchant ? normalizeMerchant(receipt.merchant) : undefined,
    evidence: receipt.evidence ? normalizeEvidence(receipt.evidence) : undefined,
    payment: receipt.payment ? normalizePayment(receipt.payment) : undefined,
    outcome,
    references,
    external_attestations: externalAttestations,
    continuity: receipt.continuity ? normalizeContinuity(receipt.continuity, execution) : undefined,
    operator_attestation: receipt.operator_attestation
      ? normalizeOperatorAttestation(receipt.operator_attestation)
      : undefined,
    signing_algorithm:
      receipt.signing_algorithm.trim().toLowerCase() || AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    message_digest_sha256_hex: receipt.message_digest_sha256_hex.trim().toLowerCase(),
    signing_public_key_ed25519_hex: receipt.signing_public_key_ed25519_hex.trim().toLowerCase(),
    ed25519_signature_hex: receipt.ed25519_signature_hex.trim().toLowerCase(),
  };

  verifyReceiptId(normalized);
  return normalized;
}

function normalizeContinuity(
  continuity: AgentReceiptContinuityV1,
  execution: AgentReceiptExecutionV1 | undefined,
): AgentReceiptContinuityV1 {
  const runId = continuity.run_id.trim().toLowerCase();
  if (!UUID_RE.test(runId)) {
    throw new Error("agent receipt: continuity.run_id must be a canonical UUID");
  }
  if (!Number.isInteger(continuity.sequence_number) || continuity.sequence_number < 1) {
    throw new Error("agent receipt: continuity.sequence_number must be an integer >= 1");
  }
  const prev = continuity.prev_message_digest_sha256_hex?.trim().toLowerCase() ?? "";
  if (continuity.sequence_number === 1) {
    if (prev) {
      throw new Error(
        "agent receipt: continuity.sequence_number 1 must not set prev_message_digest_sha256_hex",
      );
    }
  } else {
    requireHex64(prev, "continuity.prev_message_digest_sha256_hex");
  }
  if (execution && execution.run_id !== runId) {
    throw new Error("agent receipt: continuity.run_id must match execution.run_id");
  }
  return {
    ...(prev ? { prev_message_digest_sha256_hex: prev } : {}),
    sequence_number: continuity.sequence_number,
    run_id: runId,
  };
}

function normalizeOperatorAttestation(
  attestation: AgentReceiptOperatorAttestationV1,
): AgentReceiptOperatorAttestationV1 {
  const operatorDid = attestation.operator_did.trim();
  if (!operatorDid) {
    throw new Error("agent receipt: operator_attestation.operator_did is required");
  }
  return {
    operator_did: operatorDid,
    signing_public_key_ed25519_hex: attestation.signing_public_key_ed25519_hex.trim().toLowerCase(),
    message_digest_sha256_hex: attestation.message_digest_sha256_hex.trim().toLowerCase(),
    ed25519_signature_hex: attestation.ed25519_signature_hex.trim().toLowerCase(),
  };
}

function normalizeAuthorization(authorization: AgentReceiptAuthorizationV1): AgentReceiptAuthorizationV1 {
  const principalDid = authorization.principal_did.trim();
  const actorSubject = authorization.actor_subject.trim();
  if (!principalDid) {
    throw new Error("agent receipt: principal_did is required");
  }
  if (!actorSubject) {
    throw new Error("agent receipt: actor_subject is required");
  }
  const currency = authorization.currency.trim().toLowerCase();
  if (!CURRENCY_RE.test(currency)) {
    throw new Error(`agent receipt: currency ${JSON.stringify(currency)} is not canonical`);
  }
  if (authorization.requested_spend_cents < 0) {
    throw new Error("agent receipt: requested_spend_cents must be non-negative");
  }
  let mandateDigest: string | undefined;
  if (authorization.mandate_digest_sha256_hex) {
    mandateDigest = authorization.mandate_digest_sha256_hex.trim().toLowerCase();
    requireHex64(mandateDigest, "mandate_digest_sha256_hex");
  }
  const mandateReferenceId = authorization.mandate_reference_id?.trim() || undefined;
  if (mandateReferenceId && !mandateDigest) {
    throw new Error("agent receipt: mandate_reference_id requires mandate_digest_sha256_hex");
  }
  let zkPolicyProofDigest: string | undefined;
  if (authorization.zk_policy_proof_digest_sha256_hex) {
    zkPolicyProofDigest = authorization.zk_policy_proof_digest_sha256_hex.trim().toLowerCase();
    requireHex64(zkPolicyProofDigest, "zk_policy_proof_digest_sha256_hex");
  }
  return {
    principal_did: principalDid,
    actor_subject: actorSubject,
    agent: normalizeAgent(authorization.agent),
    decision_id: parseUuid(authorization.decision_id, "decision_id"),
    audit_id: authorization.audit_id ? parseUuid(authorization.audit_id, "audit_id") : undefined,
    policy: normalizePolicy(authorization.policy),
    authorized_at: formatRfc3339Seconds(authorization.authorized_at),
    requested_spend_cents: authorization.requested_spend_cents,
    currency,
    reason_codes: normalizeScopeSet(authorization.reason_codes, "reason_codes"),
    ...(mandateDigest ? { mandate_digest_sha256_hex: mandateDigest } : {}),
    ...(mandateReferenceId ? { mandate_reference_id: mandateReferenceId } : {}),
    ...(zkPolicyProofDigest ? { zk_policy_proof_digest_sha256_hex: zkPolicyProofDigest } : {}),
  };
}

function normalizeAgent(agent: AgentReceiptAgentV1): AgentReceiptAgentV1 {
  const modelFamily = normalizeScopeToken(agent.model_family, "agent.model_family");
  const configHash = agent.config_hash_sha256_hex.trim().toLowerCase();
  const promptHash = agent.prompt_hash_sha256_hex.trim().toLowerCase();
  requireHex64(configHash, "agent.config_hash_sha256_hex");
  requireHex64(promptHash, "agent.prompt_hash_sha256_hex");
  const operatorDid = agent.operator_did.trim();
  if (!operatorDid) {
    throw new Error("agent receipt: agent.operator_did is required");
  }
  return {
    operator_did: operatorDid,
    model_family: modelFamily,
    model_instance_id: agent.model_instance_id?.trim() || undefined,
    config_hash_sha256_hex: configHash,
    prompt_hash_sha256_hex: promptHash,
    deployment_epoch: agent.deployment_epoch,
  };
}

function normalizePolicy(policy: AgentReceiptPolicyV1): AgentReceiptPolicyV1 {
  const templateId = policy.template_id.trim();
  const digest = policy.content_digest_sha256_hex.trim().toLowerCase();
  if (!templateId) {
    throw new Error("agent receipt: policy.template_id is required");
  }
  requireHex64(digest, "policy.content_digest_sha256_hex");
  return {
    template_id: templateId,
    version_seq: policy.version_seq,
    content_digest_sha256_hex: digest,
    spend_policy_version: policy.spend_policy_version,
  };
}

function normalizeExecution(execution: AgentReceiptExecutionV1): AgentReceiptExecutionV1 {
  const toolCallId = execution.tool_call_id.trim();
  if (!toolCallId) {
    throw new Error("agent receipt: tool_call_id is required");
  }
  const argumentsDigest = execution.arguments_digest_sha256_hex.trim().toLowerCase();
  requireHex64(argumentsDigest, "arguments_digest_sha256_hex");
  let resultDigest: string | undefined;
  if (execution.result_digest_sha256_hex) {
    resultDigest = execution.result_digest_sha256_hex.trim().toLowerCase();
    requireHex64(resultDigest, "result_digest_sha256_hex");
  }
  const outcome = execution.outcome.trim().toLowerCase();
  if (!["executed", "denied", "skipped", "failed"].includes(outcome)) {
    throw new Error("agent receipt: outcome must be executed, denied, skipped, or failed");
  }
  if ((execution.duration_ms ?? 0) < 0) {
    throw new Error("agent receipt: duration_ms must be non-negative");
  }
  let teeAttestationDigest: string | undefined;
  if (execution.tee_attestation_digest_sha256_hex) {
    teeAttestationDigest = execution.tee_attestation_digest_sha256_hex.trim().toLowerCase();
    requireHex64(teeAttestationDigest, "tee_attestation_digest_sha256_hex");
  }
  return {
    run_id: parseUuid(execution.run_id, "run_id"),
    tool_call_id: toolCallId,
    tool_name: normalizeScopeToken(execution.tool_name, "tool_name"),
    operation: normalizeScopeToken(execution.operation, "operation"),
    arguments_digest_sha256_hex: argumentsDigest,
    result_digest_sha256_hex: resultDigest,
    outcome: outcome as AgentReceiptExecutionV1["outcome"],
    started_at: formatRfc3339Seconds(execution.started_at),
    completed_at: formatRfc3339Seconds(execution.completed_at),
    duration_ms: execution.duration_ms,
    ...(teeAttestationDigest ? { tee_attestation_digest_sha256_hex: teeAttestationDigest } : {}),
  };
}

function normalizeMerchant(merchant: AgentReceiptMerchantV1): AgentReceiptMerchantV1 {
  const payeeDid = merchant.payee_did.trim();
  if (!payeeDid) {
    throw new Error("agent receipt: payee_did is required");
  }
  return {
    payee_did: payeeDid,
    vendor_id: merchant.vendor_id ? normalizeScopeToken(merchant.vendor_id, "vendor_id") : undefined,
    vendor_ref_id: merchant.vendor_ref_id?.trim() || undefined,
  };
}

function normalizeEvidence(evidence: AgentReceiptEvidenceV1): AgentReceiptEvidenceV1 {
  const payloadDigest = evidence.payload_digest_sha256_hex.trim().toLowerCase();
  requireHex64(payloadDigest, "payload_digest_sha256_hex");
  let artifactsDigest: string | undefined;
  if (evidence.artifacts_digest_sha256_hex) {
    artifactsDigest = evidence.artifacts_digest_sha256_hex.trim().toLowerCase();
    requireHex64(artifactsDigest, "artifacts_digest_sha256_hex");
  }
  let payeeSignatureDigest: string | undefined;
  if (evidence.payee_signature_digest_sha256_hex) {
    payeeSignatureDigest = evidence.payee_signature_digest_sha256_hex.trim().toLowerCase();
    requireHex64(payeeSignatureDigest, "payee_signature_digest_sha256_hex");
  }
  const payeeDid = evidence.payee_did.trim();
  if (!payeeDid) {
    throw new Error("agent receipt: payee_did is required");
  }
  return {
    completion_preset_id: normalizeScopeToken(evidence.completion_preset_id, "completion_preset_id"),
    payload_digest_sha256_hex: payloadDigest,
    artifacts_digest_sha256_hex: artifactsDigest,
    predicate_passed: evidence.predicate_passed,
    payee_did: payeeDid,
    payee_signature_digest_sha256_hex: payeeSignatureDigest,
  };
}

function normalizePayment(payment: AgentReceiptPaymentV1): AgentReceiptPaymentV1 {
  let fundingDigest: string | undefined;
  if (payment.funding_receipt_digest_sha256_hex) {
    fundingDigest = payment.funding_receipt_digest_sha256_hex.trim().toLowerCase();
    requireHex64(fundingDigest, "funding_receipt_digest_sha256_hex");
  }
  return {
    intent_id: parseUuid(payment.intent_id, "intent_id"),
    settlement_rail: normalizeScopeToken(payment.settlement_rail, "settlement_rail"),
    funding_method: payment.funding_method
      ? normalizeScopeToken(payment.funding_method, "funding_method")
      : undefined,
    funding_reference: payment.funding_reference?.trim() || undefined,
    funding_receipt_digest_sha256_hex: fundingDigest,
  };
}

function normalizeOutcome(outcome: AgentReceiptOutcomeV1, scope: string): AgentReceiptOutcomeV1 {
  const harborState = normalizeScopeToken(outcome.harbor_state, "harbor_state");
  let spendReservationOutcome: AgentReceiptOutcomeV1["spend_reservation_outcome"];
  if (outcome.spend_reservation_outcome) {
    const normalized = outcome.spend_reservation_outcome.trim().toLowerCase();
    if (!["consumed", "released", "pending", "none"].includes(normalized)) {
      throw new Error(
        "agent receipt: spend_reservation_outcome must be consumed, released, pending, or none",
      );
    }
    spendReservationOutcome = normalized as AgentReceiptOutcomeV1["spend_reservation_outcome"];
  }
  let settlementOutcome: AgentReceiptSettlementOutcome | undefined;
  if (outcome.settlement_outcome) {
    const normalized = outcome.settlement_outcome.trim();
    if (
      ![
        SETTLEMENT_OUTCOME_SETTLED,
        SETTLEMENT_OUTCOME_PENDING_FINALITY,
        SETTLEMENT_OUTCOME_REVERSED,
        SETTLEMENT_OUTCOME_FAILED,
      ].includes(normalized)
    ) {
      throw new Error(
        "agent receipt: settlement_outcome must be SETTLED, PENDING_FINALITY, REVERSED, or FAILED",
      );
    }
    if (scope !== AGENT_RECEIPT_SCOPE_INTENT_TERMINAL) {
      throw new Error("agent receipt: settlement_outcome is only valid for intent_terminal scope");
    }
    settlementOutcome = normalized as AgentReceiptSettlementOutcome;
  }
  return {
    harbor_state: harborState,
    spend_reservation_outcome: spendReservationOutcome,
    predicate_passed: outcome.predicate_passed,
    ...(settlementOutcome ? { settlement_outcome: settlementOutcome } : {}),
  };
}

function verifyMandateAuthorizationConsistency(
  authorization: AgentReceiptAuthorizationV1,
  attestations: AgentReceiptExternalAttestationV1[],
): void {
  const digest = authorization.mandate_digest_sha256_hex?.trim().toLowerCase() ?? "";
  const refId = authorization.mandate_reference_id?.trim() ?? "";
  if (!digest && !refId) {
    return;
  }
  if (!digest) {
    throw new Error("agent receipt: mandate_reference_id requires mandate_digest_sha256_hex");
  }
  requireHex64(digest, "mandate_digest_sha256_hex");
  const matched = attestations.find(
    (entry) =>
      entry.kind.trim() === EXTERNAL_ATTESTATION_KIND_AGENT_MANDATE_V1 &&
      entry.digest_sha256_hex.trim().toLowerCase() === digest,
  );
  if (!matched) {
    throw new Error(
      `agent receipt: mandate_digest_sha256_hex must match an external_attestations entry of kind ${EXTERNAL_ATTESTATION_KIND_AGENT_MANDATE_V1}`,
    );
  }
  const attestationRef = matched.reference_id?.trim() ?? "";
  if (refId && refId !== attestationRef) {
    throw new Error(
      "agent receipt: mandate_reference_id must match the matching external_attestations reference_id",
    );
  }
}

function normalizeReferences(references: AgentReceiptReferencesV1): AgentReceiptReferencesV1 {
  if ((references.ledger_seq ?? 0) < 0) {
    throw new Error("agent receipt: ledger_seq must be non-negative");
  }
  let settlementReceiptId = references.settlement_receipt_id;
  if (settlementReceiptId) {
    const trimmed = settlementReceiptId.trim().toLowerCase();
    if (!trimmed) {
      settlementReceiptId = null;
    } else if (!UUID_RE.test(trimmed) && !HEX64_RE.test(trimmed)) {
      throw new Error(
        "agent receipt: settlement_receipt_id must be a canonical UUID or lowercase 64-byte hex digest",
      );
    } else {
      settlementReceiptId = trimmed;
    }
  }
  return {
    intent_id: parseUuid(references.intent_id, "intent_id"),
    ledger_seq: references.ledger_seq,
    settlement_receipt_id: settlementReceiptId ?? null,
  };
}

function normalizeExternalAttestations(
  values: AgentReceiptExternalAttestationV1[],
): AgentReceiptExternalAttestationV1[] {
  return values.map((value) => {
    const digest = value.digest_sha256_hex.trim().toLowerCase();
    requireHex64(digest, "digest_sha256_hex");
    if (!value.kind.trim()) {
      throw new Error("agent receipt: kind is required");
    }
    return {
      source: normalizeScopeToken(value.source, "source"),
      kind: value.kind.trim(),
      digest_sha256_hex: digest,
      reference_id: value.reference_id?.trim() || undefined,
    };
  });
}

function verifyReceiptId(receipt: AgentReceiptV1): void {
  if (receipt.scope === AGENT_RECEIPT_SCOPE_ACTION) {
    if (!receipt.execution) {
      throw new Error("agent receipt: execution is required to verify action receipt_id");
    }
    const expected = actionReceiptId(receipt.references.intent_id, receipt.execution.tool_call_id);
    if (receipt.receipt_id !== expected) {
      throw new Error("agent receipt: receipt_id does not match action scope derivation");
    }
    requireHex64(receipt.receipt_id, "receipt_id");
    return;
  }
  if (receipt.receipt_id !== receipt.references.intent_id) {
    throw new Error("agent receipt: receipt_id must equal intent_id for intent_terminal scope");
  }
  parseUuid(receipt.receipt_id, "receipt_id");
}

function marshalCanonicalAgentReceipt(receipt: AgentReceiptV1): Uint8Array {
  const authorization: Record<string, unknown> = {
    principal_did: receipt.authorization.principal_did,
    actor_subject: receipt.authorization.actor_subject,
    agent: {
      operator_did: receipt.authorization.agent.operator_did,
      model_family: receipt.authorization.agent.model_family,
      ...(receipt.authorization.agent.model_instance_id
        ? { model_instance_id: receipt.authorization.agent.model_instance_id }
        : {}),
      config_hash_sha256_hex: receipt.authorization.agent.config_hash_sha256_hex,
      prompt_hash_sha256_hex: receipt.authorization.agent.prompt_hash_sha256_hex,
      ...(receipt.authorization.agent.deployment_epoch
        ? { deployment_epoch: receipt.authorization.agent.deployment_epoch }
        : {}),
    },
    decision_id: receipt.authorization.decision_id,
    ...(receipt.authorization.audit_id ? { audit_id: receipt.authorization.audit_id } : {}),
    policy: {
      template_id: receipt.authorization.policy.template_id,
      ...(receipt.authorization.policy.version_seq
        ? { version_seq: receipt.authorization.policy.version_seq }
        : {}),
      content_digest_sha256_hex: receipt.authorization.policy.content_digest_sha256_hex,
      ...(receipt.authorization.policy.spend_policy_version
        ? { spend_policy_version: receipt.authorization.policy.spend_policy_version }
        : {}),
    },
    authorized_at: receipt.authorization.authorized_at,
    requested_spend_cents: receipt.authorization.requested_spend_cents,
    currency: receipt.authorization.currency,
    ...(receipt.authorization.reason_codes?.length
      ? { reason_codes: receipt.authorization.reason_codes }
      : {}),
    ...(receipt.authorization.mandate_digest_sha256_hex
      ? { mandate_digest_sha256_hex: receipt.authorization.mandate_digest_sha256_hex }
      : {}),
    ...(receipt.authorization.mandate_reference_id
      ? { mandate_reference_id: receipt.authorization.mandate_reference_id }
      : {}),
    ...(receipt.authorization.zk_policy_proof_digest_sha256_hex
      ? {
          zk_policy_proof_digest_sha256_hex:
            receipt.authorization.zk_policy_proof_digest_sha256_hex,
        }
      : {}),
  };

  const payload: Record<string, unknown> = {
    schema_version: receipt.schema_version,
    kind: receipt.kind,
    receipt_version: receipt.receipt_version,
    scope: receipt.scope,
    receipt_id: receipt.receipt_id,
    issued_at: receipt.issued_at,
    tenant_id: receipt.tenant_id,
    authorization,
  };

  if (receipt.execution) {
    payload.execution = {
      run_id: receipt.execution.run_id,
      tool_call_id: receipt.execution.tool_call_id,
      tool_name: receipt.execution.tool_name,
      operation: receipt.execution.operation,
      arguments_digest_sha256_hex: receipt.execution.arguments_digest_sha256_hex,
      ...(receipt.execution.result_digest_sha256_hex
        ? { result_digest_sha256_hex: receipt.execution.result_digest_sha256_hex }
        : {}),
      outcome: receipt.execution.outcome,
      started_at: receipt.execution.started_at,
      completed_at: receipt.execution.completed_at,
      ...(receipt.execution.duration_ms ? { duration_ms: receipt.execution.duration_ms } : {}),
      ...(receipt.execution.tee_attestation_digest_sha256_hex
        ? {
            tee_attestation_digest_sha256_hex:
              receipt.execution.tee_attestation_digest_sha256_hex,
          }
        : {}),
    };
  }
  if (receipt.merchant) {
    payload.merchant = {
      payee_did: receipt.merchant.payee_did,
      ...(receipt.merchant.vendor_id ? { vendor_id: receipt.merchant.vendor_id } : {}),
      ...(receipt.merchant.vendor_ref_id ? { vendor_ref_id: receipt.merchant.vendor_ref_id } : {}),
    };
  }
  if (receipt.evidence) {
    payload.evidence = {
      completion_preset_id: receipt.evidence.completion_preset_id,
      payload_digest_sha256_hex: receipt.evidence.payload_digest_sha256_hex,
      ...(receipt.evidence.artifacts_digest_sha256_hex
        ? { artifacts_digest_sha256_hex: receipt.evidence.artifacts_digest_sha256_hex }
        : {}),
      predicate_passed: receipt.evidence.predicate_passed,
      payee_did: receipt.evidence.payee_did,
      ...(receipt.evidence.payee_signature_digest_sha256_hex
        ? { payee_signature_digest_sha256_hex: receipt.evidence.payee_signature_digest_sha256_hex }
        : {}),
    };
  }
  if (receipt.payment) {
    payload.payment = {
      intent_id: receipt.payment.intent_id,
      settlement_rail: receipt.payment.settlement_rail,
      ...(receipt.payment.funding_method ? { funding_method: receipt.payment.funding_method } : {}),
      ...(receipt.payment.funding_reference
        ? { funding_reference: receipt.payment.funding_reference }
        : {}),
      ...(receipt.payment.funding_receipt_digest_sha256_hex
        ? { funding_receipt_digest_sha256_hex: receipt.payment.funding_receipt_digest_sha256_hex }
        : {}),
    };
  }

  payload.outcome = {
    harbor_state: receipt.outcome.harbor_state,
    ...(receipt.outcome.spend_reservation_outcome
      ? { spend_reservation_outcome: receipt.outcome.spend_reservation_outcome }
      : {}),
    ...(receipt.outcome.predicate_passed !== undefined
      ? { predicate_passed: receipt.outcome.predicate_passed }
      : {}),
    ...(receipt.outcome.settlement_outcome
      ? { settlement_outcome: receipt.outcome.settlement_outcome }
      : {}),
  };
  payload.references = {
    intent_id: receipt.references.intent_id,
    ...(receipt.references.ledger_seq ? { ledger_seq: receipt.references.ledger_seq } : {}),
    settlement_receipt_id: receipt.references.settlement_receipt_id ?? null,
  };
  payload.external_attestations =
    receipt.external_attestations.length > 0 ? receipt.external_attestations : null;
  if (receipt.continuity) {
    payload.continuity = {
      ...(receipt.continuity.prev_message_digest_sha256_hex
        ? { prev_message_digest_sha256_hex: receipt.continuity.prev_message_digest_sha256_hex }
        : {}),
      sequence_number: receipt.continuity.sequence_number,
      run_id: receipt.continuity.run_id,
    };
  }

  return new TextEncoder().encode(JSON.stringify(payload));
}

/** Returns canonical signing bytes for a normalized receipt body. */
export function canonicalAgentReceiptBytes(receipt: AgentReceiptV1): Uint8Array {
  return marshalCanonicalAgentReceipt(normalizeReceipt(receipt));
}

/**
 * Returns sha256(canonical receipt bytes) as lowercase hex, ignoring any existing
 * `message_digest_sha256_hex` on the input. Used to compose unsigned receipt drafts
 * (Agent Receipt Standard Phase 1) and to compute the digest signers must sign over.
 */
export function agentReceiptMessageDigestSha256Hex(receipt: AgentReceiptV1): string {
  return sha256Hex(canonicalAgentReceiptBytes(receipt));
}

/** Optional trust-anchor checks during agent receipt verification. */
export type VerifyAgentReceiptV1Options = {
  /** Lowercase signing_public_key_ed25519_hex values accepted when non-empty. */
  expectedSigningPublicKeys?: readonly string[];
  /**
   * When true, require any operator_attestation signing key to appear in
   * trustedOperatorPublicKeys (e.g. tenant middleware attach recognition keys). The
   * operator_did binding to authorization.agent.operator_did is always enforced.
   *
   * For `trustMode: "tenant_registry"`, defaults to true when an operator_attestation
   * is present (empty trusted set rejects the attestation). Gateway JWKS / gateway
   * trust mode leaves this opt-in.
   */
  verifyOperatorAgainstRegistry?: boolean;
  /** Lowercase operator signing pubkeys accepted when the registry check is enabled. */
  trustedOperatorPublicKeys?: readonly string[];
  /**
   * Mirror of Gateway `?trust_mode=`. `tenant_registry` defaults operator registry
   * checks on when an operator_attestation is present.
   */
  trustMode?: "gateway" | "tenant_registry";
  /**
   * Required validity tier: `operational` (default), `primary`, or `attested`.
   * `attested` forces operator registry checks.
   */
  requiredValidityTier?: AgentReceiptValidityTier | string;
  /**
   * When set, require `continuity.prev_message_digest_sha256_hex` to equal this digest.
   */
  expectedPriorMessageDigestHex?: string;
};

function allowsSigningPublicKeyHex(
  signingPublicKeyHex: string,
  expectedSigningPublicKeys: readonly string[] | undefined,
): boolean {
  if (!expectedSigningPublicKeys || expectedSigningPublicKeys.length === 0) {
    return true;
  }
  const normalized = signingPublicKeyHex.trim().toLowerCase();
  return expectedSigningPublicKeys.some((value) => value.trim().toLowerCase() === normalized);
}

function allowsOperatorPublicKeyHex(
  operatorPublicKeyHex: string,
  trustedOperatorPublicKeys: readonly string[] | undefined,
): boolean {
  if (!trustedOperatorPublicKeys || trustedOperatorPublicKeys.length === 0) {
    return false;
  }
  const normalized = operatorPublicKeyHex.trim().toLowerCase();
  return trustedOperatorPublicKeys.some((value) => value.trim().toLowerCase() === normalized);
}

function normalizeValidityTier(value: string | undefined): AgentReceiptValidityTier {
  const normalized = (value ?? "").trim().toLowerCase();
  switch (normalized) {
    case "":
    case AGENT_RECEIPT_VALIDITY_TIER_OPERATIONAL:
      return AGENT_RECEIPT_VALIDITY_TIER_OPERATIONAL;
    case AGENT_RECEIPT_VALIDITY_TIER_PRIMARY:
      return AGENT_RECEIPT_VALIDITY_TIER_PRIMARY;
    case AGENT_RECEIPT_VALIDITY_TIER_ATTESTED:
      return AGENT_RECEIPT_VALIDITY_TIER_ATTESTED;
    default:
      throw new Error(`agent receipt: unknown validity_tier ${JSON.stringify(value)}`);
  }
}

function requirePrimaryValidity(receipt: AgentReceiptV1): void {
  if (!receipt.evidence) {
    throw new Error("agent receipt: primary validity requires evidence");
  }
  const digest = receipt.evidence.payee_signature_digest_sha256_hex?.trim().toLowerCase() ?? "";
  if (!digest) {
    throw new Error(
      "agent receipt: primary validity requires evidence.payee_signature_digest_sha256_hex",
    );
  }
  requireHex64(digest, "evidence.payee_signature_digest_sha256_hex");
  if (receipt.payment && receipt.payment.intent_id !== receipt.references.intent_id) {
    throw new Error(
      "agent receipt: primary validity: payment.intent_id must match references.intent_id",
    );
  }
  if (
    receipt.merchant &&
    receipt.merchant.payee_did.trim() !== "" &&
    receipt.evidence.payee_did.trim() !== "" &&
    receipt.merchant.payee_did.trim() !== receipt.evidence.payee_did.trim()
  ) {
    throw new Error(
      "agent receipt: primary validity: evidence.payee_did must match merchant.payee_did",
    );
  }
}

function requireAttestedValidity(
  receipt: AgentReceiptV1,
  trustedOperatorPublicKeys: readonly string[] | undefined,
): void {
  if (!receipt.operator_attestation) {
    throw new Error("agent receipt: attested validity requires operator_attestation");
  }
  if (
    !allowsOperatorPublicKeyHex(
      receipt.operator_attestation.signing_public_key_ed25519_hex,
      trustedOperatorPublicKeys,
    )
  ) {
    throw new Error(
      "agent receipt: attested validity requires operator_attestation signing key in the configured tenant operator registry",
    );
  }
}

/** Returns the highest validity tier met under the given registry options. */
export function achievedValidityTier(
  receipt: AgentReceiptV1,
  options: Pick<VerifyAgentReceiptV1Options, "trustedOperatorPublicKeys"> = {},
): AgentReceiptValidityTier {
  try {
    requirePrimaryValidity(receipt);
  } catch {
    return AGENT_RECEIPT_VALIDITY_TIER_OPERATIONAL;
  }
  if (
    receipt.operator_attestation &&
    allowsOperatorPublicKeyHex(
      receipt.operator_attestation.signing_public_key_ed25519_hex,
      options.trustedOperatorPublicKeys,
    )
  ) {
    return AGENT_RECEIPT_VALIDITY_TIER_ATTESTED;
  }
  return AGENT_RECEIPT_VALIDITY_TIER_PRIMARY;
}

/**
 * Builds the next continuity link from a prior signed action receipt for the same run.
 * When `prior` is omitted, returns sequence 1 with no prev digest.
 */
export function continuityFromPrior(
  runId: string,
  prior?: AgentReceiptV1 | null,
): AgentReceiptContinuityV1 {
  const normalizedRunId = runId.trim().toLowerCase();
  if (!UUID_RE.test(normalizedRunId)) {
    throw new Error("agent receipt: continuity.run_id must be a canonical UUID");
  }
  if (!prior) {
    return {
      sequence_number: 1,
      run_id: normalizedRunId,
    };
  }
  let priorRunId = normalizedRunId;
  if (prior.continuity?.run_id?.trim()) {
    priorRunId = prior.continuity.run_id.trim().toLowerCase();
  } else if (prior.execution?.run_id?.trim()) {
    priorRunId = prior.execution.run_id.trim().toLowerCase();
  }
  if (priorRunId !== normalizedRunId) {
    throw new Error("agent receipt: continuity prior run_id mismatch");
  }
  const prevDigest = prior.message_digest_sha256_hex.trim().toLowerCase();
  requireHex64(prevDigest, "prior message_digest_sha256_hex");
  const seq =
    prior.continuity && prior.continuity.sequence_number > 0
      ? prior.continuity.sequence_number + 1
      : 2;
  return {
    prev_message_digest_sha256_hex: prevDigest,
    sequence_number: seq,
    run_id: normalizedRunId,
  };
}

/**
 * Validates an ordered set of action receipts that declare continuity.
 * Receipts without continuity are ignored. Broken links fail closed.
 */
export function verifyContinuityChain(receipts: readonly AgentReceiptV1[]): void {
  const linked = receipts
    .filter((receipt) => receipt.continuity != null)
    .map((receipt) => normalizeReceipt(receipt))
    .sort((a, b) => {
      const aRun = a.continuity?.run_id ?? "";
      const bRun = b.continuity?.run_id ?? "";
      if (aRun === bRun) {
        return (a.continuity?.sequence_number ?? 0) - (b.continuity?.sequence_number ?? 0);
      }
      return aRun < bRun ? -1 : 1;
    });
  if (linked.length === 0) {
    return;
  }
  const prevByRun = new Map<string, AgentReceiptV1>();
  for (const item of linked) {
    const continuity = item.continuity;
    if (!continuity) {
      continue;
    }
    const prior = prevByRun.get(continuity.run_id);
    if (!prior) {
      if (continuity.sequence_number !== 1 || continuity.prev_message_digest_sha256_hex) {
        throw new Error(
          `agent receipt: continuity chain for run ${continuity.run_id} must start at sequence_number 1 without prev digest`,
        );
      }
      prevByRun.set(continuity.run_id, item);
      continue;
    }
    const expectedSeq = (prior.continuity?.sequence_number ?? 1) + 1;
    if (continuity.sequence_number !== expectedSeq) {
      throw new Error(
        `agent receipt: continuity chain sequence gap for run ${continuity.run_id}: got ${continuity.sequence_number} want ${expectedSeq}`,
      );
    }
    if (continuity.prev_message_digest_sha256_hex !== prior.message_digest_sha256_hex) {
      throw new Error(
        `agent receipt: continuity chain digest mismatch for run ${continuity.run_id} sequence ${continuity.sequence_number}`,
      );
    }
    prevByRun.set(continuity.run_id, item);
  }
}

function verifyContinuityExpectedPrior(
  receipt: AgentReceiptV1,
  expectedPriorMessageDigestHex: string | undefined,
): void {
  const expected = expectedPriorMessageDigestHex?.trim().toLowerCase() ?? "";
  if (!expected) {
    return;
  }
  if (!receipt.continuity) {
    throw new Error(
      "agent receipt: continuity is required when an expected prior digest is configured",
    );
  }
  if (receipt.continuity.sequence_number < 2) {
    throw new Error(
      "agent receipt: continuity: expected prior digest requires sequence_number > 1",
    );
  }
  if (receipt.continuity.prev_message_digest_sha256_hex !== expected) {
    throw new Error(
      "agent receipt: continuity: prev_message_digest_sha256_hex does not match expected prior digest",
    );
  }
}

/** Validates structure, receipt_id derivation, digest, and detached Ed25519 signature. */
export async function verifyAgentReceiptV1(
  receipt: AgentReceiptV1,
  options: VerifyAgentReceiptV1Options = {},
): Promise<AgentReceiptV1> {
  ensureEd25519Sha512Sync();
  const requiredTier = normalizeValidityTier(options.requiredValidityTier);
  const verifyOperatorAgainstRegistry =
    options.verifyOperatorAgainstRegistry === true ||
    requiredTier === AGENT_RECEIPT_VALIDITY_TIER_ATTESTED
      ? true
      : options.verifyOperatorAgainstRegistry;
  const normalized = normalizeReceipt(receipt);
  verifyContinuityExpectedPrior(normalized, options.expectedPriorMessageDigestHex);
  if (!allowsSigningPublicKeyHex(normalized.signing_public_key_ed25519_hex, options.expectedSigningPublicKeys)) {
    throw new Error(
      "agent receipt: signing_public_key_ed25519_hex is not in the configured trusted key set",
    );
  }
  const canonical = marshalCanonicalAgentReceipt(normalized);
  const digest = createHash("sha256").update(canonical).digest();
  const digestHex = sha256Hex(canonical);

  if (normalized.signing_algorithm !== AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519) {
    throw new Error(
      `agent receipt: signing_algorithm must be ${AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519}`,
    );
  }
  requireHex64(normalized.message_digest_sha256_hex, "message_digest_sha256_hex");
  if (normalized.message_digest_sha256_hex !== digestHex) {
    throw new Error("agent receipt: message digest mismatch");
  }

  const publicKey = hexToBytes(normalized.signing_public_key_ed25519_hex);
  const signature = hexToBytes(normalized.ed25519_signature_hex);
  if (publicKey.length !== 32 || signature.length !== 64) {
    throw new Error("agent receipt: invalid signing material");
  }
  const valid = await verify(signature, digest, publicKey);
  if (!valid) {
    throw new Error("agent receipt: ed25519 signature verification failed");
  }
  await verifyOperatorAttestation(normalized, digest, {
    ...options,
    verifyOperatorAgainstRegistry,
  });
  if (requiredTier === AGENT_RECEIPT_VALIDITY_TIER_PRIMARY) {
    requirePrimaryValidity(normalized);
  } else if (requiredTier === AGENT_RECEIPT_VALIDITY_TIER_ATTESTED) {
    requirePrimaryValidity(normalized);
    requireAttestedValidity(normalized, options.trustedOperatorPublicKeys);
  }
  return normalized;
}

/** Validate raw JSON (schema + forbidden fields) then verify signature. */
export async function verifyAgentReceiptV1FromJSON(
  raw: string | Uint8Array | Record<string, unknown>,
  options: VerifyAgentReceiptV1Options = {},
): Promise<AgentReceiptV1> {
  const receipt =
    typeof raw === "object" && !(raw instanceof Uint8Array) && !Array.isArray(raw)
      ? validateAgentReceiptJSON(raw)
      : parseAgentReceiptJSON(raw as string | Uint8Array);
  return verifyAgentReceiptV1(receipt, options);
}

async function verifyOperatorAttestation(
  receipt: AgentReceiptV1,
  gatewayDigest: Uint8Array,
  options: VerifyAgentReceiptV1Options = {},
): Promise<void> {
  const attestation = receipt.operator_attestation;
  if (!attestation) {
    return;
  }
  const operatorDid = attestation.operator_did?.trim();
  if (!operatorDid) {
    throw new Error("agent receipt: operator_attestation.operator_did is required");
  }
  if (operatorDid !== receipt.authorization.agent.operator_did.trim()) {
    throw new Error(
      "agent receipt: operator_attestation.operator_did must match authorization.agent.operator_did",
    );
  }
  requireHex64(attestation.message_digest_sha256_hex, "operator_attestation.message_digest_sha256_hex");
  if (attestation.message_digest_sha256_hex !== receipt.message_digest_sha256_hex) {
    throw new Error(
      "agent receipt: operator_attestation message_digest_sha256_hex must match gateway digest",
    );
  }
  const enforceRegistry =
    options.verifyOperatorAgainstRegistry === true ||
    (options.verifyOperatorAgainstRegistry !== false &&
      options.trustMode === "tenant_registry");
  if (
    enforceRegistry &&
    !allowsOperatorPublicKeyHex(
      attestation.signing_public_key_ed25519_hex,
      options.trustedOperatorPublicKeys,
    )
  ) {
    throw new Error(
      "agent receipt: operator_attestation signing key is not in the configured tenant operator registry",
    );
  }
  const publicKey = hexToBytes(attestation.signing_public_key_ed25519_hex);
  const signature = hexToBytes(attestation.ed25519_signature_hex);
  if (publicKey.length !== 32 || signature.length !== 64) {
    throw new Error("agent receipt: invalid operator attestation signing material");
  }
  const valid = await verify(signature, gatewayDigest, publicKey);
  if (!valid) {
    throw new Error("agent receipt: operator attestation ed25519 signature verification failed");
  }
}

/** Attach an optional operator counter-signature over the Gateway message digest. */
export async function attachOperatorAttestationV1(
  receipt: AgentReceiptV1,
  operatorPrivateKeyHex: string,
  operatorDid: string,
): Promise<AgentReceiptV1> {
  ensureEd25519Sha512Sync();
  const verified = await verifyAgentReceiptV1(receipt);
  const normalizedOperatorDid = operatorDid.trim();
  if (!normalizedOperatorDid) {
    throw new Error("agent receipt: operator_did is required");
  }
  if (normalizedOperatorDid !== verified.authorization.agent.operator_did.trim()) {
    throw new Error(
      "agent receipt: operator_did must match authorization.agent.operator_did",
    );
  }
  const digest = hexToBytes(verified.message_digest_sha256_hex);
  const privateKey = hexToBytes(operatorPrivateKeyHex);
  if (privateKey.length !== 64 && privateKey.length !== 32) {
    throw new Error("agent receipt: operator private key must be 32- or 64-byte ed25519 material");
  }
  const { sign } = await import("@noble/ed25519");
  const signature = await sign(digest, privateKey.slice(0, 32));
  const { getPublicKey } = await import("@noble/ed25519");
  const publicKey = await getPublicKey(privateKey.slice(0, 32));
  return {
    ...verified,
    operator_attestation: {
      operator_did: normalizedOperatorDid,
      signing_public_key_ed25519_hex: Buffer.from(publicKey).toString("hex"),
      message_digest_sha256_hex: verified.message_digest_sha256_hex,
      ed25519_signature_hex: Buffer.from(signature).toString("hex"),
    },
  };
}

function hexToBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0) {
    return new Uint8Array();
  }
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}
