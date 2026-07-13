/**
 * ACTA decision-receipt projection for `paybond.agent_receipt_v1`.
 *
 * Maps ARS fields into the ACTA Signed Decision Receipt shape
 * (`draft-farley-acta-signed-receipts`) for MCP / governance handoff.
 * This is an export projection only — ARS remains the canonical wire format
 * and authenticity is verified via native ARS verify, not ACTA JCS re-sign.
 */

import type { AgentReceiptV1 } from "./agent-receipt.js";

/** ACTA payload `type` for Paybond agent-receipt projections. */
export const ACTA_AGENT_RECEIPT_TYPE = "paybond:agent_receipt";

/** ACTA signature algorithm label used in the projected envelope. */
export const ACTA_SIGNATURE_ALG_EDDSA = "EdDSA";

export type ActaDecision = "allow" | "deny";

export type ActaDecisionReceiptPayloadV1 = {
  type: typeof ACTA_AGENT_RECEIPT_TYPE;
  issued_at: string;
  issuer_id: string;
  tool_name?: string;
  decision: ActaDecision;
  reason?: string;
  policy_digest?: string;
  session_id?: string;
  action_ref?: string;
  payload_digest?: string;
  /** Correlation: native ARS receipt_id. */
  ars_receipt_id: string;
  /** Correlation: ARS scope (`action` | `intent_terminal`). */
  ars_scope: string;
  /** Correlation: ARS kind constant. */
  ars_kind: "paybond.agent_receipt_v1";
};

export type ActaDecisionReceiptSignatureV1 = {
  alg: typeof ACTA_SIGNATURE_ALG_EDDSA;
  kid: string;
  sig: string;
};

/**
 * ACTA-shaped decision receipt projected from a verified/composed ARS envelope.
 *
 * `signature` copies ARS Ed25519 material for correlation. Consumers MUST verify
 * the original ARS envelope (or `payload_digest`) with native ARS verify —
 * ACTA JCS signing over this projected payload is not performed.
 */
export type ActaDecisionReceiptV1 = {
  payload: ActaDecisionReceiptPayloadV1;
  signature: ActaDecisionReceiptSignatureV1;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function sha256Prefixed(hexDigest: string): string {
  const normalized = hexDigest.trim().toLowerCase();
  if (normalized.startsWith("sha256:")) {
    return normalized;
  }
  return `sha256:${normalized}`;
}

/**
 * Maps ARS execution / outcome fields to an ACTA allow/deny decision.
 */
export function projectActaDecisionFromAgentReceipt(
  receipt: AgentReceiptV1 | Record<string, unknown>,
): ActaDecision {
  const doc = receipt as Record<string, unknown>;
  const scope = optionalString(doc.scope)?.toLowerCase();
  const outcome = asRecord(doc.outcome);
  const execution = asRecord(doc.execution);
  const evidence = asRecord(doc.evidence);

  if (scope === "intent_terminal") {
    const settlement = optionalString(outcome?.settlement_outcome)?.toUpperCase();
    if (settlement === "FAILED" || settlement === "REVERSED") {
      return "deny";
    }
    if (settlement === "SETTLED" || settlement === "PENDING_FINALITY") {
      return "allow";
    }
    const harbor = optionalString(outcome?.harbor_state)?.toLowerCase();
    if (harbor === "failed" || harbor === "failure" || harbor === "refunded") {
      return "deny";
    }
    return "allow";
  }

  const execOutcome = optionalString(execution?.outcome)?.toLowerCase();
  if (execOutcome && execOutcome !== "executed") {
    return "deny";
  }
  if (evidence?.predicate_passed === false || outcome?.predicate_passed === false) {
    return "deny";
  }
  return "allow";
}

/**
 * Projects a composed/verified ARS receipt into an ACTA decision-receipt shape.
 *
 * @throws Error when required ARS correlation fields are missing
 */
export function projectAgentReceiptToActaDecisionReceipt(
  receipt: AgentReceiptV1 | Record<string, unknown>,
): ActaDecisionReceiptV1 {
  const doc = receipt as Record<string, unknown>;
  const receiptId = optionalString(doc.receipt_id);
  const issuedAt = optionalString(doc.issued_at);
  const scope = optionalString(doc.scope);
  const pubKey = optionalString(doc.signing_public_key_ed25519_hex)?.toLowerCase();
  const sig = optionalString(doc.ed25519_signature_hex)?.toLowerCase();
  const messageDigest = optionalString(doc.message_digest_sha256_hex)?.toLowerCase();

  if (!receiptId) {
    throw new Error("acta projection: receipt_id is required");
  }
  if (!issuedAt) {
    throw new Error("acta projection: issued_at is required");
  }
  if (!scope) {
    throw new Error("acta projection: scope is required");
  }
  if (!pubKey) {
    throw new Error("acta projection: signing_public_key_ed25519_hex is required");
  }
  if (!sig) {
    throw new Error("acta projection: ed25519_signature_hex is required");
  }

  const authorization = asRecord(doc.authorization);
  const policy = asRecord(authorization?.policy);
  const execution = asRecord(doc.execution);
  const outcome = asRecord(doc.outcome);
  const continuity = asRecord(doc.continuity);

  const policyDigestHex = optionalString(policy?.content_digest_sha256_hex);
  const toolName = optionalString(execution?.tool_name);
  const sessionId =
    optionalString(execution?.run_id) ?? optionalString(continuity?.run_id);
  const actionRef =
    optionalString(execution?.arguments_digest_sha256_hex) ?? messageDigest;
  const reason =
    optionalString(outcome?.harbor_state) ??
    optionalString(outcome?.spend_reservation_outcome) ??
    optionalString(outcome?.settlement_outcome);

  const payload: ActaDecisionReceiptPayloadV1 = {
    type: ACTA_AGENT_RECEIPT_TYPE,
    issued_at: issuedAt,
    issuer_id: pubKey,
    decision: projectActaDecisionFromAgentReceipt(doc),
    ars_receipt_id: receiptId,
    ars_scope: scope,
    ars_kind: "paybond.agent_receipt_v1",
  };
  if (toolName) {
    payload.tool_name = toolName;
  }
  if (reason) {
    payload.reason = reason;
  }
  if (policyDigestHex) {
    payload.policy_digest = sha256Prefixed(policyDigestHex);
  }
  if (sessionId) {
    payload.session_id = sessionId;
  }
  if (actionRef) {
    payload.action_ref = actionRef.toLowerCase();
  }
  if (messageDigest) {
    payload.payload_digest = sha256Prefixed(messageDigest);
  }

  return {
    payload,
    signature: {
      alg: ACTA_SIGNATURE_ALG_EDDSA,
      kid: pubKey,
      sig,
    },
  };
}
