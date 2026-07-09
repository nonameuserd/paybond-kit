/**
 * Maps partner attestation artifacts into Agent Receipt `external_attestations` entries.
 *
 * Partner digests are SHA-256 of canonical JSON (signature fields stripped for SEP-2828).
 * These entries are never canonical inside Paybond; they provide interop hooks only.
 */

import { createHash } from "node:crypto";

import { readString, verifySignedAgentMandateV1 } from "./agent-mandate.js";
import type { AgentReceiptExternalAttestationV1 } from "./agent-receipt.js";
import { normalizeJson } from "./json-digest.js";
import {
  verifyProtocolAuthorizationReceiptV1,
  verifyProtocolSettlementReceiptV1,
} from "./protocol-receipt.js";
import { stripDigestPrefix } from "./mcp-sep2828-evidence.js";
import { verifySep2828ReceiptPair } from "./sep2828-signature.js";
import {
  buildX402ReceiptDigestPayload,
  type X402ReceiptPayloadV1,
} from "./x402-receipt-evidence.js";
import { extractSignedX402Receipt, verifySignedX402Receipt } from "./x402-receipt-signature.js";

export const AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828 = "sep2828_mcp";
export const AGENT_RECEIPT_EXTERNAL_SOURCE_X402 = "x402";
export const AGENT_RECEIPT_EXTERNAL_SOURCE_AP2 = "ap2";

const SEP2828_SIGNATURE_KEYS = new Set([
  "signature",
  "ed25519_signature_hex",
  "message_digest_sha256_hex",
  "signing_public_key_ed25519_hex",
]);
const SEP2828_ASSERTED_BLOCKS = ["issuerAsserted", "receiptAsserted"] as const;

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(normalizeJson(value)));
}

/** SHA-256 hex digest of canonical JSON bytes. */
export function partnerRecordDigestSha256Hex(record: Record<string, unknown>): string {
  return createHash("sha256").update(Buffer.from(canonicalJsonBytes(record))).digest("hex");
}

function stripSep2828SignatureFields(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (SEP2828_SIGNATURE_KEYS.has(key)) {
      continue;
    }
    if ((SEP2828_ASSERTED_BLOCKS as readonly string[]).includes(key)) {
      const asserted = readObject(value);
      if (!asserted) {
        continue;
      }
      const stripped: Record<string, unknown> = {};
      for (const [innerKey, innerValue] of Object.entries(asserted)) {
        if (!SEP2828_SIGNATURE_KEYS.has(innerKey)) {
          stripped[innerKey] = innerValue;
        }
      }
      if (Object.keys(stripped).length > 0) {
        out[key] = stripped;
      }
      continue;
    }
    out[key] = value;
  }
  return out;
}

function sep2828RecordDigest(record: Record<string, unknown>): string {
  return partnerRecordDigestSha256Hex(stripSep2828SignatureFields(record));
}

function x402PayloadDigestSha256Hex(payload: X402ReceiptPayloadV1): string {
  return partnerRecordDigestSha256Hex(payload);
}

/**
 * Converts verified SEP-2828 decision/outcome records into external attestation entries.
 */
export function sep2828RecordsToExternalAttestations(
  decisionInput: Record<string, unknown>,
  outcomeInput: Record<string, unknown>,
): AgentReceiptExternalAttestationV1[] {
  verifySep2828ReceiptPair(decisionInput, outcomeInput);

  const decisionBackLink = readObject(decisionInput.backLink);
  const referenceID =
    typeof decisionBackLink?.attestationDigest === "string"
      ? stripDigestPrefix(decisionBackLink.attestationDigest)
      : undefined;

  return [
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
      kind: "decision_record",
      digest_sha256_hex: sep2828RecordDigest(decisionInput),
      reference_id: referenceID,
    },
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_SEP2828,
      kind: "outcome_record",
      digest_sha256_hex: sep2828RecordDigest(outcomeInput),
      reference_id: referenceID,
    },
  ];
}

/**
 * Converts a verified x402 signed delivery receipt into one external attestation entry.
 */
export function x402ReceiptToExternalAttestations(
  receiptInput: Record<string, unknown>,
): AgentReceiptExternalAttestationV1[] {
  const signed = extractSignedX402Receipt(receiptInput);
  const verifiedPayload = verifySignedX402Receipt(signed);
  const payload = buildX402ReceiptDigestPayload(verifiedPayload);
  return [
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
      kind: "delivery_receipt_v1",
      digest_sha256_hex: x402PayloadDigestSha256Hex(payload),
      reference_id: payload.resourceUrl,
    },
  ];
}

/**
 * Converts a verified signed AP2 agent mandate into one external attestation entry.
 */
export function signedMandateToExternalAttestations(
  signed: Record<string, unknown>,
  transportBinding?: { external_authorization_id?: string },
): AgentReceiptExternalAttestationV1[] {
  verifySignedAgentMandateV1(signed);

  const digest = readString(signed.message_digest_sha256_hex).trim().toLowerCase();
  const externalAuthorizationId = transportBinding?.external_authorization_id?.trim();
  const nonce = readString(signed.nonce).trim();
  const referenceID = externalAuthorizationId || nonce || undefined;

  return [
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
      kind: "agent_mandate_v1",
      digest_sha256_hex: digest,
      reference_id: referenceID,
    },
  ];
}

/**
 * Converts a verified AP2 protocol authorization receipt into one external attestation entry.
 */
export function protocolAuthorizationReceiptToExternalAttestations(
  receipt: Record<string, unknown>,
): AgentReceiptExternalAttestationV1[] {
  const verified = verifyProtocolAuthorizationReceiptV1(receipt);
  return [
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
      kind: "protocol_authorization_receipt_v1",
      digest_sha256_hex: verified.message_digest_sha256_hex,
      reference_id: verified.intent_id,
    },
  ];
}

/**
 * Converts a verified AP2 protocol settlement receipt into one external attestation entry.
 */
export function protocolSettlementReceiptToExternalAttestations(
  receipt: Record<string, unknown>,
): AgentReceiptExternalAttestationV1[] {
  const verified = verifyProtocolSettlementReceiptV1(receipt);
  return [
    {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
      kind: "protocol_settlement_receipt_v1",
      digest_sha256_hex: verified.message_digest_sha256_hex,
      reference_id: verified.intent_id,
    },
  ];
}

export type PaybondExternalAttestationInput =
  | { kind: "sep2828"; decision: Record<string, unknown>; outcome: Record<string, unknown> }
  | { kind: "x402"; receipt: Record<string, unknown> }
  | {
      kind: "ap2_mandate";
      signedMandate: Record<string, unknown>;
      transportBinding?: { external_authorization_id?: string };
    }
  | { kind: "ap2_authorization_receipt"; receipt: Record<string, unknown> }
  | { kind: "ap2_settlement_receipt"; receipt: Record<string, unknown> }
  | AgentReceiptExternalAttestationV1;

/** Resolves pre-built or partner-native attestation inputs into normalized receipt entries. */
export function resolveExternalAttestations(
  inputs: readonly PaybondExternalAttestationInput[],
): AgentReceiptExternalAttestationV1[] {
  const out: AgentReceiptExternalAttestationV1[] = [];
  for (const input of inputs) {
    if ("source" in input && "digest_sha256_hex" in input) {
      out.push(input);
      continue;
    }
    if (input.kind === "sep2828") {
      out.push(...sep2828RecordsToExternalAttestations(input.decision, input.outcome));
      continue;
    }
    if (input.kind === "x402") {
      out.push(...x402ReceiptToExternalAttestations(input.receipt));
      continue;
    }
    if (input.kind === "ap2_mandate") {
      out.push(
        ...signedMandateToExternalAttestations(input.signedMandate, input.transportBinding),
      );
      continue;
    }
    if (input.kind === "ap2_authorization_receipt") {
      out.push(...protocolAuthorizationReceiptToExternalAttestations(input.receipt));
      continue;
    }
    if (input.kind === "ap2_settlement_receipt") {
      out.push(...protocolSettlementReceiptToExternalAttestations(input.receipt));
    }
  }
  return out;
}
