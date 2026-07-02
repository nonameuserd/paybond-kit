/**
 * Maps x402 Signed Offer & Receipt extension payloads into artifact_attested evidence.
 *
 * Digests JCS-canonical receipt bytes (resourceUrl, payer, network, issuedAt, optional transaction)
 * into artifact_blake3_hex. Does not import Coinbase authorization_succeeded funding webhooks.
 */

import { jsonValueDigest } from "./json-digest.js";
import { extractSignedX402Receipt, verifySignedX402Receipt } from "./x402-receipt-signature.js";

export const X402_RECEIPT_MAPPER_VERSION = "x402_receipt_v1";

export type X402ReceiptPayloadV1 = {
  resourceUrl: string;
  payer: string;
  network: string;
  issuedAt: number;
  transaction?: string;
};

export type ArtifactAttestedEvidence = {
  artifact_blake3_hex: string[];
  operation: string;
  vendor_ref_id: string;
};

const FUNDING_EVIDENCE_FIELDS = [
  "payment_session_id",
  "authorization_id",
  "capture_id",
  "void_id",
  "x402_payment_session_id",
  "onchain_transaction_hashes",
] as const;

function readString(record: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function readNumber(record: Record<string, unknown>, ...keys: string[]): number | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      return value;
    }
  }
  return undefined;
}

function digestToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Rejects Coinbase funding webhook shapes — those are not tool-completion evidence. */
export function assertNotX402FundingArtifact(input: Record<string, unknown>): void {
  const eventType = readString(input, "event_type", "eventType", "type");
  if (eventType === "authorization_succeeded") {
    throw new Error(
      "authorization_succeeded webhooks are funding signals, not x402 delivery receipt evidence",
    );
  }
  for (const field of FUNDING_EVIDENCE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(input, field)) {
      throw new Error(`funding field ${field} must not be submitted as tool-completion evidence`);
    }
  }
}

function hasReceiptShape(record: Record<string, unknown>): boolean {
  return (
    readString(record, "resourceUrl", "resource_url") !== undefined &&
    readString(record, "payer") !== undefined &&
    readString(record, "network") !== undefined &&
    readNumber(record, "issuedAt", "issued_at") !== undefined
  );
}

function unwrapReceiptRecord(input: Record<string, unknown>): Record<string, unknown> {
  assertNotX402FundingArtifact(input);

  const signed = extractSignedX402Receipt(input);
  const verifiedPayload = verifySignedX402Receipt(signed);
  if (hasReceiptShape(verifiedPayload)) {
    return verifiedPayload;
  }

  throw new Error(
    "x402 receipt payload missing required fields (resourceUrl, payer, network, issuedAt)",
  );
}

/** Normalizes wire fields into the v1 digest payload (camelCase, optional transaction only when set). */
export function buildX402ReceiptDigestPayload(raw: Record<string, unknown>): X402ReceiptPayloadV1 {
  const resourceUrl = readString(raw, "resourceUrl", "resource_url");
  const payer = readString(raw, "payer");
  const network = readString(raw, "network");
  const issuedAt = readNumber(raw, "issuedAt", "issued_at");
  const transaction = readString(raw, "transaction", "txHash", "tx_hash");

  if (!resourceUrl || !payer || !network || issuedAt === undefined) {
    throw new Error(
      "x402 receipt payload missing required fields (resourceUrl, payer, network, issuedAt)",
    );
  }

  const payload: X402ReceiptPayloadV1 = { resourceUrl, payer, network, issuedAt };
  if (transaction) {
    payload.transaction = transaction;
  }
  return payload;
}

/** BLAKE3 hex digest of JCS-canonical x402 receipt payload bytes. */
export function x402ReceiptPayloadDigestHex(payload: X402ReceiptPayloadV1): string {
  return digestToHex(jsonValueDigest(payload));
}

/**
 * Converts an x402 signed receipt artifact or payload into artifact_attested evidence fields.
 */
export function mapX402ReceiptToArtifactAttestedEvidence(
  receiptInput: Record<string, unknown>,
): ArtifactAttestedEvidence {
  const raw = unwrapReceiptRecord(receiptInput);
  const payload = buildX402ReceiptDigestPayload(raw);
  return {
    artifact_blake3_hex: [x402ReceiptPayloadDigestHex(payload)],
    operation: "attested",
    vendor_ref_id: payload.resourceUrl,
  };
}
