/**
 * Payment Evidence Frame (PEF) wrapper for agent-receipt audit handoff.
 *
 * Inspired by draft-hopley-x402-payment-evidence-frame: content-addressed
 * `frame_id` over JCS(preimage), with `claim_type=paybond_agent_receipt_v1`.
 * ARS core signing stays `ed25519-sha256-json-v1`; this adapter owns JCS.
 *
 * RFC 9421 detached signatures are reserved (`signature` extension point) and
 * not populated by the builder in this release.
 */

import { createHash } from "node:crypto";

import type { AgentReceiptV1 } from "./agent-receipt.js";

/** PEF claim taxonomy for Paybond agent receipts (interop adapter). */
export const PEF_CLAIM_TYPE_AGENT_RECEIPT_V1 = "paybond_agent_receipt_v1";

/** Canonicalisation URN pinned by the x402 PEF substrate. */
export const PEF_CANON_VERSION_JCS_RFC8785_V1 =
  "urn:x402:canonicalisation:jcs-rfc8785-v1";

export const PEF_VERSION_V1 = "1";

/** Inner receipt format label carried in the PEF envelope. */
export const PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1 = "paybond.agent_receipt_v1";

export type BuildAgentReceiptPefFrameInput = {
  /** Full ARS receipt JSON (verified or composed). */
  receipt: AgentReceiptV1 | Record<string, unknown>;
  /** DID of the party asserting the frame (audit exporter / Gateway). */
  frameProviderDid: string;
  /** Epoch milliseconds for the frame assertion. */
  frameTimestampMs: number;
};

/**
 * PEF envelope wrapping an ARS receipt for partner audit handoff.
 *
 * `signature` is omitted; callers MAY attach an RFC 9421 detached signature
 * later without changing `frame_id` (signature is excluded from the preimage).
 */
export type AgentReceiptPefFrameV1 = {
  canon_version: typeof PEF_CANON_VERSION_JCS_RFC8785_V1;
  claim_type: typeof PEF_CLAIM_TYPE_AGENT_RECEIPT_V1;
  frame_id: string;
  frame_provider_did: string;
  frame_timestamp_ms: number;
  pef_version: typeof PEF_VERSION_V1;
  receipt: AgentReceiptV1 | Record<string, unknown>;
  receipt_format: typeof PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1;
  receipt_hash: string;
};

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

/** Returns RFC 8785 JCS bytes for an arbitrary JSON value. */
export function jcsCanonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(canonicalizeJson(value)));
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function sha256Prefixed(hexDigest: string): string {
  return `sha256:${hexDigest}`;
}

/**
 * Computes `receipt_hash = sha256:` + hex(SHA-256(JCS(receipt))).
 */
export function agentReceiptPefReceiptHash(
  receipt: AgentReceiptV1 | Record<string, unknown>,
): string {
  return sha256Prefixed(sha256Hex(jcsCanonicalBytes(receipt)));
}

/**
 * Builds the PEF preimage object (excludes `frame_id` and `signature`).
 */
export function agentReceiptPefPreimage(
  input: BuildAgentReceiptPefFrameInput,
  receiptHash: string,
): Record<string, unknown> {
  const provider = input.frameProviderDid.trim();
  if (!provider) {
    throw new Error("pef: frame_provider_did is required");
  }
  if (!Number.isInteger(input.frameTimestampMs) || input.frameTimestampMs < 0) {
    throw new Error("pef: frame_timestamp_ms must be a non-negative integer");
  }
  return {
    canon_version: PEF_CANON_VERSION_JCS_RFC8785_V1,
    claim_type: PEF_CLAIM_TYPE_AGENT_RECEIPT_V1,
    frame_provider_did: provider,
    frame_timestamp_ms: input.frameTimestampMs,
    pef_version: PEF_VERSION_V1,
    receipt: input.receipt,
    receipt_format: PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1,
    receipt_hash: receiptHash,
  };
}

/**
 * Derives `frame_id = sha256:` + hex(SHA-256(JCS(preimage))).
 */
export function agentReceiptPefFrameId(preimage: Record<string, unknown>): string {
  return sha256Prefixed(sha256Hex(jcsCanonicalBytes(preimage)));
}

/**
 * Builds a content-addressed PEF wrapper around an ARS receipt.
 *
 * Does not modify or re-sign the inner ARS envelope.
 */
export function buildAgentReceiptPefFrame(
  input: BuildAgentReceiptPefFrameInput,
): AgentReceiptPefFrameV1 {
  const receiptHash = agentReceiptPefReceiptHash(input.receipt);
  const preimage = agentReceiptPefPreimage(input, receiptHash);
  const frameId = agentReceiptPefFrameId(preimage);
  return {
    canon_version: PEF_CANON_VERSION_JCS_RFC8785_V1,
    claim_type: PEF_CLAIM_TYPE_AGENT_RECEIPT_V1,
    frame_id: frameId,
    frame_provider_did: String(preimage.frame_provider_did),
    frame_timestamp_ms: input.frameTimestampMs,
    pef_version: PEF_VERSION_V1,
    receipt: input.receipt,
    receipt_format: PEF_RECEIPT_FORMAT_AGENT_RECEIPT_V1,
    receipt_hash: receiptHash,
  };
}

/**
 * Recomputes `frame_id` / `receipt_hash` and checks they match the frame.
 *
 * @throws Error when hashes do not match
 */
export function verifyAgentReceiptPefFrameId(frame: AgentReceiptPefFrameV1): void {
  const expectedReceiptHash = agentReceiptPefReceiptHash(frame.receipt);
  if (frame.receipt_hash !== expectedReceiptHash) {
    throw new Error("pef: receipt_hash mismatch");
  }
  const preimage = agentReceiptPefPreimage(
    {
      receipt: frame.receipt,
      frameProviderDid: frame.frame_provider_did,
      frameTimestampMs: frame.frame_timestamp_ms,
    },
    expectedReceiptHash,
  );
  const expectedFrameId = agentReceiptPefFrameId(preimage);
  if (frame.frame_id !== expectedFrameId) {
    throw new Error("pef: frame_id mismatch");
  }
  if (frame.claim_type !== PEF_CLAIM_TYPE_AGENT_RECEIPT_V1) {
    throw new Error("pef: unexpected claim_type");
  }
}
