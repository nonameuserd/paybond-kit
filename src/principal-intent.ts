/**
 * Principal intent creation signing for raw `predicate_dsl` (no managed-policy binding).
 * Matches `crates/harbor-intent-escrow/src/signing.rs` (`intent_creation_sign_bytes_raw`).
 */

import { sign, getPublicKey } from "@noble/ed25519";
import { parse as parseUuid } from "uuid";
import { jsonValueDigest } from "./json-digest.js";

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function encodeU64(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) {
    throw new Error("encodeU64: expected non-negative integer");
  }
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function encodeI64(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigInt64(0, BigInt(n), true);
  return b;
}

function encodeBincodeString(s: string): Uint8Array {
  const utf8 = new TextEncoder().encode(s);
  return concatBytes(encodeU64(utf8.length), utf8);
}

function dslDigest(predicate: Record<string, unknown>): Uint8Array {
  return jsonValueDigest(predicate);
}

function allowedToolsDigest(tools: string[]): Uint8Array {
  const sorted = [...tools]
    .map((s) => s.trim().toLowerCase())
    .sort()
    .filter((v, i, a) => a.indexOf(v) === i);
  return jsonValueDigest(sorted);
}

/** Bincode payload for principal intent creation (wire format revision byte `2`). */
function encodeIntentCreationSign(input: {
  tenantId: string;
  intentId: string;
  principalDid: string;
  payeeDid: string;
  amountCents: number;
  currency: string;
  deadlineRfc3339: string;
  budgetDigest: Uint8Array;
  evidenceSchemaDigest: Uint8Array;
  predicateDslDigest: Uint8Array;
  predicateRef: string;
  allowedToolsDigest: Uint8Array;
}): Uint8Array {
  const version = new Uint8Array([2]);
  const intentBytes = parseUuid(input.intentId);
  if (intentBytes.length !== 16) {
    throw new Error("intentId must be a UUID string");
  }
  // Serde `Uuid` + bincode uses a u64 length prefix (16) before the raw 16 bytes (matches Rust).
  return concatBytes(
    version,
    encodeBincodeString(input.tenantId),
    encodeU64(16),
    intentBytes,
    encodeBincodeString(input.principalDid),
    encodeBincodeString(input.payeeDid),
    encodeI64(input.amountCents),
    encodeBincodeString(input.currency),
    encodeBincodeString(input.deadlineRfc3339),
    input.budgetDigest,
    input.evidenceSchemaDigest,
    input.predicateDslDigest,
    encodeBincodeString(input.predicateRef),
    input.allowedToolsDigest,
  );
}

export function intentCreationSignBytesRaw(input: {
  tenantId: string;
  intentId: string;
  principalDid: string;
  payeeDid: string;
  amountCents: number;
  currency: string;
  deadlineRfc3339: string;
  budget: Record<string, unknown>;
  evidenceSchema: Record<string, unknown>;
  predicate: Record<string, unknown>;
  predicateRef: string;
  allowedTools: string[];
}): Uint8Array {
  const budgetDigest = jsonValueDigest(input.budget);
  const evidenceSchemaDigest = jsonValueDigest(input.evidenceSchema);
  const predicateDslDigest = dslDigest(input.predicate);
  const allowedDigest = allowedToolsDigest(input.allowedTools);
  return encodeIntentCreationSign({
    tenantId: input.tenantId,
    intentId: input.intentId,
    principalDid: input.principalDid,
    payeeDid: input.payeeDid,
    amountCents: input.amountCents,
    currency: input.currency,
    deadlineRfc3339: input.deadlineRfc3339,
    budgetDigest,
    evidenceSchemaDigest,
    predicateDslDigest,
    predicateRef: input.predicateRef,
    allowedToolsDigest: allowedDigest,
  });
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export type BuildSignedCreateIntentParams = {
  tenantId: string;
  intentId: string;
  principalDid: string;
  principalSigningSeed: Uint8Array;
  payeeDid: string;
  budget: Record<string, unknown>;
  predicate: Record<string, unknown>;
  currency: string;
  amountCents: number;
  evidenceSchema: Record<string, unknown>;
  deadlineRfc3339: string;
  allowedTools: string[];
  predicateRef?: string;
};

/**
 * Build a Harbor `POST /intents` JSON body with principal Ed25519 detached signature.
 */
export function buildSignedCreateIntentBody(params: BuildSignedCreateIntentParams): Record<string, unknown> {
  if (params.principalSigningSeed.length !== 32) {
    throw new Error("principalSigningSeed must be 32 bytes");
  }
  if (params.allowedTools.length === 0) {
    throw new Error("allowedTools must be non-empty");
  }
  const predicateRef = params.predicateRef ?? "";
  const msg = intentCreationSignBytesRaw({
    tenantId: params.tenantId,
    intentId: params.intentId,
    principalDid: params.principalDid,
    payeeDid: params.payeeDid,
    amountCents: params.amountCents,
    currency: params.currency,
    deadlineRfc3339: params.deadlineRfc3339,
    budget: params.budget,
    evidenceSchema: params.evidenceSchema,
    predicate: params.predicate,
    predicateRef,
    allowedTools: params.allowedTools,
  });
  const sig = sign(msg, params.principalSigningSeed);
  const pub = getPublicKey(params.principalSigningSeed);
  const body: Record<string, unknown> = {
    intent_id: params.intentId,
    principal_did: params.principalDid,
    principal_pubkey: bytesToBase64(pub),
    principal_signature: bytesToBase64(sig),
    payee_did: params.payeeDid,
    budget: params.budget,
    currency: params.currency,
    amount_cents: params.amountCents,
    evidence_schema: params.evidenceSchema,
    deadline: params.deadlineRfc3339,
    predicate_dsl: params.predicate,
    signing_version: 2,
    policy_binding: null,
    allowed_tools: params.allowedTools,
  };
  if (predicateRef.trim() !== "") {
    body.predicate_ref = predicateRef;
  }
  return body;
}
