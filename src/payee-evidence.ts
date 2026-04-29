/**
 * Payee evidence signing bytes (matches `paybond-evidence` `EvidenceSignV1` + `encode_evidence_sign_v1`).
 */

import { sign, getPublicKey } from "@noble/ed25519";
import { createHash } from "blake3";
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
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function encodeBincodeString(s: string): Uint8Array {
  const utf8 = new TextEncoder().encode(s);
  return concatBytes(encodeU64(utf8.length), utf8);
}

/** BLAKE3 digest of concatenated artifact hashes (empty list matches Harbor / `paybond-evidence`). */
export function artifactsDigest(artifactHashes32: Uint8Array[]): Uint8Array {
  const h = createHash();
  for (const a of artifactHashes32) {
    h.update(a);
  }
  const buf = h.digest({ length: 32 });
  return new Uint8Array(buf);
}

function encodeEvidenceSignV1(input: {
  tenantId: string;
  intentId: string;
  payeeDid: string;
  payloadDigest: Uint8Array;
  artifactsDigest: Uint8Array;
  submittedAtRfc3339: string;
}): Uint8Array {
  const version = new Uint8Array([1]);
  const intentBytes = parseUuid(input.intentId);
  if (intentBytes.length !== 16) {
    throw new Error("intentId must be a UUID string");
  }
  if (input.payloadDigest.length !== 32 || input.artifactsDigest.length !== 32) {
    throw new Error("digest must be 32 bytes");
  }
  return concatBytes(
    version,
    encodeBincodeString(input.tenantId),
    encodeU64(16),
    intentBytes,
    encodeBincodeString(input.payeeDid),
    input.payloadDigest,
    input.artifactsDigest,
    encodeBincodeString(input.submittedAtRfc3339),
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function hexToBytes(hex: string): Uint8Array {
  const s = hex.trim();
  if (s.length % 2 !== 0) throw new Error("bad hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export type SignPayeeEvidenceParams = {
  tenantId: string;
  intentId: string;
  payeeDid: string;
  payload: Record<string, unknown>;
  artifactsBlake3Hex: string[];
  submittedAtRfc3339: string;
  payeeSigningSeed: Uint8Array;
};

/** Build Harbor `POST /intents/{id}/evidence` JSON with detached Ed25519 payee signature. */
export function signPayeeEvidenceBinding(params: SignPayeeEvidenceParams): Record<string, unknown> {
  if (params.payeeSigningSeed.length !== 32) {
    throw new Error("payeeSigningSeed must be 32 bytes");
  }
  const artifactBin: Uint8Array[] = params.artifactsBlake3Hex.map((h) => hexToBytes(h));
  const payloadDigest = jsonValueDigest(params.payload);
  const artDigest = artifactsDigest(artifactBin);
  const msg = encodeEvidenceSignV1({
    tenantId: params.tenantId,
    intentId: params.intentId,
    payeeDid: params.payeeDid,
    payloadDigest,
    artifactsDigest: artDigest,
    submittedAtRfc3339: params.submittedAtRfc3339,
  });
  const sig = sign(msg, params.payeeSigningSeed);
  const pub = getPublicKey(params.payeeSigningSeed);
  return {
    payload: params.payload,
    artifacts: params.artifactsBlake3Hex,
    payee_did: params.payeeDid,
    payee_pubkey: bytesToBase64(pub),
    payee_signature: bytesToBase64(sig),
    submitted_at: params.submittedAtRfc3339,
  };
}
