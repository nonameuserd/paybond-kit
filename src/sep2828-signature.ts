/**
 * Verifies SEP-2828 MCP decision/outcome record signatures before evidence mapping.
 *
 * Uses Ed25519-over-SHA-256(JCS-style canonical JSON with signature fields stripped),
 * matching Paybond Kit audit-export verification and SEP-2787 detached signatures.
 */

import { createHash } from "node:crypto";

import { verify as ed25519Verify } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";
import { normalizeJson } from "./json-digest.js";

const SIGNATURE_KEYS = new Set([
  "signature",
  "ed25519_signature_hex",
  "message_digest_sha256_hex",
  "signing_public_key_ed25519_hex",
]);
const ASSERTED_BLOCKS = ["issuerAsserted", "receiptAsserted"] as const;

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function stripDigestPrefix(digest: string): string {
  return digest.replace(/^(sha256|blake3):/i, "");
}

function canonicalJsonBytes(value: unknown): Uint8Array {
  const normalized = normalizeJson(value);
  return new TextEncoder().encode(JSON.stringify(normalized));
}

function sha256Hex(data: Uint8Array): string {
  const digest = createHash("sha256").update(Buffer.from(data)).digest();
  return Buffer.from(digest).toString("hex");
}

function hexToBytes(hex: string): Uint8Array {
  const trimmed = hex.trim();
  if (trimmed.length % 2 !== 0) {
    throw new Error("invalid hex length");
  }
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function stripSignatureFields(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (SIGNATURE_KEYS.has(key)) {
      continue;
    }
    if ((ASSERTED_BLOCKS as readonly string[]).includes(key)) {
      const asserted = readObject(value);
      if (!asserted) {
        continue;
      }
      const stripped: Record<string, unknown> = {};
      for (const [innerKey, innerValue] of Object.entries(asserted)) {
        if (!SIGNATURE_KEYS.has(innerKey)) {
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

function extractSignatureMaterial(record: Record<string, unknown>): { signatureHex: string; publicKeyHex: string } {
  for (const blockName of ASSERTED_BLOCKS) {
    const block = readObject(record[blockName]);
    if (!block) {
      continue;
    }
    const signature = block.ed25519_signature_hex ?? block.signature;
    const publicKey = block.signing_public_key_ed25519_hex;
    if (typeof signature === "string" && signature.length > 0 && typeof publicKey === "string" && publicKey.length > 0) {
      return { signatureHex: signature.trim(), publicKeyHex: publicKey.trim() };
    }
  }

  const signature = record.ed25519_signature_hex ?? record.signature;
  const publicKey = record.signing_public_key_ed25519_hex;
  if (typeof signature === "string" && signature.length > 0 && typeof publicKey === "string" && publicKey.length > 0) {
    return { signatureHex: signature.trim(), publicKeyHex: publicKey.trim() };
  }

  throw new Error("SEP-2828 record missing ed25519 signature and signing_public_key_ed25519_hex");
}

/** Verifies a single SEP-2828 decision or outcome record signature. */
export function verifySep2828RecordSignature(record: Record<string, unknown>): void {
  ensureEd25519Sha512Sync();
  const { signatureHex, publicKeyHex } = extractSignatureMaterial(record);
  const digest = hexToBytes(sha256Hex(canonicalJsonBytes(stripSignatureFields(record))));
  const signature = hexToBytes(signatureHex);
  const publicKey = hexToBytes(publicKeyHex);
  if (!ed25519Verify(signature, digest, publicKey)) {
    throw new Error("SEP-2828 record signature verification failed");
  }
}

function recordContentDigestHex(record: Record<string, unknown>): string {
  return sha256Hex(canonicalJsonBytes(stripSignatureFields(record)));
}

/** Verifies signatures and backLink / decisionDigest pairing before mapping to evidence. */
export function verifySep2828ReceiptPair(
  decision: Record<string, unknown>,
  outcome: Record<string, unknown>,
): void {
  verifySep2828RecordSignature(decision);
  verifySep2828RecordSignature(outcome);

  const decisionBackLink = readObject(decision.backLink);
  const outcomeBackLink = readObject(outcome.backLink);
  if (!decisionBackLink || !outcomeBackLink) {
    throw new Error("SEP-2828 decision and outcome records must both include backLink");
  }

  const decisionDigest = decisionBackLink.attestationDigest;
  const outcomeDigest = outcomeBackLink.attestationDigest;
  if (typeof decisionDigest !== "string" || decisionDigest.length === 0) {
    throw new Error("SEP-2828 decision backLink.attestationDigest is required");
  }
  if (decisionDigest !== outcomeDigest) {
    throw new Error("SEP-2828 decision and outcome backLink.attestationDigest must match");
  }

  const outcomeDerived = readObject(outcome.outcomeDerived);
  if (!outcomeDerived) {
    throw new Error("SEP-2828 outcome record must include outcomeDerived");
  }

  const expectedDecisionDigest = stripDigestPrefix(recordContentDigestHex(decision));
  const decisionDigestField = outcomeDerived.decisionDigest;
  if (typeof decisionDigestField !== "string" || decisionDigestField.length === 0) {
    throw new Error("SEP-2828 outcomeDerived.decisionDigest is required for pairing");
  }
  if (stripDigestPrefix(decisionDigestField) !== expectedDecisionDigest) {
    throw new Error("SEP-2828 outcomeDerived.decisionDigest does not match signed decision record");
  }
}
