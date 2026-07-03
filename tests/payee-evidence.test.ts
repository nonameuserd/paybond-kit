import { verify } from "@noble/ed25519";
import { describe, expect, it } from "vitest";

import { EVIDENCE_SIGN_VERSION } from "../src/bincode-wire.js";
import { ensureEd25519Sha512Sync } from "../src/ed25519-sync.js";
import { jsonValueDigest } from "../src/json-digest.js";
import {
  artifactsDigest,
  evidenceSignBytesV1,
  signPayeeEvidenceBinding,
} from "../src/payee-evidence.js";
import {
  bytesToHex,
  loadEvidenceSignV1Golden,
} from "./helpers/wire-goldens.js";

function hexToBytes32(hex: string): Uint8Array {
  const s = hex.trim().replace(/^0x/i, "");
  if (s.length !== 64) {
    throw new Error(`expected 32-byte hex, got length ${s.length}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe("evidenceSignBytesV1 wire golden", () => {
  it("matches kit/wire-goldens/evidence_sign_v1.json (Rust paybond-evidence parity)", () => {
    const golden = loadEvidenceSignV1Golden();

    expect(EVIDENCE_SIGN_VERSION).toBe(golden.expected.evidence_sign_version);

    const payloadDigest = jsonValueDigest(golden.input.payload);
    expect(bytesToHex(payloadDigest)).toBe(golden.expected.payload_digest_hex);

    const artifactBins = golden.input.artifacts_blake3_hex.map(hexToBytes32);
    const artifactsDig = artifactsDigest(artifactBins);
    expect(bytesToHex(artifactsDig)).toBe(golden.expected.artifacts_digest_hex);

    const signBytes = evidenceSignBytesV1({
      tenantId: golden.input.tenant_id,
      intentId: golden.input.intent_id,
      payeeDid: golden.input.payee_did,
      payload: golden.input.payload,
      artifactsBlake3Hex: golden.input.artifacts_blake3_hex,
      submittedAtRfc3339: golden.input.submitted_at_rfc3339,
    });
    expect(bytesToHex(signBytes)).toBe(golden.expected.sign_bytes_hex);
  });
});

describe("signPayeeEvidenceBinding happy path", () => {
  it("sets artifacts to [] and signs EvidenceSignV1 bytes matching the wire golden", () => {
    ensureEd25519Sha512Sync();
    const golden = loadEvidenceSignV1Golden();
    const payeeSigningSeed = new Uint8Array(32).fill(9);

    const wire = signPayeeEvidenceBinding({
      tenantId: golden.input.tenant_id,
      intentId: golden.input.intent_id,
      payeeDid: golden.input.payee_did,
      payload: golden.input.payload,
      artifactsBlake3Hex: golden.input.artifacts_blake3_hex,
      submittedAtRfc3339: golden.input.submitted_at_rfc3339,
      payeeSigningSeed,
    });

    expect(wire.artifacts).toEqual([]);
    expect(wire.payload).toEqual(golden.input.payload);
    expect(wire.payee_did).toBe(golden.input.payee_did);
    expect(wire.submitted_at).toBe(golden.input.submitted_at_rfc3339);

    const signBytes = evidenceSignBytesV1({
      tenantId: golden.input.tenant_id,
      intentId: golden.input.intent_id,
      payeeDid: golden.input.payee_did,
      payload: golden.input.payload,
      artifactsBlake3Hex: golden.input.artifacts_blake3_hex,
      submittedAtRfc3339: golden.input.submitted_at_rfc3339,
    });
    expect(bytesToHex(signBytes)).toBe(golden.expected.sign_bytes_hex);

    const signature = Uint8Array.from(atob(String(wire.payee_signature)), (c) => c.charCodeAt(0));
    const publicKey = Uint8Array.from(atob(String(wire.payee_pubkey)), (c) => c.charCodeAt(0));
    expect(verify(signature, signBytes, publicKey)).toBe(true);
  });
});
