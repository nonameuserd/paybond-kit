import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT,
  newAgentRecognitionRequestEnvelope,
  signAgentRecognitionProofV1,
  signHarborEvidenceSubmitRecognitionProof,
} from "../src/agent-recognition.js";

function seedFromLabel(label: string): Uint8Array {
  return new Uint8Array(createHash("sha256").update(label).digest());
}

describe("signAgentRecognitionProofV1", () => {
  it("canonicalizes fields and produces a verifiable digest/signature envelope", () => {
    const signingSeed = seedFromLabel("agent-recognition-proof-roundtrip");
    const body = new TextEncoder().encode('{"rollback":true}');
    const issuedAt = new Date("2026-05-17T16:00:00.000Z");
    const expiresAt = new Date("2026-05-17T16:05:00.000Z");

    const proof = signAgentRecognitionProofV1(signingSeed, {
      keyId: " kid-1 ",
      purpose: " harbor.policy.rollback ",
      tenantId: " acme-pilot ",
      method: " post ",
      path: " /harbor/policy/v1/rollback ",
      body,
      issuedAt,
      expiresAt,
      nonce: " nonce-123 ",
    });

    expect(proof.kind).toBe("paybond.agent_recognition_proof_v1");
    expect(proof.key_id).toBe("kid-1");
    expect(proof.purpose).toBe("harbor.policy.rollback");
    expect(proof.verifier_context).toEqual({
      tenant_id: "acme-pilot",
      verifier_id: "paybond-gateway",
    });
    expect(proof.request_envelope).toEqual({
      method: "POST",
      path: "/harbor/policy/v1/rollback",
      body_digest_sha256_hex: newAgentRecognitionRequestEnvelope(
        "POST",
        "/harbor/policy/v1/rollback",
        body,
      ).bodyDigestSha256Hex,
    });
    expect(proof.message_digest_sha256_hex).toMatch(/^[0-9a-f]{64}$/);
    expect(proof.signing_public_key_ed25519_hex).toMatch(/^[0-9a-f]{64}$/);
    expect(proof.ed25519_signature_hex).toMatch(/^[0-9a-f]{128}$/);
  });

  it("binds harbor evidence submit proofs to the signed evidence body", () => {
    const signingSeed = seedFromLabel("httpserver-agent-recognition");
    const evidenceBody = {
      payload: { status: "completed", cost_cents: 100 },
      payee_did: "did:web:vendor.example",
      submitted_at: "2026-06-30T12:00:00Z",
    };

    const proof = signHarborEvidenceSubmitRecognitionProof({
      tenantId: "tenant-a",
      intentId: "550e8400-e29b-41d4-a716-446655440000",
      evidenceBody,
      keyId: "kid-1",
      signingSeed,
    });

    expect(proof.purpose).toBe(AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT);
    expect(proof.request_envelope.path).toBe(
      "/harbor/intents/550e8400-e29b-41d4-a716-446655440000/evidence",
    );
    expect(proof.request_envelope.body_digest_sha256_hex).toBe(
      createHash("sha256").update(JSON.stringify(evidenceBody)).digest("hex"),
    );
  });
});
