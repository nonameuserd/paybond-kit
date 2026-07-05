import { createHash, randomUUID } from "node:crypto";

import { sign, getPublicKey } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";

export type SignedAgentRecognitionProofV1 = {
  schema_version: number;
  kind: string;
  key_id: string;
  signature_algorithm: string;
  issued_at: string;
  expires_at: string;
  nonce: string;
  purpose: string;
  verifier_context: {
    tenant_id: string;
    verifier_id: string;
  };
  request_envelope: {
    method: string;
    path: string;
    body_digest_sha256_hex: string;
  };
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

export const AGENT_RECOGNITION_PROOF_SCHEMA_VERSION = 1;
export const AGENT_RECOGNITION_PROOF_KIND_V1 = "paybond.agent_recognition_proof_v1";
export const AGENT_RECOGNITION_SIGNATURE_ALGORITHM_ED25519 = "ed25519-sha256-json-v1";
export const AGENT_RECOGNITION_GATEWAY_VERIFIER_ID = "paybond-gateway";
export const AGENT_RECOGNITION_PURPOSE_CREATE = "harbor.intent.create";
export const AGENT_RECOGNITION_PURPOSE_FUND = "harbor.intent.fund";
export const AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT = "harbor.intent.evidence.submit";
export const AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM = "harbor.intent.settlement.confirm";
export const AGENT_RECOGNITION_MAX_FRESHNESS_MS = 10 * 60 * 1000;

const SCOPE_TOKEN_RE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

export type SignAgentRecognitionProofV1Params = {
  keyId: string;
  purpose: string;
  tenantId: string;
  verifierId?: string;
  method: string;
  path: string;
  body: Uint8Array | Record<string, unknown>;
  issuedAt?: Date;
  expiresAt?: Date;
  nonce?: string;
};

type CanonicalRecognitionProof = {
  schemaVersion: number;
  kind: string;
  keyId: string;
  signatureAlgorithm: string;
  issuedAt: string;
  expiresAt: string;
  nonce: string;
  purpose: string;
  verifierContext: {
    tenantId: string;
    verifierId: string;
  };
  requestEnvelope: {
    method: string;
    path: string;
    bodyDigestSha256Hex: string;
  };
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

function formatRfc3339Seconds(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function normalizeScopeToken(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!normalized) {
    throw new Error(`agent recognition proof: ${field} is required`);
  }
  if (!SCOPE_TOKEN_RE.test(normalized)) {
    throw new Error(`agent recognition proof: ${field} ${JSON.stringify(normalized)} is not canonical`);
  }
  return normalized;
}

function requestBodyBytes(body: Uint8Array | Record<string, unknown>): Uint8Array {
  if (body instanceof Uint8Array) {
    return body;
  }
  return new TextEncoder().encode(JSON.stringify(body));
}

/** Canonicalize request metadata that recognition proofs bind to. */
export function newAgentRecognitionRequestEnvelope(
  method: string,
  path: string,
  body: Uint8Array | Record<string, unknown>,
): CanonicalRecognitionProof["requestEnvelope"] {
  const normalizedMethod = method.trim().toUpperCase();
  const normalizedPath = path.trim() || "/";
  if (!normalizedMethod) {
    throw new Error("agent recognition proof: request_envelope.method is required");
  }
  if (!normalizedPath.startsWith("/")) {
    throw new Error('agent recognition proof: request_envelope.path must begin with "/"');
  }
  return {
    method: normalizedMethod,
    path: normalizedPath,
    bodyDigestSha256Hex: sha256Hex(requestBodyBytes(body)),
  };
}

function marshalCanonicalAgentRecognitionProof(proof: CanonicalRecognitionProof): Uint8Array {
  const payload = {
    schema_version: proof.schemaVersion,
    kind: proof.kind,
    key_id: proof.keyId,
    signature_algorithm: proof.signatureAlgorithm,
    issued_at: proof.issuedAt,
    expires_at: proof.expiresAt,
    nonce: proof.nonce,
    purpose: proof.purpose,
    verifier_context: {
      tenant_id: proof.verifierContext.tenantId,
      verifier_id: proof.verifierContext.verifierId,
    },
    request_envelope: {
      method: proof.requestEnvelope.method,
      path: proof.requestEnvelope.path,
      body_digest_sha256_hex: proof.requestEnvelope.bodyDigestSha256Hex,
    },
  };
  return new TextEncoder().encode(JSON.stringify(payload));
}

function normalizeRecognitionProof(params: SignAgentRecognitionProofV1Params): CanonicalRecognitionProof {
  const tenantId = params.tenantId.trim();
  if (!tenantId) {
    throw new Error("agent recognition proof: verifier_context.tenant_id is required");
  }

  const issuedAt = params.issuedAt ?? new Date(Date.now() - 60_000);
  const expiresAt = params.expiresAt ?? new Date(issuedAt.getTime() + 4 * 60_000);
  const issuedAtUtc = new Date(issuedAt.toISOString());
  const expiresAtUtc = new Date(expiresAt.toISOString());

  if (expiresAtUtc.getTime() <= issuedAtUtc.getTime()) {
    throw new Error("agent recognition proof: expires_at must be after issued_at");
  }
  if (expiresAtUtc.getTime() - issuedAtUtc.getTime() > AGENT_RECOGNITION_MAX_FRESHNESS_MS) {
    throw new Error("agent recognition proof: freshness window must not exceed 10m0s");
  }

  const nonce = params.nonce?.trim();
  if (!nonce) {
    throw new Error("agent recognition proof: nonce is required");
  }
  if (nonce.length > 256) {
    throw new Error("agent recognition proof: nonce must be 256 bytes or fewer");
  }

  const requestEnvelope = newAgentRecognitionRequestEnvelope(params.method, params.path, params.body);
  if (!HEX64_RE.test(requestEnvelope.bodyDigestSha256Hex)) {
    throw new Error(
      "agent recognition proof: request_envelope.body_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest",
    );
  }

  return {
    schemaVersion: AGENT_RECOGNITION_PROOF_SCHEMA_VERSION,
    kind: AGENT_RECOGNITION_PROOF_KIND_V1,
    keyId: normalizeScopeToken(params.keyId, "key_id"),
    signatureAlgorithm: AGENT_RECOGNITION_SIGNATURE_ALGORITHM_ED25519,
    issuedAt: formatRfc3339Seconds(issuedAtUtc),
    expiresAt: formatRfc3339Seconds(expiresAtUtc),
    nonce,
    purpose: normalizeScopeToken(params.purpose, "purpose"),
    verifierContext: {
      tenantId,
      verifierId: normalizeScopeToken(
        params.verifierId ?? AGENT_RECOGNITION_GATEWAY_VERIFIER_ID,
        "verifier_context.verifier_id",
      ),
    },
    requestEnvelope,
  };
}

/** Validate, canonicalize, and sign a replay-safe `AgentRecognitionProofV1`. */
export function signAgentRecognitionProofV1(
  signingSeed: Uint8Array,
  params: SignAgentRecognitionProofV1Params,
): SignedAgentRecognitionProofV1 {
  if (signingSeed.length !== 32) {
    throw new Error("agent recognition proof: signing key must be an ed25519 private key");
  }

  ensureEd25519Sha512Sync();
  const normalized = normalizeRecognitionProof({
    ...params,
    nonce: params.nonce?.trim() || randomUUID(),
  });
  const canonical = marshalCanonicalAgentRecognitionProof(normalized);
  const digest = sha256Hex(canonical);
  const digestBytes = createHash("sha256").update(canonical).digest();
  const signature = sign(digestBytes, signingSeed);
  const publicKey = getPublicKey(signingSeed);

  return {
    schema_version: normalized.schemaVersion,
    kind: normalized.kind,
    key_id: normalized.keyId,
    signature_algorithm: normalized.signatureAlgorithm,
    issued_at: normalized.issuedAt,
    expires_at: normalized.expiresAt,
    nonce: normalized.nonce,
    purpose: normalized.purpose,
    verifier_context: {
      tenant_id: normalized.verifierContext.tenantId,
      verifier_id: normalized.verifierContext.verifierId,
    },
    request_envelope: {
      method: normalized.requestEnvelope.method,
      path: normalized.requestEnvelope.path,
      body_digest_sha256_hex: normalized.requestEnvelope.bodyDigestSha256Hex,
    },
    message_digest_sha256_hex: digest,
    signing_public_key_ed25519_hex: bytesToHex(publicKey),
    ed25519_signature_hex: bytesToHex(signature),
  };
}

/** Build a recognition proof for Gateway `POST /harbor/intents`. */
export function signHarborCreateRecognitionProof(input: {
  tenantId: string;
  intentBody: Record<string, unknown>;
  keyId: string;
  signingSeed: Uint8Array;
}): SignedAgentRecognitionProofV1 {
  return signAgentRecognitionProofV1(input.signingSeed, {
    keyId: input.keyId,
    purpose: AGENT_RECOGNITION_PURPOSE_CREATE,
    tenantId: input.tenantId,
    method: "POST",
    path: "/harbor/intents",
    body: input.intentBody,
  });
}

/** Build a recognition proof for Gateway `POST /harbor/intents/{intentId}/fund`. */
export function signHarborFundRecognitionProof(input: {
  tenantId: string;
  intentId: string;
  keyId: string;
  signingSeed: Uint8Array;
}): SignedAgentRecognitionProofV1 {
  return signAgentRecognitionProofV1(input.signingSeed, {
    keyId: input.keyId,
    purpose: AGENT_RECOGNITION_PURPOSE_FUND,
    tenantId: input.tenantId,
    method: "POST",
    path: `/harbor/intents/${input.intentId}/fund`,
    body: {},
  });
}

/** Build a recognition proof for Gateway `POST /harbor/intents/{intentId}/evidence`. */
export function signHarborEvidenceSubmitRecognitionProof(input: {
  tenantId: string;
  intentId: string;
  evidenceBody: Record<string, unknown>;
  keyId: string;
  signingSeed: Uint8Array;
}): SignedAgentRecognitionProofV1 {
  return signAgentRecognitionProofV1(input.signingSeed, {
    keyId: input.keyId,
    purpose: AGENT_RECOGNITION_PURPOSE_EVIDENCE_SUBMIT,
    tenantId: input.tenantId,
    method: "POST",
    path: `/harbor/intents/${input.intentId}/evidence`,
    body: input.evidenceBody,
  });
}

/** Build a recognition proof for Gateway `POST /harbor/intents/{intentId}/settlement/confirm`. */
export function signHarborSettlementConfirmRecognitionProof(input: {
  tenantId: string;
  intentId: string;
  body?: Record<string, unknown>;
  keyId: string;
  signingSeed: Uint8Array;
}): SignedAgentRecognitionProofV1 {
  return signAgentRecognitionProofV1(input.signingSeed, {
    keyId: input.keyId,
    purpose: AGENT_RECOGNITION_PURPOSE_SETTLEMENT_CONFIRM,
    tenantId: input.tenantId,
    method: "POST",
    path: `/harbor/intents/${input.intentId}/settlement/confirm`,
    body: input.body ?? {},
  });
}
