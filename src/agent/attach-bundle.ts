import { createDecipheriv, createCipheriv, randomBytes } from "node:crypto";

import type { PaybondRunProductionEvidenceCredentials } from "./types.js";

/** Attach bundle wire prefix (`ab1.`). */
export const PAYBOND_ATTACH_BUNDLE_PREFIX = "ab1.";

export const PAYBOND_ATTACH_INTENT_ID_ENV = "PAYBOND_ATTACH_INTENT_ID";
export const PAYBOND_CAPABILITY_TOKEN_ENV = "PAYBOND_CAPABILITY_TOKEN";
export const PAYBOND_ATTACH_BUNDLE_ENV = "PAYBOND_ATTACH_BUNDLE";

/** Cleartext credential payload sealed inside {@link PAYBOND_ATTACH_BUNDLE_ENV}. */
export type PaybondAttachBundlePayloadV1 = Readonly<{
  v: 1;
  payee_did: string;
  payee_signing_seed_hex: string;
  agent_recognition_key_id: string;
  agent_recognition_signing_seed_hex: string;
}>;

type AttachBundleEnvelopeV1 = Readonly<{
  v: 1;
  alg: "aes-256-gcm";
  k: string;
  n: string;
  c: string;
}>;

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlDecode(encoded: string): Uint8Array {
  return new Uint8Array(Buffer.from(encoded, "base64url"));
}

function parseSeed32Hex(raw: string, field: string): Uint8Array {
  const hex = raw.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${field} must be a 32-byte Ed25519 seed (64 hex characters)`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Seal production signing material into an opaque attach bundle for env injection. */
export function sealPaybondAttachBundle(payload: PaybondAttachBundlePayloadV1): string {
  if (payload.v !== 1) {
    throw new Error("attach bundle payload version must be 1");
  }
  const bundleKey = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", bundleKey, nonce);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  const envelope: AttachBundleEnvelopeV1 = {
    v: 1,
    alg: "aes-256-gcm",
    k: base64UrlEncode(bundleKey),
    n: base64UrlEncode(nonce),
    c: base64UrlEncode(ciphertext),
  };
  return PAYBOND_ATTACH_BUNDLE_PREFIX + Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url");
}

/** Open a console-minted attach bundle and return the sealed credential payload. */
export function openPaybondAttachBundle(bundle: string): PaybondAttachBundlePayloadV1 {
  const trimmed = bundle.trim();
  if (!trimmed.startsWith(PAYBOND_ATTACH_BUNDLE_PREFIX)) {
    throw new Error(`attach bundle must start with ${PAYBOND_ATTACH_BUNDLE_PREFIX}`);
  }
  const encoded = trimmed.slice(PAYBOND_ATTACH_BUNDLE_PREFIX.length);
  let envelope: AttachBundleEnvelopeV1;
  try {
    envelope = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as AttachBundleEnvelopeV1;
  } catch {
    throw new Error("attach bundle envelope is not valid base64url JSON");
  }
  if (envelope.v !== 1 || envelope.alg !== "aes-256-gcm") {
    throw new Error("unsupported attach bundle envelope");
  }
  const bundleKey = base64UrlDecode(envelope.k);
  const nonce = base64UrlDecode(envelope.n);
  const ciphertext = base64UrlDecode(envelope.c);
  if (bundleKey.length !== 32 || nonce.length !== 12 || ciphertext.length < 16) {
    throw new Error("attach bundle envelope fields are malformed");
  }
  const authTag = ciphertext.slice(ciphertext.length - 16);
  const encrypted = ciphertext.slice(0, ciphertext.length - 16);
  const decipher = createDecipheriv("aes-256-gcm", bundleKey, nonce);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  const payload = JSON.parse(plaintext.toString("utf8")) as PaybondAttachBundlePayloadV1;
  if (payload.v !== 1) {
    throw new Error("attach bundle payload version must be 1");
  }
  return payload;
}

/** Map attach bundle payload bytes into run-scoped production evidence credentials. */
export function productionEvidenceFromAttachBundle(
  payload: PaybondAttachBundlePayloadV1,
): PaybondRunProductionEvidenceCredentials {
  return {
    payeeDid: payload.payee_did.trim(),
    payeeSigningSeed: parseSeed32Hex(payload.payee_signing_seed_hex, "payee_signing_seed_hex"),
    agentRecognitionKeyId: payload.agent_recognition_key_id.trim(),
    agentRecognitionSigningSeed: parseSeed32Hex(
      payload.agent_recognition_signing_seed_hex,
      "agent_recognition_signing_seed_hex",
    ),
  };
}

export type PaybondAttachEnvRecord = Readonly<Record<string, string | undefined>>;

/**
 * Resolve funded-intent attach context from standard production env vars.
 * Requires {@link PAYBOND_ATTACH_INTENT_ID_ENV}, {@link PAYBOND_CAPABILITY_TOKEN_ENV},
 * and {@link PAYBOND_ATTACH_BUNDLE_ENV}.
 */
export function resolveAttachContextFromEnv(
  env: PaybondAttachEnvRecord = process.env as PaybondAttachEnvRecord,
): {
  intentId: string;
  capabilityToken: string;
  productionEvidence: PaybondRunProductionEvidenceCredentials;
} {
  const intentId = env[PAYBOND_ATTACH_INTENT_ID_ENV]?.trim() ?? "";
  const capabilityToken = env[PAYBOND_CAPABILITY_TOKEN_ENV]?.trim() ?? "";
  const bundle = env[PAYBOND_ATTACH_BUNDLE_ENV]?.trim() ?? "";
  if (!intentId) {
    throw new Error(`${PAYBOND_ATTACH_INTENT_ID_ENV} is required when attach is "env"`);
  }
  if (!capabilityToken) {
    throw new Error(`${PAYBOND_CAPABILITY_TOKEN_ENV} is required when attach is "env"`);
  }
  if (!bundle) {
    throw new Error(`${PAYBOND_ATTACH_BUNDLE_ENV} is required when attach is "env"`);
  }
  const payload = openPaybondAttachBundle(bundle);
  return {
    intentId,
    capabilityToken,
    productionEvidence: productionEvidenceFromAttachBundle(payload),
  };
}

/** Format the console one-time env snippet for copy/paste into a secrets manager. */
export function formatPaybondAttachEnvSnippet(input: {
  intentId: string;
  capabilityToken: string;
  attachBundle: string;
}): string {
  return [
    `${PAYBOND_ATTACH_INTENT_ID_ENV}=${input.intentId}`,
    `${PAYBOND_CAPABILITY_TOKEN_ENV}=${input.capabilityToken}`,
    `${PAYBOND_ATTACH_BUNDLE_ENV}=${input.attachBundle}`,
  ].join("\n");
}
