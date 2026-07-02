import { describe, expect, it } from "vitest";

import {
  formatPaybondAttachEnvSnippet,
  openPaybondAttachBundle,
  PAYBOND_ATTACH_BUNDLE_ENV,
  PAYBOND_ATTACH_INTENT_ID_ENV,
  PAYBOND_CAPABILITY_TOKEN_ENV,
  productionEvidenceFromAttachBundle,
  resolveAttachContextFromEnv,
  sealPaybondAttachBundle,
  type PaybondAttachBundlePayloadV1,
} from "../../src/agent/attach-bundle.js";

const SAMPLE_PAYLOAD: PaybondAttachBundlePayloadV1 = {
  v: 1,
  payee_did: "did:paybond:middleware:acme:amk_demo:payee",
  payee_signing_seed_hex: "a".repeat(64),
  agent_recognition_key_id: "amk_demo",
  agent_recognition_signing_seed_hex: "b".repeat(64),
};

describe("attach bundle", () => {
  it("seals and opens a v1 attach bundle round-trip", () => {
    const bundle = sealPaybondAttachBundle(SAMPLE_PAYLOAD);
    expect(bundle.startsWith("ab1.")).toBe(true);
    expect(openPaybondAttachBundle(bundle)).toEqual(SAMPLE_PAYLOAD);
  });

  it("maps bundle payload to production evidence credentials", () => {
    const evidence = productionEvidenceFromAttachBundle(SAMPLE_PAYLOAD);
    expect(evidence.payeeDid).toBe(SAMPLE_PAYLOAD.payee_did);
    expect(evidence.agentRecognitionKeyId).toBe("amk_demo");
    expect(evidence.payeeSigningSeed).toHaveLength(32);
    expect(evidence.agentRecognitionSigningSeed).toHaveLength(32);
  });

  it("resolves attach context from env vars", () => {
    const bundle = sealPaybondAttachBundle(SAMPLE_PAYLOAD);
    const context = resolveAttachContextFromEnv({
      [PAYBOND_ATTACH_INTENT_ID_ENV]: "intent-123",
      [PAYBOND_CAPABILITY_TOKEN_ENV]: "cap-token",
      [PAYBOND_ATTACH_BUNDLE_ENV]: bundle,
    });
    expect(context.intentId).toBe("intent-123");
    expect(context.capabilityToken).toBe("cap-token");
    expect(context.productionEvidence.payeeDid).toBe(SAMPLE_PAYLOAD.payee_did);
  });

  it("formats a copy-paste env snippet", () => {
    const snippet = formatPaybondAttachEnvSnippet({
      intentId: "intent-123",
      capabilityToken: "cap-token",
      attachBundle: "ab1.payload",
    });
    expect(snippet).toContain(`${PAYBOND_ATTACH_INTENT_ID_ENV}=intent-123`);
    expect(snippet).toContain(`${PAYBOND_CAPABILITY_TOKEN_ENV}=cap-token`);
    expect(snippet).toContain(`${PAYBOND_ATTACH_BUNDLE_ENV}=ab1.payload`);
  });
});
