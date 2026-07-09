import { describe, expect, it } from "vitest";

import { agentMandateDigestSha256Hex, normalizeAgentMandateV1 } from "../src/agent-mandate.js";
import {
  AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
  AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
  partnerRecordDigestSha256Hex,
  protocolAuthorizationReceiptToExternalAttestations,
  protocolSettlementReceiptToExternalAttestations,
  resolveExternalAttestations,
  signedMandateToExternalAttestations,
} from "../src/agent-receipt-external-attestations.js";
import {
  AP2_TEST_INTENT_ID,
  signedAp2Mandate,
  signedProtocolAuthorizationReceipt,
  signedProtocolSettlementReceipt,
} from "./helpers/evidence-fixtures.js";

describe("agent-receipt-external-attestations", () => {
  it("partnerRecordDigestSha256Hex is stable for canonical JSON", () => {
    const first = partnerRecordDigestSha256Hex({ b: 2, a: 1 });
    const second = partnerRecordDigestSha256Hex({ a: 1, b: 2 });
    expect(first).toBe(second);
    expect(first).toHaveLength(64);
  });

  it("resolveExternalAttestations accepts pre-built entries", () => {
    const built = resolveExternalAttestations([
      {
        source: AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
        kind: "delivery_receipt_v1",
        digest_sha256_hex: "a".repeat(64),
        reference_id: "https://api.example/resource",
      },
    ]);
    expect(built).toHaveLength(1);
    expect(built[0]?.reference_id).toBe("https://api.example/resource");
  });

  it("resolveExternalAttestations accepts pre-built ap2 entries unchanged", () => {
    const prebuilt = {
      source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
      kind: "agent_mandate_v1",
      digest_sha256_hex: "b".repeat(64),
      reference_id: "authz-prebuilt",
    };
    const built = resolveExternalAttestations([prebuilt]);
    expect(built).toEqual([prebuilt]);
  });

  it("resolveExternalAttestations throws when sep2828 verification fails", () => {
    expect(() =>
      resolveExternalAttestations([
        {
          kind: "sep2828",
          decision: { note: "decision" },
          outcome: { note: "outcome" },
        },
      ]),
    ).toThrow();
  });

  describe("AP2 signed mandate", () => {
    it("maps via signedMandateToExternalAttestations", () => {
      const signed = signedAp2Mandate();
      const attestations = signedMandateToExternalAttestations(signed, {
        external_authorization_id: "authz-123",
      });

      expect(attestations).toHaveLength(1);
      expect(attestations[0]).toEqual({
        source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        kind: "agent_mandate_v1",
        digest_sha256_hex: signed.message_digest_sha256_hex,
        reference_id: "authz-123",
      });
    });

    it("falls back to mandate nonce when transport binding omits external_authorization_id", () => {
      const signed = signedAp2Mandate();
      const attestations = signedMandateToExternalAttestations(signed);

      expect(attestations[0]?.reference_id).toBe("nonce-123");
    });

    it("maps via resolveExternalAttestations with ap2_mandate kind", () => {
      const signed = signedAp2Mandate();
      const attestations = resolveExternalAttestations([
        {
          kind: "ap2_mandate",
          signedMandate: signed,
          transportBinding: { external_authorization_id: "authz-123" },
        },
      ]);

      expect(attestations).toHaveLength(1);
      expect(attestations[0]?.source).toBe(AGENT_RECEIPT_EXTERNAL_SOURCE_AP2);
      expect(attestations[0]?.kind).toBe("agent_mandate_v1");
      expect(attestations[0]?.digest_sha256_hex).toBe(signed.message_digest_sha256_hex);
      expect(attestations[0]?.reference_id).toBe("authz-123");
    });

    it("cross-checks mandate digest against agentMandateDigestSha256Hex and verified envelope digest", () => {
      const signed = signedAp2Mandate();
      const normalizedDigest = agentMandateDigestSha256Hex(normalizeAgentMandateV1(signed));
      const attestations = signedMandateToExternalAttestations(signed);

      expect(attestations[0]?.digest_sha256_hex).toBe(signed.message_digest_sha256_hex);
      expect(attestations[0]?.digest_sha256_hex).toBe(normalizedDigest);
    });

    it("throws when mandate verification fails", () => {
      const signed = signedAp2Mandate();
      const tampered = { ...signed, allowed_tools: ["travel.cancel"] };

      expect(() => signedMandateToExternalAttestations(tampered)).toThrow();
      expect(() =>
        resolveExternalAttestations([{ kind: "ap2_mandate", signedMandate: tampered }]),
      ).toThrow();
    });
  });

  describe("AP2 protocol authorization receipt", () => {
    it("maps via protocolAuthorizationReceiptToExternalAttestations", () => {
      const receipt = signedProtocolAuthorizationReceipt();
      const attestations = protocolAuthorizationReceiptToExternalAttestations(receipt);

      expect(attestations).toHaveLength(1);
      expect(attestations[0]).toEqual({
        source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        kind: "protocol_authorization_receipt_v1",
        digest_sha256_hex: receipt.message_digest_sha256_hex,
        reference_id: AP2_TEST_INTENT_ID,
      });
    });

    it("maps via resolveExternalAttestations with ap2_authorization_receipt kind", () => {
      const receipt = signedProtocolAuthorizationReceipt();
      const attestations = resolveExternalAttestations([
        { kind: "ap2_authorization_receipt", receipt },
      ]);

      expect(attestations).toHaveLength(1);
      expect(attestations[0]?.source).toBe(AGENT_RECEIPT_EXTERNAL_SOURCE_AP2);
      expect(attestations[0]?.kind).toBe("protocol_authorization_receipt_v1");
      expect(attestations[0]?.digest_sha256_hex).toBe(receipt.message_digest_sha256_hex);
      expect(attestations[0]?.reference_id).toBe(AP2_TEST_INTENT_ID);
    });

    it("throws when authorization receipt verification fails", () => {
      const receipt = signedProtocolAuthorizationReceipt();
      const tampered = { ...receipt, intent_id: "00000000-0000-4000-8000-000000000001" };

      expect(() => protocolAuthorizationReceiptToExternalAttestations(tampered)).toThrow();
      expect(() =>
        resolveExternalAttestations([{ kind: "ap2_authorization_receipt", receipt: tampered }]),
      ).toThrow();
    });
  });

  describe("AP2 protocol settlement receipt", () => {
    it("maps via protocolSettlementReceiptToExternalAttestations", () => {
      const receipt = signedProtocolSettlementReceipt();
      const attestations = protocolSettlementReceiptToExternalAttestations(receipt);

      expect(attestations).toHaveLength(1);
      expect(attestations[0]).toEqual({
        source: AGENT_RECEIPT_EXTERNAL_SOURCE_AP2,
        kind: "protocol_settlement_receipt_v1",
        digest_sha256_hex: receipt.message_digest_sha256_hex,
        reference_id: AP2_TEST_INTENT_ID,
      });
    });

    it("maps via resolveExternalAttestations with ap2_settlement_receipt kind", () => {
      const receipt = signedProtocolSettlementReceipt();
      const attestations = resolveExternalAttestations([
        { kind: "ap2_settlement_receipt", receipt },
      ]);

      expect(attestations).toHaveLength(1);
      expect(attestations[0]?.source).toBe(AGENT_RECEIPT_EXTERNAL_SOURCE_AP2);
      expect(attestations[0]?.kind).toBe("protocol_settlement_receipt_v1");
      expect(attestations[0]?.digest_sha256_hex).toBe(receipt.message_digest_sha256_hex);
      expect(attestations[0]?.reference_id).toBe(AP2_TEST_INTENT_ID);
    });

    it("throws when settlement receipt verification fails", () => {
      const receipt = signedProtocolSettlementReceipt();
      const tampered = { ...receipt, harbor_state: "funded" };

      expect(() => protocolSettlementReceiptToExternalAttestations(tampered)).toThrow();
      expect(() =>
        resolveExternalAttestations([{ kind: "ap2_settlement_receipt", receipt: tampered }]),
      ).toThrow();
    });
  });
});
