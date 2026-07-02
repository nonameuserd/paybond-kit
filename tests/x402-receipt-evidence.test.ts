import { describe, expect, it } from "vitest";

import {
  assertNotX402FundingArtifact,
  buildX402ReceiptDigestPayload,
  mapX402ReceiptToArtifactAttestedEvidence,
  x402ReceiptPayloadDigestHex,
} from "../src/x402-receipt-evidence.js";
import { signedJwsX402Receipt } from "./helpers/evidence-fixtures.js";

const SAMPLE_RECEIPT = {
  resourceUrl: "https://api.vendor.example/job/123",
  payer: "0xabc123",
  network: "eip155:84532",
  issuedAt: 1710000000,
};

describe("x402-receipt-evidence", () => {
  it("digests JCS-canonical receipt payload bytes into artifact_blake3_hex", () => {
    const payload = buildX402ReceiptDigestPayload(SAMPLE_RECEIPT);
    const digest = x402ReceiptPayloadDigestHex(payload);
    expect(digest).toHaveLength(64);

    const evidence = mapX402ReceiptToArtifactAttestedEvidence(signedJwsX402Receipt(SAMPLE_RECEIPT));
    expect(evidence).toEqual({
      artifact_blake3_hex: [digest],
      operation: "attested",
      vendor_ref_id: "https://api.vendor.example/job/123",
    });
  });

  it("includes optional transaction in the digest payload", () => {
    const withTx = {
      ...SAMPLE_RECEIPT,
      txHash: "0xdeadbeef",
    };
    const withoutTx = x402ReceiptPayloadDigestHex(buildX402ReceiptDigestPayload(SAMPLE_RECEIPT));
    const withTxDigest = x402ReceiptPayloadDigestHex(buildX402ReceiptDigestPayload(withTx));
    expect(withTxDigest).not.toBe(withoutTx);
  });

  it("unwraps signed receipt extension envelopes", () => {
    const evidence = mapX402ReceiptToArtifactAttestedEvidence(signedJwsX402Receipt(SAMPLE_RECEIPT));
    expect(evidence.vendor_ref_id).toBe(SAMPLE_RECEIPT.resourceUrl);
    expect(evidence.artifact_blake3_hex).toHaveLength(1);
  });

  it("rejects unsigned receipt payloads", () => {
    expect(() => mapX402ReceiptToArtifactAttestedEvidence(SAMPLE_RECEIPT)).toThrow(
      /signed offer-receipt artifact/,
    );
  });

  it("rejects Coinbase authorization_succeeded funding webhooks", () => {
    expect(() =>
      assertNotX402FundingArtifact({
        event_type: "authorization_succeeded",
        payment_session_id: "sess_123",
      }),
    ).toThrow(/funding signals/);
  });

  it("rejects funding session ids in receipt input", () => {
    expect(() =>
      mapX402ReceiptToArtifactAttestedEvidence({
        ...SAMPLE_RECEIPT,
        payment_session_id: "sess_123",
      }),
    ).toThrow(/funding field payment_session_id/);
  });
});
