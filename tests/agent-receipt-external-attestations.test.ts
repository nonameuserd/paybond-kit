import { describe, expect, it } from "vitest";

import {
  AGENT_RECEIPT_EXTERNAL_SOURCE_X402,
  partnerRecordDigestSha256Hex,
  resolveExternalAttestations,
} from "../src/agent-receipt-external-attestations.js";

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
});
