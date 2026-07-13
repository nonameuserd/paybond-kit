import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  projectAgentReceiptToActaDecisionReceipt,
} from "../src/agent-receipt-acta.js";
import {
  buildAgentReceiptPefFrame,
  verifyAgentReceiptPefFrameId,
} from "../src/agent-receipt-pef.js";
import {
  buildAgentReceiptScittExport,
  verifyAgentReceiptScittExport,
} from "../src/agent-receipt-scitt.js";

const ROOT = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE = join(ROOT, "../../agent-receipt/conformance");

describe("agent receipt ACTA projection", () => {
  it("matches the ACTA projection golden file", () => {
    const receipt = JSON.parse(
      readFileSync(join(CONFORMANCE, "signed-action-receipt-v1.json"), "utf8"),
    );
    const golden = JSON.parse(
      readFileSync(join(CONFORMANCE, "acta-projection-v1.json"), "utf8"),
    );
    const projected = projectAgentReceiptToActaDecisionReceipt(receipt);
    expect(projected).toEqual(golden.expected);
  });
});

describe("agent receipt PEF frame", () => {
  it("matches the PEF frame_id golden and verifies deterministically", () => {
    const receipt = JSON.parse(
      readFileSync(join(CONFORMANCE, "signed-action-receipt-v1.json"), "utf8"),
    );
    const golden = JSON.parse(
      readFileSync(join(CONFORMANCE, "pef-frame-id-v1.json"), "utf8"),
    );
    const frame = buildAgentReceiptPefFrame({
      receipt,
      frameProviderDid: golden.frame_provider_did,
      frameTimestampMs: golden.frame_timestamp_ms,
    });
    expect(frame.receipt_hash).toBe(golden.expected_receipt_hash);
    expect(frame.frame_id).toBe(golden.expected_frame_id);
    expect(frame.claim_type).toBe(golden.expected_claim_type);
    verifyAgentReceiptPefFrameId(frame);
    const again = buildAgentReceiptPefFrame({
      receipt,
      frameProviderDid: golden.frame_provider_did,
      frameTimestampMs: golden.frame_timestamp_ms,
    });
    expect(again.frame_id).toBe(frame.frame_id);
  });
});

describe("agent receipt SCITT export", () => {
  it("matches the SCITT COSE golden and verifies the envelope", () => {
    const golden = JSON.parse(
      readFileSync(join(CONFORMANCE, "scitt-cose-export-v1.json"), "utf8"),
    );
    const seed = createHash("sha256")
      .update(golden.signing_private_key_seed_sha256_of)
      .digest("hex");
    expect(seed).toBe(golden.signing_private_key_seed_hex);
    const exportDoc = buildAgentReceiptScittExport({
      receiptId: golden.expected.receipt_id,
      messageDigestSha256Hex: golden.expected.message_digest_sha256_hex,
      signingPrivateKeySeedHex: seed,
      issuer: golden.issuer,
      kid: golden.kid,
    });
    expect(exportDoc).toEqual(golden.expected);
    verifyAgentReceiptScittExport(exportDoc);
  });
});
