import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  gateAgentReceiptPDFExport,
  parseAgentReceiptPDFExportManifestJSON,
  validateAgentReceiptPDFExportManifestJSON,
} from "../src/agent-receipt-pdf-export.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const AGENT_RECEIPT_DIR = join(MODULE_DIR, "../../agent-receipt");

describe("agent receipt pdf export manifest", () => {
  it("validates conformance manifest against pdf-export-manifest-schema.json", () => {
    const manifest = JSON.parse(
      readFileSync(join(AGENT_RECEIPT_DIR, "conformance/pdf-export-manifest-v1.json"), "utf8"),
    );
    expect(() => validateAgentReceiptPDFExportManifestJSON(manifest)).not.toThrow();
  });

  it("rejects embedded_receipt_json as authority", () => {
    const manifest = JSON.parse(
      readFileSync(join(AGENT_RECEIPT_DIR, "conformance/pdf-export-manifest-v1.json"), "utf8"),
    );
    manifest.embedded_receipt_json = { receipt_id: "forged" };
    expect(() => validateAgentReceiptPDFExportManifestJSON(manifest)).toThrow(
      /forbidden field/,
    );
  });

  it("gate binds manifest to verified conformance receipt", async () => {
    const receiptJSON = readFileSync(
      join(AGENT_RECEIPT_DIR, "conformance/signed-action-receipt-v1.json"),
      "utf8",
    );
    const manifestJSON = readFileSync(
      join(AGENT_RECEIPT_DIR, "conformance/pdf-export-manifest-v1.json"),
      "utf8",
    );

    const { receipt, manifest } = await gateAgentReceiptPDFExport({
      receiptJSON,
      manifestJSON,
    });
    expect(manifest.receipt_id).toBe(receipt.receipt_id);
    expect(manifest.message_digest_sha256_hex).toBe(receipt.message_digest_sha256_hex);
  });

  it("gate verifies pdf_sha256_hex when pdf bytes are supplied", async () => {
    const receiptJSON = readFileSync(
      join(AGENT_RECEIPT_DIR, "conformance/signed-action-receipt-v1.json"),
      "utf8",
    );
    const manifest = parseAgentReceiptPDFExportManifestJSON(
      readFileSync(join(AGENT_RECEIPT_DIR, "conformance/pdf-export-manifest-v1.json"), "utf8"),
    );
    const pdfBytes = new TextEncoder().encode("%PDF-1.4 conformance test bytes");
    manifest.pdf_sha256_hex = createHash("sha256").update(pdfBytes).digest("hex");

    await expect(
      gateAgentReceiptPDFExport({
        receiptJSON,
        manifestJSON: JSON.stringify(manifest),
        pdfBytes,
      }),
    ).resolves.toBeDefined();

    await expect(
      gateAgentReceiptPDFExport({
        receiptJSON,
        manifestJSON: JSON.stringify(manifest),
        pdfBytes: new TextEncoder().encode("tampered"),
      }),
    ).rejects.toThrow(/pdf_sha256_hex mismatch/);
  });
});
