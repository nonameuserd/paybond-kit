import { describe, expect, it } from "vitest";

import { getCompletionPreset } from "../src/completion-catalog.js";
import { validateCompletionEvidence } from "../src/completion-validate-evidence.js";

describe("completion-validate-evidence", () => {
  it("passes valid stripe_charge vendor payload", () => {
    const preset = getCompletionPreset("stripe_charge");
    const vendor = preset.vendor_sample_evidence ?? {};
    const report = validateCompletionEvidence({
      presetId: "stripe_charge",
      vendorPayload: vendor,
    });
    expect(report.vendor_schema_ok).toBe(true);
    expect(report.canonical_schema_ok).toBe(true);
    expect(report.drift_kinds).toEqual([]);
  });

  it("detects pack_stale when frozen api_version lags catalog", () => {
    const preset = getCompletionPreset("stripe_charge");
    const vendor = preset.vendor_sample_evidence ?? {};
    const report = validateCompletionEvidence({
      presetId: "stripe_charge",
      vendorPayload: vendor,
      frozenVendorApiVersion: "legacy_epoch",
    });
    expect(report.pack_stale).toBe(true);
    expect(report.drift_kinds).toContain("pack_stale");
  });

  it("flags missing quality fields on reshaped vendor payload", () => {
    const report = validateCompletionEvidence({
      presetId: "ach_travel_booking",
      vendorPayload: {
        confirmation_number: "AA-123",
        http_status: 200,
        response_digest: "blake3:abc",
        status: "confirmed",
        total_cents: 12000,
      },
    });
    expect(report.quality_fields_missing).toContain("fare_class");
    expect(report.drift_kinds).toContain("quality_field_missing");
  });

  it("flags forbidden evidence fields from preset catalog", () => {
    const report = validateCompletionEvidence({
      presetId: "x402_paid_api_ok",
      vendorPayload: {
        http_status: 200,
        response_digest: "blake3:abc",
        payment_session_id: "sess_123",
      },
    });
    expect(report.forbidden_fields_present).toContain("payment_session_id");
    expect(report.drift_kinds).toContain("forbidden_field_present");
    expect(report.vendor_schema_ok).toBe(false);
  });
});
