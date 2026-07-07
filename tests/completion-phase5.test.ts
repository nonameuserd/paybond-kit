import { describe, expect, it } from "vitest";

import {
  completionPresetDeprecationWarning,
  mapVendorEvidenceToCanonical,
  resolveCompletionPreset,
} from "../src/completion-resolve.js";
import { mapSep2828ReceiptsToArtifactAttestedEvidence } from "../src/mcp-sep2828-evidence.js";
import { loadCompletionCatalog } from "../src/completion-catalog.js";
import { signedJwsX402Receipt, signedSep2828Pair } from "./helpers/evidence-fixtures.js";

describe("completion-resolve", () => {
  it("resolves stripe_charge vendor pack to api_response archetype", () => {
    const resolved = resolveCompletionPreset("stripe_charge");
    expect(resolved.kind).toBe("vendor_pack");
    expect(resolved.archetype.preset_id).toBe("api_response_ok");
    expect(resolved.harborTemplateId).toBe("api_response_v1");
  });

  it("resolves vendor_webhook_confirmed with neutral job.completed default", () => {
    const resolved = resolveCompletionPreset("vendor_webhook_confirmed");
    expect(resolved.archetype.preset_id).toBe("webhook_confirmed");
    expect(resolved.parameters.expected_event_type).toBe("job.completed");
  });

  it("warns on deprecated stripe_webhook_payment preset", () => {
    const warning = completionPresetDeprecationWarning("stripe_webhook_payment");
    expect(warning).toContain("vendor_webhook_confirmed");
  });

  it("maps legacy stripe_event_id on deprecated stripe_webhook_payment", () => {
    const resolved = resolveCompletionPreset("stripe_webhook_payment");
    const canonical = mapVendorEvidenceToCanonical(resolved.preset, {
      stripe_event_id: "evt_legacy",
      event_type: "job.completed",
      payload_digest: "blake3:abc",
    });
    expect(canonical.webhook_event_id).toBe("evt_legacy");
  });

  it("maps vendor evidence fields to canonical names", () => {
    const resolved = resolveCompletionPreset("stripe_charge");
    const canonical = mapVendorEvidenceToCanonical(resolved.preset, {
      charge_id: "ch_123",
      http_status: 200,
      response_digest: "blake3:abc",
    });
    expect(canonical).toEqual({
      vendor_ref_id: "ch_123",
      http_status: 200,
      response_digest: "blake3:abc",
    });
  });

  it("maps ach_paid_api_ok confirmation_number to vendor_ref_id", () => {
    const resolved = resolveCompletionPreset("ach_paid_api_ok");
    expect(resolved.preset.rail_hints).toEqual(["stripe_ach_debit"]);
    const canonical = mapVendorEvidenceToCanonical(resolved.preset, {
      confirmation_number: "AA-8JZ3QK",
      http_status: 200,
      response_digest: "blake3:abc",
    });
    expect(canonical.vendor_ref_id).toBe("AA-8JZ3QK");
  });

  it("maps x402_delivery_receipt receipt_digest into artifact_blake3_hex array", () => {
    const resolved = resolveCompletionPreset("x402_delivery_receipt");
    const canonical = mapVendorEvidenceToCanonical(resolved.preset, {
      receipt_digest: "deadbeef",
      resource_url: "https://api.vendor.example/job/123",
      operation: "attested",
    });
    expect(canonical).toEqual({
      artifact_blake3_hex: ["deadbeef"],
      vendor_ref_id: "https://api.vendor.example/job/123",
      operation: "attested",
    });
  });

  it("resolves ach_travel_booking with custom evidence schema", () => {
    const resolved = resolveCompletionPreset("ach_travel_booking");
    expect(resolved.evidenceSchema.required).toEqual(
      expect.arrayContaining(["confirmation_number", "total_cents", "fare_class", "status"]),
    );
    expect(resolved.parameters.cost_path).toEqual(["total_cents"]);
  });

  it("resolves x402_saas_api_purchase with subscription_id mapping", () => {
    const resolved = resolveCompletionPreset("x402_saas_api_purchase");
    expect(resolved.kind).toBe("vendor_pack");
    expect(resolved.preset.rail_hints).toEqual(["x402_usdc_base", "stripe_mpp"]);
    const canonical = mapVendorEvidenceToCanonical(resolved.preset, {
      subscription_id: "sub_abc",
      seat_count: 3,
      http_status: 200,
      response_digest: "blake3:abc",
    });
    expect(canonical.vendor_ref_id).toBe("sub_abc");
  });

  it("resolves x402_travel_booking with x402 rail hints", () => {
    const resolved = resolveCompletionPreset("x402_travel_booking");
    expect(resolved.preset.rail_hints).toEqual(["x402_usdc_base", "stripe_mpp"]);
    expect(resolved.parameters.cost_path).toEqual(["total_cents"]);
    expect(resolved.parameters.expected_status).toBe("completed");
  });

  it("resolves invoice_payment_confirmed with invoice.paid event type", () => {
    const resolved = resolveCompletionPreset("invoice_payment_confirmed");
    expect(resolved.archetype.preset_id).toBe("webhook_confirmed");
    expect(resolved.parameters.expected_event_type).toBe("invoice.paid");
    expect(resolved.evidenceSchema.required).toEqual(
      expect.arrayContaining(["invoice_number", "payment_reference", "webhook_event_id"]),
    );
  });
});

describe("phase 5.2 vendor pack catalog", () => {
  it("includes ACH and x402 vendor packs with forbidden fields", () => {
    const catalog = loadCompletionCatalog();
    const achPack = catalog.presets.find((preset) => preset.preset_id === "ach_vendor_webhook");
    const x402Pack = catalog.presets.find((preset) => preset.preset_id === "x402_paid_api_ok");
    expect(achPack?.rail_hints).toEqual(["stripe_ach_debit"]);
    expect(achPack?.forbidden_evidence_fields).toContain("payment_intent_id");
    expect(x402Pack?.rail_hints).toEqual(["x402_usdc_base", "stripe_mpp"]);
    expect(x402Pack?.forbidden_evidence_fields).toContain("payment_session_id");
  });

  it("includes vertical completion presets", () => {
    const catalog = loadCompletionCatalog();
    const verticalIds = ["x402_saas_api_purchase", "x402_travel_booking", "invoice_payment_confirmed"];
    for (const presetId of verticalIds) {
      const preset = catalog.presets.find((entry) => entry.preset_id === presetId);
      expect(preset, presetId).toBeDefined();
      expect(preset?.kind).toBe("vendor_pack");
      expect(preset?.vendor_contract?.api_version).toBeTruthy();
    }
  });
});

describe("mcp-sep2828-evidence", () => {
  it("maps paired signed decision and outcome records to artifact_attested evidence", async () => {
    const { decision, outcome } = await signedSep2828Pair();
    const evidence = mapSep2828ReceiptsToArtifactAttestedEvidence(decision, outcome);
    expect(evidence.operation).toBe("attested");
    expect(evidence.vendor_ref_id).toBe("sha256:deadbeef");
    expect(evidence.artifact_blake3_hex).toContain("22222222");
  });

  it("rejects unsigned decision/outcome records", () => {
    expect(() =>
      mapSep2828ReceiptsToArtifactAttestedEvidence(
        { backLink: { attestationDigest: "sha256:deadbeef" } },
        { backLink: { attestationDigest: "sha256:deadbeef" } },
      ),
    ).toThrow(/missing ed25519 signature/);
  });
});
