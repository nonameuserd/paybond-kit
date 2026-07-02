import { describe, expect, it } from "vitest";

import { Paybond } from "../../src/index.js";
import { paybondSolutionPresets } from "../../src/solutions/api.js";
import { getSolutionSmokeDefaults, loadSolutionManifest } from "../../src/solutions/catalog.js";
import { paybondPolicyPresets } from "../../src/policy/policy-api.js";
import { resolveComposedPresetDocument } from "../../src/policy/presets.js";

describe("solution bundles", () => {
  it("loads travel manifest with smoke defaults", () => {
    const manifest = loadSolutionManifest("travel");
    expect(manifest.id).toBe("travel");
    expect(manifest.primary_operation).toBe("travel.book_hotel");
    expect(manifest.completion_preset).toBe("ach_travel_booking");
    expect(manifest.vendor_pack).toBe("travel_booking_v1");

    const smoke = getSolutionSmokeDefaults("travel");
    expect(smoke.operation).toBe("travel.book_hotel");
    expect(smoke.requestedSpendCents).toBe(18_700);
    expect(smoke.evidencePreset).toBe("cost_and_completion");
    expect(smoke.resultBody).toEqual({ status: "completed", cost_cents: 18_700 });
  });

  it("paybond.solution.travel() returns policy, smoke defaults, and operations", () => {
    const paybond = new Paybond({ apiKey: "test" });
    const bundle = paybond.solution.travel();
    expect(bundle.id).toBe("travel");
    expect(bundle.title).toBe("Travel booking agent");
    expect(bundle.completionPreset).toBe("ach_travel_booking");
    expect(bundle.vendorPack).toBe("travel_booking_v1");
    expect(bundle.operations).toEqual(["travel.book_hotel"]);
    expect(bundle.smokeDefaults.requestedSpendCents).toBe(18_700);
    expect(bundle.policy.document).toEqual(resolveComposedPresetDocument("travel"));
  });

  it("paybondSolutionPresets.travel matches paybond.policyPresets.travel policy document", () => {
    const bundle = paybondSolutionPresets.travel();
    expect(bundle.policy.document).toEqual(paybondPolicyPresets.travel().document);
  });
});
