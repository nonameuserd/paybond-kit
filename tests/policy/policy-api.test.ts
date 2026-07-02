import { describe, expect, it } from "vitest";

import { paybondPolicyPresets } from "../../src/policy/policy-api.js";
import {
  assertLayeredPresetMatchesFlat,
  composePolicyLayers,
  composeBundledPresetDefault,
} from "../../src/policy/compose.js";
import { domain } from "../../src/policy/domain.js";
import { guardrails, maxSpend, maxSpendUsd } from "../../src/policy/guardrails.js";
import { resolveComposedPresetDocument } from "../../src/policy/presets.js";
import { listPolicyPresetIds } from "../../src/policy/presets.js";

describe("policy compose API", () => {
  it("flat travel matches bundled compose default", () => {
    assertLayeredPresetMatchesFlat("travel");
    const flat = resolveComposedPresetDocument("travel");
    const composed = composeBundledPresetDefault("travel");
    expect(composed).toEqual(flat);
  });

  it("paybondPolicyPresets.travel matches flat travel preset", () => {
    const preset = paybondPolicyPresets.travel();
    const flat = resolveComposedPresetDocument("travel");
    expect(preset.document).toEqual(flat);
  });

  it("custom max spend tightens side-effecting tool caps", () => {
    const policy = paybondPolicyPresets.travel({ maxSpend: 5000 });
    expect(policy.document.tools["travel.book_hotel"]?.max_spend_cents).toBe(5000);
  });

  it("compose stacks domain and guardrails programmatically", () => {
    const document = composePolicyLayers(
      domain.travel(),
      guardrails.defaultDeny(),
      guardrails.maxSpendUsd(500),
      maxSpend(15_000),
    );
    expect(document.tools["travel.book_hotel"]?.max_spend_cents).toBe(15_000);
    expect(document.intent?.budget?.max_spend_usd).toBe(500);
    expect(document.default_deny).toBe(true);
  });

  it("readOnly filter keeps non-side-effecting tools only", () => {
    const document = composePolicyLayers(domain.travel(), guardrails.readOnly());
    expect(document.tools["travel.book_hotel"]).toBeUndefined();
    expect(document.tools["search.web"]).toBeDefined();
    expect(document.intent?.allowed_tools).toEqual([]);
  });

  it("all bundled layered presets still match flat files", () => {
    for (const presetId of listPolicyPresetIds()) {
      expect(() => assertLayeredPresetMatchesFlat(presetId)).not.toThrow();
    }
  });
});
