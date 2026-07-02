import { describe, expect, it } from "vitest";

import { assertLayeredPresetMatchesFlat, composeLayeredPolicyPresetDocument } from "../../src/policy/compose.js";
import { listPolicyPresetIds } from "../../src/policy/presets.js";

describe("policy preset composition", () => {
  it("composes layered vertical presets that match bundled flat files", () => {
    for (const presetId of listPolicyPresetIds()) {
      expect(() => assertLayeredPresetMatchesFlat(presetId)).not.toThrow();
    }
  });

  it("composes travel domain and guardrails into the travel preset shape", () => {
    const composed = composeLayeredPolicyPresetDocument("travel");
    expect(composed.name).toBe("travel-agent-v1");
    const tools = composed.tools as Record<string, Record<string, unknown>>;
    expect(tools["travel.book_hotel"]?.max_spend_cents).toBe(20000);
    expect(tools["travel.book_hotel"]?.evidence_preset).toBe("cost_and_completion");
    const intent = composed.intent as Record<string, unknown>;
    expect(intent.allowed_tools).toEqual(["travel.book_hotel"]);
    expect(intent.budget).toEqual({ currency: "usd", max_spend_usd: 200 });
  });
});
