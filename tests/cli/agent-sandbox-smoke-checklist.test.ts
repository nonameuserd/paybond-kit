import { describe, expect, it } from "vitest";

import { formatAgentSandboxSmokeChecklist } from "../../src/cli/agent-sandbox-smoke-checklist.js";
import type { GlobalOptions } from "../../src/cli/types.js";

const globals: GlobalOptions = {
  gateway: "https://api.paybond.ai",
  envFile: ".env.local",
  format: "table",
  color: "never",
  requestId: "test-request-id",
  yes: false,
  noOpen: false,
};

describe("formatAgentSandboxSmokeChecklist", () => {
  it("renders travel preset success steps", () => {
    const lines = formatAgentSandboxSmokeChecklist({
      presetId: "travel",
      bind: {
        intent_id: "intent-1",
        operation: "travel.book_hotel",
        completion_preset: "cost_and_completion",
        requested_spend_cents: 20000,
      },
      execute: {
        authorization: { allow: true },
        evidence: { submitted: true },
      },
      resultBody: { status: "completed", cost_cents: 18700 },
      globals,
    });

    expect(lines).toEqual([
      "✓ Policy loaded (travel)",
      "✓ Sandbox intent created",
      "✓ Tool call: travel.book_hotel",
      "✓ Spend authorized up to $200.00 (20,000 cents)",
      "✓ Reported cost $187.00 (18,700 cents)",
      "✓ Evidence validated (cost_and_completion)",
      "✓ Settlement simulated",
      "Success",
    ]);
  });

  it("uses policy file basename when preset id is omitted", () => {
    const lines = formatAgentSandboxSmokeChecklist({
      bind: {
        policy_file: "/tmp/paybond.policy.yaml",
        operation: "paid-tool",
      },
      execute: {
        authorization: { allow: true },
        evidence: { submitted: true },
      },
      resultBody: { cost_cents: 100 },
      globals,
    });

    expect(lines[0]).toBe("✓ Policy loaded (paybond.policy.yaml)");
  });
});
