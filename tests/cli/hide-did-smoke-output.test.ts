import { describe, expect, it } from "vitest";

import { formatAgentSandboxSmokeChecklist } from "../../src/cli/agent-sandbox-smoke-checklist.js";
import type { GlobalOptions } from "../../src/cli/types.js";

const globals: GlobalOptions = {
  gateway: "https://api.paybond.ai",
  envFile: ".env.local",
  format: "table",
  color: "never",
};

const DID_VOCABULARY = [
  /\bdid:/i,
  /\bDID\b/,
  /payee[_-]did/i,
  /principal[_-]did/i,
  /signing[_\s-]seed/i,
  /recognition proof/i,
] as const;

describe("sandbox smoke CLI output hides DID vocabulary", () => {
  it("checklist lines contain no DID or signing terms", () => {
    const lines = formatAgentSandboxSmokeChecklist({
      presetId: "travel",
      bind: {
        intent_id: "intent-1",
        operation: "travel.book_hotel",
        completion_preset: "cost_and_completion",
        requested_spend_cents: 18700,
      },
      execute: {
        authorization: { allow: true },
        evidence: { submitted: true },
      },
      resultBody: { status: "completed", cost_cents: 18700 },
      globals,
    });

    const output = lines.join("\n");
    for (const pattern of DID_VOCABULARY) {
      expect(output, `smoke checklist must not match ${pattern}`).not.toMatch(pattern);
    }
  });
});
