import { describe, expect, it, vi } from "vitest";
import { Paybond } from "../../src/index.js";
import { runVercelAiSandboxDemo } from "../../src/vercel-ai/sandbox-demo.js";
import {
  AGENT_SMOKE_INTENT,
  createAgentGatewayFetch,
  SANDBOX_RAW_KEY,
} from "../cli/agent-gateway-mock.js";

describe("runVercelAiSandboxDemo", () => {
  it("runs toolApproval + wrapped execute + auto-evidence without a live model", async () => {
    const fetch = createAgentGatewayFetch();
    vi.stubGlobal("fetch", fetch);

    const paybond = await Paybond.open({
      apiKey: SANDBOX_RAW_KEY,
      gatewayBaseUrl: "https://api.paybond.ai",
      expectedEnvironment: "sandbox",
    });

    try {
      const demo = await runVercelAiSandboxDemo({
        paybond,
        operation: "paid-tool",
        requestedSpendCents: 100,
        evidencePreset: "cost_and_completion",
      });

      expect(demo.tool_approval).toBe("approved");
      expect(demo.generate_text.text).toContain("paid tool completed");
      expect(demo.generate_text.tool_calls).toBeGreaterThan(0);
      expect(demo.execute.tool_result).toBeTruthy();
      expect(demo.bind.intent_id).toBe(AGENT_SMOKE_INTENT);

      const evidenceCalls = fetch.mock.calls.filter(([input]) =>
        String(input).includes(`/v1/sandbox/guardrails/${AGENT_SMOKE_INTENT}/evidence`),
      );
      expect(evidenceCalls.length).toBeGreaterThan(0);
    } finally {
      await paybond.aclose();
      vi.unstubAllGlobals();
    }
  });
});
