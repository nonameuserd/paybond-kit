import { describe, expect, it, vi } from "vitest";
import { Paybond } from "../../src/index.js";
import { runCloudflareAgentsSandboxDemo } from "../../src/cloudflare-agents/sandbox-demo.js";
import {
  AGENT_SMOKE_INTENT,
  createAgentGatewayFetch,
  SANDBOX_RAW_KEY,
} from "../cli/agent-gateway-mock.js";

describe("runCloudflareAgentsSandboxDemo", () => {
  it("runs guarded AI SDK tool execute + auto-evidence without a live LLM", async () => {
    const fetch = createAgentGatewayFetch();
    vi.stubGlobal("fetch", fetch);

    const paybond = await Paybond.open({
      apiKey: SANDBOX_RAW_KEY,
      gatewayBaseUrl: "https://api.paybond.ai",
      expectedEnvironment: "sandbox",
    });

    try {
      const demo = await runCloudflareAgentsSandboxDemo({
        paybond,
        operation: "paid-tool",
        requestedSpendCents: 100,
        evidencePreset: "cost_and_completion",
      });

      expect(demo.authorization.allow).toBe(true);
      expect(demo.execute.tool_result).toEqual({
        status: "completed",
        cost_cents: 100,
      });
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
