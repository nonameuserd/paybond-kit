import { describe, expect, it, vi } from "vitest";

import { Paybond } from "../../src/index.js";
import {
  AGENT_SMOKE_INTENT,
  createAgentGatewayFetch,
  SANDBOX_RAW_KEY,
} from "../cli/agent-gateway-mock.js";

vi.mock("node:module", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:module")>();
  return {
    ...actual,
    createRequire: vi.fn((url: string) => {
      const require = actual.createRequire(url);
      return ((id: string) => {
        if (id === "@google/adk") {
          return {
            FunctionTool: class FakeFunctionTool {
              name: string;
              description: string;
              execute: (input: unknown) => unknown | Promise<unknown>;

              constructor(options: {
                name?: string;
                description: string;
                execute: (input: unknown) => unknown | Promise<unknown>;
              }) {
                this.name = options.name ?? "tool";
                this.description = options.description;
                this.execute = options.execute;
              }
            },
          };
        }
        return require(id);
      }) as NodeRequire;
    }),
  };
});

const { runGoogleAdkSandboxDemo } = await import("../../src/google-adk/sandbox-demo.js");

describe("runGoogleAdkSandboxDemo", () => {
  it("runs guarded FunctionTool execute + auto-evidence without a live LLM", async () => {
    const fetch = createAgentGatewayFetch();
    vi.stubGlobal("fetch", fetch);

    const paybond = await Paybond.open({
      apiKey: SANDBOX_RAW_KEY,
      gatewayBaseUrl: "https://api.paybond.ai",
      expectedEnvironment: "sandbox",
    });

    try {
      const demo = await runGoogleAdkSandboxDemo({
        paybond,
        operation: "paid-tool",
        requestedSpendCents: 100,
        evidencePreset: "cost_and_completion",
      });

      expect(demo.authorization.allow).toBe(true);
      expect(demo.tool_result).toEqual({
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
