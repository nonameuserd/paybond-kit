import { describe, expect, it, vi, afterEach } from "vitest";

import {
  appendSmokeDeepLinkChecklistLines,
  buildAgentSandboxSmokeDeepLinks,
} from "../../src/cli/smoke-deep-links.js";

describe("buildAgentSandboxSmokeDeepLinks", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("returns local trace url and hosted links for sandbox smoke bind output", () => {
    vi.stubEnv("PAYBOND_PUBLIC_BASE_URL", "https://paybond.ai");
    vi.stubEnv("PAYBOND_CONSOLE_BASE_URL", "https://console.paybond.ai");

    const links = buildAgentSandboxSmokeDeepLinks({
      bind: {
        run_id: "smoke-travel-1",
        intent_id: "00000000-0000-4000-8000-000000000001",
      },
    });

    expect(links.trace_url).toBe("http://localhost:9477/runs/smoke-travel-1");
    expect(links.console_url).toBe(
      "https://console.paybond.ai/console/operations/intents/00000000-0000-4000-8000-000000000001",
    );
    expect(links.agent_trace_url).toBe(
      "https://paybond.ai/demo/agent-trace?intent=00000000-0000-4000-8000-000000000001",
    );
  });

  it("omits console and replay links when intent id is missing", () => {
    const links = buildAgentSandboxSmokeDeepLinks({
      bind: { run_id: "smoke-1" },
    });
    expect(links.trace_url).toBe("http://localhost:9477/runs/smoke-1");
    expect(links.console_url).toBeUndefined();
    expect(links.agent_trace_url).toBeUndefined();
  });
});

describe("appendSmokeDeepLinkChecklistLines", () => {
  it("inserts trace and console lines before Success", () => {
    const lines = appendSmokeDeepLinkChecklistLines(
      ["✓ Policy loaded (travel)", "Success"],
      {
        trace_url: "http://localhost:9477/runs/smoke-1",
        console_url: "https://console.paybond.ai/console/operations/intents/intent-1",
        agent_trace_url: "https://paybond.ai/demo/agent-trace?intent=intent-1",
      },
      { color: "never", format: "table" },
    );
    expect(lines).toEqual([
      "✓ Policy loaded (travel)",
      "✓ Trace → http://localhost:9477/runs/smoke-1",
      "✓ Console → https://console.paybond.ai/console/operations/intents/intent-1",
      "✓ Replay → https://paybond.ai/demo/agent-trace?intent=intent-1",
      "Success",
    ]);
  });
});
