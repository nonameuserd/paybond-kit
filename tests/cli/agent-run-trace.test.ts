import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  appendAgentRunTraceEvent,
  loadAgentRunTrace,
  loadAgentRunTraceIfExists,
} from "../../src/cli/agent/run-trace-store.js";
import { formatAgentRunTraceTable } from "../../src/cli/agent-run-trace-table.js";
import { devTraceStepsFromEvents } from "../../src/dev/trace-buffer.js";
import { defaultGlobalOptions } from "../../src/cli/globals.js";

describe("agent run trace store", () => {
  it("persists and reloads trace events for a run id", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-run-trace-"));
    const runId = "run-trace-1";
    const event = {
      type: "tool_selected" as const,
      runId,
      toolName: "paid-tool",
      toolCallId: "call-1",
      operation: "paid-tool",
      recordedAt: "2026-07-01T12:00:00.000Z",
    };
    await appendAgentRunTraceEvent(cwd, runId, event, "intent-1");
    const stored = await loadAgentRunTrace(cwd, runId);
    expect(stored.run_id).toBe(runId);
    expect(stored.intent_id).toBe("intent-1");
    expect(stored.trace_events).toHaveLength(1);
    expect(await loadAgentRunTraceIfExists(cwd, "missing")).toBeUndefined();
  });

  it("formats table lines from trace steps", () => {
    const events = [
      {
        type: "tool_selected" as const,
        runId: "run-1",
        toolName: "paid-tool",
        toolCallId: "call-1",
        operation: "paid-tool",
        recordedAt: "2026-07-01T12:00:00.000Z",
      },
      {
        type: "spend_authorized" as const,
        runId: "run-1",
        toolCallId: "call-1",
        operation: "paid-tool",
        auditId: "audit-1",
        amountCents: 100,
        recordedAt: "2026-07-01T12:00:01.000Z",
      },
    ];
    const lines = formatAgentRunTraceTable({
      runId: "run-1",
      intentId: "intent-1",
      steps: devTraceStepsFromEvents(events),
      globals: defaultGlobalOptions(),
    });
    expect(lines[0]).toBe("run_id: run-1");
    expect(lines.some((line) => line.includes("Tool call: paid-tool"))).toBe(true);
    expect(
      lines.some((line) =>
        line.includes("Paybond authorized up to $1.00 (100 cents)"),
      ),
    ).toBe(true);
  });
});
