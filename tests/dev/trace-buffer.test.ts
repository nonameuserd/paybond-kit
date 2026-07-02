import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  activateDevTraceCollector,
  appendDevTraceEvent,
  buildDevStartupBannerLines,
  devTraceStepsFromEvents,
  DEV_DEFAULT_PRESET,
  DEV_TRACE_DEFAULT_PORT,
  DEV_TRACE_FILE,
  devTraceUrl,
  finalizeDevTraceCollector,
  listDevTraceEvents,
  readDevTraceEventsFromDisk,
  recordSmokeTraceEvent,
  resolveDevTraceSink,
} from "../../src/dev/trace-buffer.js";

describe("dev trace buffer", () => {
  it("records smoke trace events with travel defaults shape", () => {
    const before = listDevTraceEvents().length;
    const event = recordSmokeTraceEvent({
      preset: DEV_DEFAULT_PRESET,
      bind: {
        run_id: "run-test-1",
        operation: "travel.book_hotel",
        intent_id: "intent-1",
        requested_spend_cents: 18_700,
      },
      execute: {
        evidence_submitted: true,
        sandbox_lifecycle_status: "released",
      },
      resultBody: { status: "completed", cost_cents: 18_700 },
    });
    expect(event.id).toBe("run-test-1");
    expect(event.preset).toBe("travel");
    expect(event.operation).toBe("travel.book_hotel");
    expect(event.authorized).toBe(true);
    expect(event.evidence_submitted).toBe(true);
    expect(listDevTraceEvents().length).toBe(before + 1);
    expect(listDevTraceEvents().at(-1)?.id).toBe("run-test-1");
  });

  it("builds startup banner lines for dev loop", () => {
    expect(buildDevStartupBannerLines()).toEqual([
      "✓ Sandbox capability (or: offline mock)",
      "✓ Settlement simulator",
      `✓ Trace dashboard → http://localhost:${DEV_TRACE_DEFAULT_PORT}`,
      "✓ Audit log → .paybond/dev-audit.jsonl",
    ]);
  });

  it("builds trace URLs with optional run id", () => {
    expect(devTraceUrl()).toBe(`http://localhost:${DEV_TRACE_DEFAULT_PORT}`);
    expect(devTraceUrl(9477, "run-test-1")).toBe("http://localhost:9477/runs/run-test-1");
  });

  it("drops oldest events after the ring buffer limit", () => {
    const start = listDevTraceEvents().length;
    for (let index = 0; index < 105; index += 1) {
      appendDevTraceEvent({
        id: `overflow-${index}`,
        recorded_at: new Date().toISOString(),
        preset: "travel",
        operation: "travel.book_hotel",
        authorized: true,
        evidence_submitted: true,
      });
    }
    const events = listDevTraceEvents();
    expect(events.length).toBeLessThanOrEqual(100);
    expect(events.length).toBe(Math.min(100, start + 105));
    expect(events[0]?.id).toMatch(/^overflow-/);
  });

  it("collects interceptor trace events into dashboard steps", () => {
    activateDevTraceCollector({ preset: "travel" });
    const sink = resolveDevTraceSink();
    expect(sink).toBeDefined();
    sink?.({
      type: "tool_selected",
      runId: "run-collector-1",
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      operation: "travel.book_hotel",
      recordedAt: "2026-07-01T12:00:00.000Z",
    });
    sink?.({
      type: "spend_authorized",
      runId: "run-collector-1",
      toolCallId: "call-1",
      operation: "travel.book_hotel",
      auditId: "audit-1",
      amountCents: 18_700,
      recordedAt: "2026-07-01T12:00:01.000Z",
    });
    sink?.({
      type: "tool_executed",
      runId: "run-collector-1",
      toolCallId: "call-1",
      operation: "travel.book_hotel",
      durationMs: 12,
      recordedAt: "2026-07-01T12:00:02.000Z",
    });
    sink?.({
      type: "evidence_submitted",
      runId: "run-collector-1",
      toolCallId: "call-1",
      operation: "travel.book_hotel",
      sandboxLifecycleStatus: "released",
      recordedAt: "2026-07-01T12:00:03.000Z",
    });

    const event = finalizeDevTraceCollector({ status: "completed", cost_cents: 18_700 });
    expect(event?.id).toBe("run-collector-1");
    expect(event?.steps?.map((step) => step.phase)).toEqual([
      "tool",
      "authorize",
      "result",
      "evidence",
      "result",
    ]);
    expect(devTraceStepsFromEvents(event?.trace_events ?? []).length).toBeGreaterThan(0);
  });

  it("persists trace events to .paybond/dev-trace.jsonl for cross-process dev trace", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-trace-disk-"));
    recordSmokeTraceEvent(
      {
        preset: DEV_DEFAULT_PRESET,
        bind: {
          run_id: "run-disk-1",
          operation: "travel.book_hotel",
          requested_spend_cents: 18_700,
        },
        execute: {
          evidence_submitted: true,
          sandbox_lifecycle_status: "released",
        },
        resultBody: { status: "completed", cost_cents: 18_700 },
      },
      cwd,
    );

    const fromDisk = readDevTraceEventsFromDisk(cwd);
    expect(fromDisk).toHaveLength(1);
    expect(fromDisk[0]?.id).toBe("run-disk-1");
    expect(fromDisk[0]?.steps?.map((step) => step.phase)).toEqual(
      expect.arrayContaining(["authorize", "evidence", "result"]),
    );
    expect(listDevTraceEvents(cwd).at(-1)?.id).toBe("run-disk-1");
    expect(existsSync(join(cwd, DEV_TRACE_FILE))).toBe(true);
  });
});
