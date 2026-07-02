import { appendFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { PaybondTraceEvent, PaybondTraceSink } from "../agent/types.js";

export const DEV_TRACE_DEFAULT_PORT = 9477;
export const DEV_AUDIT_DIR = ".paybond";
export const DEV_AUDIT_FILE = join(DEV_AUDIT_DIR, "dev-audit.jsonl");
export const DEV_TRACE_FILE = join(DEV_AUDIT_DIR, "dev-trace.jsonl");
export const DEV_DEFAULT_POLICY_FILE = "paybond.policy.yaml";
export const DEV_DEFAULT_PRESET = "travel";

const MAX_TRACE_EVENTS = 100;

export type DevTraceStepPhase = "agent" | "tool" | "authorize" | "evidence" | "result";

export type DevTraceStep = {
  phase: DevTraceStepPhase;
  label: string;
  recorded_at: string;
  detail?: Record<string, unknown>;
};

export type DevTraceEvent = {
  id: string;
  recorded_at: string;
  preset: string;
  operation: string;
  intent_id?: string;
  run_id?: string;
  requested_spend_cents?: number;
  authorized: boolean;
  evidence_submitted: boolean;
  sandbox_lifecycle_status?: string;
  result_status?: string;
  cost_cents?: number;
  steps?: DevTraceStep[];
  trace_events?: PaybondTraceEvent[];
};

const traceEvents: DevTraceEvent[] = [];

/** Read persisted dev trace events from `.paybond/dev-trace.jsonl`. */
export function readDevTraceEventsFromDisk(cwd: string): DevTraceEvent[] {
  const path = join(cwd, DEV_TRACE_FILE);
  if (!existsSync(path)) {
    return [];
  }
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as DevTraceEvent);
}

function mergeDevTraceEvents(
  fromDisk: readonly DevTraceEvent[],
  fromMemory: readonly DevTraceEvent[],
): DevTraceEvent[] {
  const byId = new Map<string, DevTraceEvent>();
  for (const event of fromDisk) {
    byId.set(event.id, event);
  }
  for (const event of fromMemory) {
    byId.set(event.id, event);
  }
  return [...byId.values()].sort((left, right) => left.recorded_at.localeCompare(right.recorded_at));
}

/** List dev trace events from disk (when `cwd` is set) and the in-process ring buffer. */
export function listDevTraceEvents(cwd?: string): DevTraceEvent[] {
  const memory = [...traceEvents];
  if (!cwd) {
    return memory;
  }
  return mergeDevTraceEvents(readDevTraceEventsFromDisk(cwd), memory);
}

function trimDevTraceFileSync(path: string): void {
  if (!existsSync(path)) {
    return;
  }
  const lines = readFileSync(path, "utf8").split("\n").filter((line) => line.trim().length > 0);
  if (lines.length <= MAX_TRACE_EVENTS) {
    return;
  }
  writeFileSync(path, `${lines.slice(-MAX_TRACE_EVENTS).join("\n")}\n`, "utf8");
}

function persistDevTraceEventSync(cwd: string, event: DevTraceEvent): void {
  const dir = join(cwd, DEV_AUDIT_DIR);
  mkdirSync(dir, { recursive: true });
  const path = join(cwd, DEV_TRACE_FILE);
  appendFileSync(path, `${JSON.stringify(event)}\n`, "utf8");
  trimDevTraceFileSync(path);
}

/** Find the most recent in-memory dev trace event for a run id (same-process fallback). */
export function findDevTraceEventForRun(runId: string): DevTraceEvent | undefined {
  const normalized = runId.trim();
  for (let index = traceEvents.length - 1; index >= 0; index -= 1) {
    const event = traceEvents[index];
    if (event?.run_id === normalized || event?.id === normalized) {
      return event;
    }
  }
  return undefined;
}

export function appendDevTraceEvent(event: DevTraceEvent, cwd?: string): void {
  traceEvents.push(event);
  while (traceEvents.length > MAX_TRACE_EVENTS) {
    traceEvents.shift();
  }
  if (cwd) {
    persistDevTraceEventSync(cwd, event);
  }
}

export function devTraceUrl(port = DEV_TRACE_DEFAULT_PORT, runId?: string): string {
  const base = `http://localhost:${port}`;
  return runId ? `${base}/runs/${encodeURIComponent(runId)}` : base;
}

/** User-facing startup banner lines for `paybond dev loop`. */
export function buildDevStartupBannerLines(port = DEV_TRACE_DEFAULT_PORT): string[] {
  return [
    "✓ Sandbox capability (or: offline mock)",
    "✓ Settlement simulator",
    `✓ Trace dashboard → ${devTraceUrl(port)}`,
    `✓ Audit log → ${DEV_AUDIT_FILE}`,
  ];
}

export function devTraceHasCredentials(): boolean {
  return Boolean(process.env.PAYBOND_API_KEY?.trim());
}

export async function appendDevAuditLog(
  cwd: string,
  entry: Record<string, unknown>,
): Promise<string> {
  const dir = join(cwd, DEV_AUDIT_DIR);
  await mkdir(dir, { recursive: true });
  const path = join(cwd, DEV_AUDIT_FILE);
  await appendFile(path, `${JSON.stringify(entry)}\n`, "utf8");
  return path;
}

export function devTraceStepsFromEvents(events: readonly PaybondTraceEvent[]): DevTraceStep[] {
  const steps: DevTraceStep[] = [];

  for (const event of events) {
    switch (event.type) {
      case "tool_selected":
        steps.push({
          phase: "tool",
          label: `Tool call: ${event.toolName}`,
          recorded_at: event.recordedAt,
          detail: { operation: event.operation, tool_call_id: event.toolCallId },
        });
        break;
      case "spend_authorized":
        steps.push({
          phase: "authorize",
          label: `Paybond approved $${(event.amountCents / 100).toFixed(2)}`,
          recorded_at: event.recordedAt,
          detail: {
            audit_id: event.auditId,
            decision_id: event.decisionId,
            amount_cents: event.amountCents,
          },
        });
        break;
      case "spend_denied":
        steps.push({
          phase: "authorize",
          label: `Spend denied: ${event.message}`,
          recorded_at: event.recordedAt,
          detail: { audit_id: event.auditId, code: event.code },
        });
        break;
      case "approval_required":
        steps.push({
          phase: "authorize",
          label: `Approval required: ${event.message}`,
          recorded_at: event.recordedAt,
          detail: { audit_id: event.auditId, code: event.code },
        });
        break;
      case "tool_executed":
        steps.push({
          phase: "result",
          label: `Tool executed (${event.durationMs}ms)`,
          recorded_at: event.recordedAt,
          detail: { duration_ms: event.durationMs },
        });
        break;
      case "evidence_submitted":
        steps.push({
          phase: "evidence",
          label: event.predicatePassed === false ? "Evidence submitted (predicate failed)" : "Evidence submitted",
          recorded_at: event.recordedAt,
          detail: {
            evidence_id: event.evidenceId,
            preset_id: event.presetId,
            evidence_preset: event.evidencePreset ?? event.presetId,
            sandbox_lifecycle_status: event.sandboxLifecycleStatus,
            predicate_passed: event.predicatePassed,
          },
        });
        if (event.sandboxLifecycleStatus) {
          steps.push({
            phase: "result",
            label: `Settlement: ${event.sandboxLifecycleStatus}`,
            recorded_at: event.recordedAt,
            detail: { sandbox_lifecycle_status: event.sandboxLifecycleStatus },
          });
        }
        break;
      case "spend_finalized":
        if (event.status === "consumed") {
          steps.push({
            phase: "result",
            label: "Spend authorization consumed",
            recorded_at: event.recordedAt,
            detail: { status: event.status },
          });
        }
        break;
      default:
        break;
    }
  }

  return steps;
}

function summarizeTraceEvents(events: readonly PaybondTraceEvent[]): {
  operation: string;
  runId: string;
  requestedSpendCents?: number;
  authorized: boolean;
  evidenceSubmitted: boolean;
  sandboxLifecycleStatus?: string;
} {
  const toolSelected = events.find((event) => event.type === "tool_selected");
  const spendAuthorized = events.find((event) => event.type === "spend_authorized");
  const evidenceSubmitted = events.find((event) => event.type === "evidence_submitted");
  const spendDenied = events.some(
    (event) => event.type === "spend_denied" || event.type === "approval_required",
  );

  return {
    operation: toolSelected?.operation ?? spendAuthorized?.operation ?? "",
    runId: toolSelected?.runId ?? spendAuthorized?.runId ?? `trace-${Date.now()}`,
    requestedSpendCents: spendAuthorized?.amountCents,
    authorized: Boolean(spendAuthorized) && !spendDenied,
    evidenceSubmitted: Boolean(evidenceSubmitted),
    sandboxLifecycleStatus: evidenceSubmitted?.sandboxLifecycleStatus,
  };
}

class DevTraceCollector {
  private readonly events: PaybondTraceEvent[] = [];

  constructor(private readonly options: { preset: string; intentId?: string }) {}

  readonly sink: PaybondTraceSink = (event) => {
    this.events.push(event);
  };

  finalize(resultBody?: Record<string, unknown>, cwd?: string): DevTraceEvent | undefined {
    if (this.events.length === 0) {
      return undefined;
    }
    const summary = summarizeTraceEvents(this.events);
    const event: DevTraceEvent = {
      id: summary.runId,
      recorded_at: this.events.at(-1)?.recordedAt ?? new Date().toISOString(),
      preset: this.options.preset,
      operation: summary.operation,
      intent_id: this.options.intentId,
      run_id: summary.runId,
      requested_spend_cents: summary.requestedSpendCents,
      authorized: summary.authorized,
      evidence_submitted: summary.evidenceSubmitted,
      sandbox_lifecycle_status: summary.sandboxLifecycleStatus,
      result_status: typeof resultBody?.status === "string" ? resultBody.status : undefined,
      cost_cents: typeof resultBody?.cost_cents === "number" ? resultBody.cost_cents : undefined,
      steps: devTraceStepsFromEvents(this.events),
      trace_events: [...this.events],
    };
    appendDevTraceEvent(event, cwd);
    return event;
  }
}

let activeDevTraceCollector: DevTraceCollector | undefined;
let activeDevTraceCollectorCwd: string | undefined;

/** Reset in-memory dev trace state (tests and local dashboard restarts). */
export function clearDevTraceEvents(): void {
  traceEvents.length = 0;
  activeDevTraceCollector = undefined;
  activeDevTraceCollectorCwd = undefined;
}

/** Activate an in-process dev trace collector for the next bind/execute cycle. */
export function activateDevTraceCollector(options: {
  preset: string;
  intentId?: string;
  cwd?: string;
}): void {
  activeDevTraceCollector = new DevTraceCollector(options);
  activeDevTraceCollectorCwd = options.cwd;
}

/** Resolve the active dev trace sink for {@link PaybondAgentRun.bind}. */
export function resolveDevTraceSink(): PaybondTraceSink | undefined {
  return activeDevTraceCollector?.sink;
}

/** Finalize and persist the active dev trace collector as a dashboard event. */
export function finalizeDevTraceCollector(
  resultBody?: Record<string, unknown>,
  cwd?: string,
): DevTraceEvent | undefined {
  const event = activeDevTraceCollector?.finalize(resultBody, cwd ?? activeDevTraceCollectorCwd);
  activeDevTraceCollector = undefined;
  activeDevTraceCollectorCwd = undefined;
  return event;
}

export function recordSmokeTraceEvent(
  input: {
    preset: string;
    bind: Record<string, unknown>;
    execute: Record<string, unknown>;
    resultBody: Record<string, unknown>;
  },
  cwd?: string,
): DevTraceEvent {
  const runId = String(input.bind.run_id ?? "smoke-1");
  const event: DevTraceEvent = {
    id: runId,
    recorded_at: new Date().toISOString(),
    preset: input.preset,
    operation: String(input.bind.operation ?? ""),
    intent_id: typeof input.bind.intent_id === "string" ? input.bind.intent_id : undefined,
    run_id: runId,
    requested_spend_cents:
      typeof input.bind.requested_spend_cents === "number"
        ? input.bind.requested_spend_cents
        : undefined,
    authorized: true,
    evidence_submitted: Boolean(input.execute.evidence_submitted ?? input.execute.evidence),
    sandbox_lifecycle_status:
      typeof input.execute.sandbox_lifecycle_status === "string"
        ? input.execute.sandbox_lifecycle_status
        : typeof input.bind.sandbox_lifecycle_status === "string"
          ? input.bind.sandbox_lifecycle_status
          : undefined,
    result_status: typeof input.resultBody.status === "string" ? input.resultBody.status : undefined,
    cost_cents:
      typeof input.resultBody.cost_cents === "number" ? input.resultBody.cost_cents : undefined,
    steps: devTraceStepsFromEvents([
      {
        type: "tool_selected",
        runId,
        toolName: String(input.bind.operation ?? "tool"),
        toolCallId: "smoke-1",
        operation: String(input.bind.operation ?? ""),
        recordedAt: new Date().toISOString(),
      },
      {
        type: "spend_authorized",
        runId,
        toolCallId: "smoke-1",
        operation: String(input.bind.operation ?? ""),
        auditId: "smoke",
        amountCents:
          typeof input.bind.requested_spend_cents === "number"
            ? input.bind.requested_spend_cents
            : 0,
        recordedAt: new Date().toISOString(),
      },
      {
        type: "tool_executed",
        runId,
        toolCallId: "smoke-1",
        operation: String(input.bind.operation ?? ""),
        durationMs: 0,
        recordedAt: new Date().toISOString(),
      },
      ...(input.execute.evidence_submitted ?? input.execute.evidence
        ? [
            {
              type: "evidence_submitted" as const,
              runId,
              toolCallId: "smoke-1",
              operation: String(input.bind.operation ?? ""),
              evidenceId: `evidence:${String(input.bind.intent_id ?? "smoke")}:smoke-1`,
              presetId: input.preset,
              evidencePreset: input.preset,
              sandboxLifecycleStatus:
                typeof input.execute.sandbox_lifecycle_status === "string"
                  ? input.execute.sandbox_lifecycle_status
                  : undefined,
              recordedAt: new Date().toISOString(),
            },
          ]
        : []),
    ]),
  };
  appendDevTraceEvent(event, cwd);
  return event;
}
