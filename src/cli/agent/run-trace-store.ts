import { mkdirSync, readFileSync } from "node:fs";
import { mkdir, readFile } from "node:fs/promises";

import { writeAtomicFile, writeAtomicFileAsync } from "../automation.js";
import { CliError } from "../types.js";

import type { PaybondTraceEvent, PaybondTraceSink } from "../../agent/types.js";
import type { PaybondAgentRun } from "../../agent/run.js";
import { type AgentRunUpsertInput } from "../../agent/gateway-trace-reporter.js";

type GatewayAgentRunHost = Readonly<{
  harbor: {
    createAgentRunTraceReporter(runId: string): {
      registerRun(input: AgentRunUpsertInput): void;
      reportEvent(event: PaybondTraceEvent): void;
    };
  };
}>;
import { agentRunFilePath, agentRunsDir } from "./run-store.js";

export type PersistedAgentRunTrace = {
  run_id: string;
  intent_id: string;
  trace_events: PaybondTraceEvent[];
  updated_at: string;
};

export function agentRunTraceFilePath(cwd: string, runId: string): string {
  return `${agentRunFilePath(cwd, runId).replace(/\.json$/, "")}.trace.json`;
}

export function loadAgentRunTraceIfExistsSync(
  cwd: string,
  runId: string,
): PersistedAgentRunTrace | undefined {
  const path = agentRunTraceFilePath(cwd, runId);
  try {
    const raw = readFileSync(path, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new CliError(`invalid run trace at ${path}`, {
        category: "validation",
        code: "cli.agent.invalid_run_trace",
      });
    }
    return parsed as PersistedAgentRunTrace;
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return undefined;
    }
    throw err;
  }
}

export async function loadAgentRunTraceIfExists(
  cwd: string,
  runId: string,
): Promise<PersistedAgentRunTrace | undefined> {
  const path = agentRunTraceFilePath(cwd, runId);
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return undefined;
    }
    throw err;
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CliError(`invalid run trace at ${path}`, {
      category: "validation",
      code: "cli.agent.invalid_run_trace",
    });
  }
  return parsed as PersistedAgentRunTrace;
}

export async function loadAgentRunTrace(cwd: string, runId: string): Promise<PersistedAgentRunTrace> {
  const stored = await loadAgentRunTraceIfExists(cwd, runId);
  if (!stored) {
    throw new CliError(
      `no trace events for run "${runId}"; run paybond agent tool execute first`,
      {
        category: "validation",
        code: "cli.agent.trace_not_found",
        exitCode: 1,
        details: { run_id: runId, path: agentRunTraceFilePath(cwd, runId) },
      },
    );
  }
  return stored;
}

export function appendAgentRunTraceEventSync(
  cwd: string,
  runId: string,
  event: PaybondTraceEvent,
  intentId?: string,
): void {
  const existing = loadAgentRunTraceIfExistsSync(cwd, runId);
  const traceEvents = [...(existing?.trace_events ?? []), event];
  persistAgentRunTraceEventsSync(
    cwd,
    runId,
    traceEvents,
    intentId ?? existing?.intent_id ?? "",
  );
}

export async function appendAgentRunTraceEvent(
  cwd: string,
  runId: string,
  event: PaybondTraceEvent,
  intentId?: string,
): Promise<void> {
  const existing = await loadAgentRunTraceIfExists(cwd, runId);
  const traceEvents = [...(existing?.trace_events ?? []), event];
  await persistAgentRunTraceEvents(cwd, runId, traceEvents, intentId ?? existing?.intent_id ?? "");
}

export function persistAgentRunTraceEventsSync(
  cwd: string,
  runId: string,
  events: readonly PaybondTraceEvent[],
  intentId = "",
): string {
  const path = agentRunTraceFilePath(cwd, runId);
  mkdirSync(agentRunsDir(cwd), { recursive: true });
  const payload: PersistedAgentRunTrace = {
    run_id: runId.trim(),
    intent_id: intentId,
    trace_events: [...events],
    updated_at: new Date().toISOString(),
  };
  writeAtomicFile(path, `${JSON.stringify(payload, null, 2)}\n`, 0o600);
  return path;
}

export async function persistAgentRunTraceEvents(
  cwd: string,
  runId: string,
  events: readonly PaybondTraceEvent[],
  intentId = "",
): Promise<string> {
  const path = agentRunTraceFilePath(cwd, runId);
  await mkdir(agentRunsDir(cwd), { recursive: true });
  const payload: PersistedAgentRunTrace = {
    run_id: runId.trim(),
    intent_id: intentId,
    trace_events: [...events],
    updated_at: new Date().toISOString(),
  };
  await writeAtomicFileAsync(path, `${JSON.stringify(payload, null, 2)}\n`, 0o600);
  return path;
}

/** Composite sink that persists per-run trace events and optionally forwards to another sink. */
export function createAgentRunTraceSink(
  cwd: string,
  runId: string,
  options?: { intentId?: string; forward?: PaybondTraceSink },
): PaybondTraceSink {
  return (event) => {
    appendAgentRunTraceEventSync(cwd, runId, event, options?.intentId);
    options?.forward?.(event);
  };
}

/** Forward middleware trace events to Gateway when a tenant session is available. */
export function createGatewayAgentRunTraceSink(
  paybond: GatewayAgentRunHost,
  runId: string,
): PaybondTraceSink {
  const reporter = paybond.harbor.createAgentRunTraceReporter(runId);
  return (event) => {
    reporter.reportEvent(event);
  };
}

/** Register run metadata on Gateway after a successful bind. */
export function registerGatewayAgentRun(
  paybond: GatewayAgentRunHost,
  run: PaybondAgentRun,
  options?: { completionPreset?: string },
): void {
  const meta: AgentRunUpsertInput = {
    intentId: run.intentId,
    operation: run.binding.sandbox?.operation ?? run.allowedTools[0] ?? "",
    sandbox: Boolean(run.binding.sandbox),
    allowedTools: run.allowedTools,
    completionPreset: options?.completionPreset,
  };
  paybond.harbor.createAgentRunTraceReporter(run.runId).registerRun(meta);
}

/** Composite sink: local run trace file, optional dev collector, optional Gateway reporter. */
export function resolveAgentRunTraceSink(
  cwd: string,
  runId: string,
  intentId?: string,
  forward?: PaybondTraceSink,
  gateway?: PaybondTraceSink,
): PaybondTraceSink {
  const sinks: PaybondTraceSink[] = [];
  if (gateway) {
    sinks.push(gateway);
  }
  if (forward) {
    sinks.push(forward);
  }
  const composed =
    sinks.length === 0
      ? undefined
      : sinks.length === 1
        ? sinks[0]
        : (event: PaybondTraceEvent) => {
            for (const sink of sinks) {
              sink(event);
            }
          };
  return createAgentRunTraceSink(cwd, runId, {
    intentId,
    forward: composed,
  });
}
