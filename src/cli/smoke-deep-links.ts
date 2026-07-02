import { devTraceUrl } from "../dev/trace-buffer.js";
import { colorize, shouldUseColor } from "./color.js";
import type { GlobalOptions } from "./types.js";

const HARBOR_INTENT_UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const DEFAULT_LOCAL_PUBLIC_ORIGIN = "http://127.0.0.1:3000";

/** Deep links returned by `paybond agent sandbox smoke` for local trace and hosted replay. */
export type AgentSandboxSmokeDeepLinks = Readonly<{
  trace_url: string;
  console_url?: string;
  agent_trace_url?: string;
}>;

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, "");
}

function resolvePublicOrigin(): string {
  const configured =
    process.env.PAYBOND_PUBLIC_BASE_URL?.trim() ||
    process.env.PAYBOND_CONSOLE_BASE_URL?.trim();
  return stripTrailingSlashes(configured && configured.length > 0 ? configured : DEFAULT_LOCAL_PUBLIC_ORIGIN);
}

function resolveConsoleOrigin(): string {
  const configured =
    process.env.PAYBOND_CONSOLE_BASE_URL?.trim() ||
    process.env.PAYBOND_PUBLIC_BASE_URL?.trim();
  return stripTrailingSlashes(configured && configured.length > 0 ? configured : DEFAULT_LOCAL_PUBLIC_ORIGIN);
}

function harborIntentId(bind: Record<string, unknown>): string | undefined {
  const raw = bind.intent_id;
  if (typeof raw !== "string") {
    return undefined;
  }
  const trimmed = raw.trim();
  return HARBOR_INTENT_UUID.test(trimmed) ? trimmed : undefined;
}

/**
 * Builds trace, console dossier, and hosted agent-trace replay URLs for sandbox smoke JSON.
 */
export function buildAgentSandboxSmokeDeepLinks(input: {
  bind: Record<string, unknown>;
}): AgentSandboxSmokeDeepLinks {
  const runId = String(input.bind.run_id ?? "smoke-1");
  const links: AgentSandboxSmokeDeepLinks = {
    trace_url: devTraceUrl(undefined, runId),
  };

  const intentId = harborIntentId(input.bind);
  if (!intentId) {
    return links;
  }

  const consoleOrigin = resolveConsoleOrigin();
  const publicOrigin = resolvePublicOrigin();
  return {
    ...links,
    console_url: `${consoleOrigin}/console/operations/intents/${encodeURIComponent(intentId)}`,
    agent_trace_url: `${publicOrigin}/demo/agent-trace?intent=${encodeURIComponent(intentId)}`,
  };
}

/** Inserts trace/console/replay checklist lines before the trailing Success row. */
export function appendSmokeDeepLinkChecklistLines(
  checklistLines: ReadonlyArray<string>,
  deepLinks: AgentSandboxSmokeDeepLinks,
  globals: GlobalOptions,
): string[] {
  const useColor = shouldUseColor(globals);
  const mark = (line: string): string => colorize(line, "green", useColor);
  const linkLines = [
    mark(`✓ Trace → ${deepLinks.trace_url}`),
    ...(deepLinks.console_url ? [mark(`✓ Console → ${deepLinks.console_url}`)] : []),
    ...(deepLinks.agent_trace_url ? [mark(`✓ Replay → ${deepLinks.agent_trace_url}`)] : []),
  ];

  if (checklistLines.length === 0) {
    return linkLines;
  }

  const last = checklistLines.at(-1);
  if (last === "Success" || last === mark("Success")) {
    return [...checklistLines.slice(0, -1), ...linkLines, last];
  }
  return [...checklistLines, ...linkLines];
}
