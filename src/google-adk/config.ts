import { createRequire } from "node:module";

import {
  PaybondAutoEvidenceSubmitError,
  PaybondUnregisteredSideEffectingToolError,
} from "../agent/types.js";
import type { PaybondAgentRun } from "../agent/run.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../index.js";

type GoogleAdkModule = {
  FunctionTool: new (options: {
    name?: string;
    description: string;
    parameters?: unknown;
    execute: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;
    isLongRunning?: boolean;
  }) => GoogleAdkFunctionToolLike;
  isFunctionTool?: (value: unknown) => boolean;
};

/** Minimal Google ADK FunctionTool shape used by the Paybond wrap helpers. */
export type GoogleAdkFunctionToolLike = {
  name: string;
  description: string;
  isLongRunning?: boolean;
  execute?: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;
  parameters?: unknown;
  runAsync?: (req: { args: unknown; toolContext?: unknown }) => Promise<unknown>;
};

/** Google ADK runner config: guarded tools plus incremental `wrapTool`. */
export type PaybondGoogleAdkConfig = {
  tools: GoogleAdkFunctionToolLike[];
  wrapTool: (tool: GoogleAdkFunctionToolLike | unknown) => GoogleAdkFunctionToolLike;
};

let cachedGoogleAdk: GoogleAdkModule | undefined;

/**
 * Lazily resolve the optional `@google/adk` peer dependency.
 *
 * Importing this module must not require the peer to be installed.
 */
function loadGoogleAdk(): GoogleAdkModule {
  if (cachedGoogleAdk === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedGoogleAdk = require("@google/adk") as GoogleAdkModule;
    } catch (err) {
      throw new Error(
        'The Google ADK integration requires the optional peer dependency "@google/adk"; install it with: npm install @google/adk',
        { cause: err },
      );
    }
  }
  return cachedGoogleAdk;
}

/** Return true when the optional `@google/adk` peer is importable. */
export function googleAdkRuntimeAvailable(): boolean {
  try {
    loadGoogleAdk();
    return true;
  } catch {
    return false;
  }
}

function isGoogleAdkFunctionTool(value: unknown): value is GoogleAdkFunctionToolLike {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.name !== "string" || !record.name.trim()) {
    return false;
  }
  if (typeof record.execute === "function") {
    return true;
  }
  try {
    const mod = loadGoogleAdk();
    if (typeof mod.isFunctionTool === "function" && mod.isFunctionTool(value)) {
      return true;
    }
  } catch {
    // Peer missing — fall through to duck-type check.
  }
  return typeof record.runAsync === "function";
}

function resolveToolExecute(
  tool: GoogleAdkFunctionToolLike,
): (input: unknown, toolContext?: unknown) => unknown | Promise<unknown> {
  if (typeof tool.execute === "function") {
    return tool.execute.bind(tool);
  }
  if (typeof tool.runAsync === "function") {
    const runAsync = tool.runAsync.bind(tool);
    return async (input: unknown, toolContext?: unknown) =>
      runAsync({ args: input as Record<string, unknown>, toolContext });
  }
  throw new TypeError(
    "each Google ADK tool must expose an execute callback or runAsync method",
  );
}

function resolveToolCallId(toolContext: unknown, fallback: string): string {
  if (typeof toolContext === "object" && toolContext !== null) {
    const record = toolContext as Record<string, unknown>;
    for (const key of ["functionCallId", "function_call_id", "toolCallId"] as const) {
      const value = record[key];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
  }
  return fallback;
}

function paybondErrorMessage(err: unknown): string {
  if (err instanceof PaybondUnregisteredSideEffectingToolError) {
    return `Paybond capability denied: unregistered side-effecting tool (${err.message})`;
  }
  if (err instanceof PaybondSpendApprovalRequiredError) {
    const decisionId = err.result.decisionId;
    const suffix = decisionId ? ` (decision_id=${decisionId})` : "";
    const msg = err.result.message ?? err.result.code ?? "approval required";
    return `Paybond capability approval required: ${msg}${suffix}`;
  }
  if (err instanceof PaybondSpendDeniedError) {
    const msg = err.result.message ?? err.result.code ?? "capability denied";
    return `Paybond capability denied: ${msg}`;
  }
  if (err instanceof PaybondAutoEvidenceSubmitError) {
    return `Paybond evidence submit failed: ${err.message}`;
  }
  return err instanceof Error ? err.message : String(err);
}

function rebuildFunctionTool(options: {
  name: string;
  description: string;
  parameters?: unknown;
  execute: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;
  isLongRunning?: boolean;
}): GoogleAdkFunctionToolLike {
  const { FunctionTool } = loadGoogleAdk();
  return new FunctionTool(options);
}

function wrapGoogleAdkTool(
  run: PaybondAgentRun,
  tool: GoogleAdkFunctionToolLike,
): GoogleAdkFunctionToolLike {
  const toolName = tool.name.trim();
  if (!run.registry.isSideEffecting(toolName)) {
    return tool;
  }

  const originalExecute = resolveToolExecute(tool);

  const guardedExecute = async (
    input: unknown,
    toolContext?: unknown,
  ): Promise<unknown> => {
    const toolCallId = resolveToolCallId(
      toolContext,
      globalThis.crypto.randomUUID(),
    );
    try {
      const wrapped = await run.interceptor.wrapExecute({
        toolName,
        toolCallId,
        arguments: input,
        approvalToken: run.getApprovalToken(toolCallId),
        execute: async () => originalExecute(input, toolContext),
      });
      return wrapped.toolResult;
    } catch (err) {
      if (err instanceof PaybondUnregisteredSideEffectingToolError) {
        throw err;
      }
      if (
        err instanceof PaybondSpendApprovalRequiredError ||
        err instanceof PaybondSpendDeniedError ||
        err instanceof PaybondAutoEvidenceSubmitError
      ) {
        // Clear Paybond message so the ADK agent loop surfaces deny/hold/evidence failures.
        throw new Error(paybondErrorMessage(err), { cause: err });
      }
      throw err;
    }
  };

  return rebuildFunctionTool({
    name: toolName,
    description: tool.description || `Tool ${toolName}`,
    parameters: tool.parameters,
    execute: guardedExecute,
    isLongRunning: tool.isLongRunning,
  });
}

function normalizeGoogleAdkTools(
  tools: unknown[],
): GoogleAdkFunctionToolLike[] {
  if (!Array.isArray(tools)) {
    throw new TypeError(
      "google-adk framework tools must be a sequence of FunctionTool instances",
    );
  }
  return tools.map((tool) => {
    if (!isGoogleAdkFunctionTool(tool)) {
      throw new TypeError(
        "each google-adk tool must be a FunctionTool instance with name and execute/runAsync",
      );
    }
    return tool;
  });
}

/**
 * Wrap Google ADK `FunctionTool` instances with Paybond middleware.
 *
 * Returns guarded tools plus a `wrapTool` helper for incremental wiring.
 * Prefer `new LlmAgent({ tools: config.tools })` with pre-wrapped tools.
 *
 * Tenant isolation: wrap uses only authenticated `PaybondAgentRun` context —
 * never invent tenant IDs from ADK session state or agent names.
 */
export function createPaybondGoogleAdkConfig(
  run: PaybondAgentRun,
  tools: unknown[],
): PaybondGoogleAdkConfig {
  loadGoogleAdk();
  const normalized = normalizeGoogleAdkTools(tools);
  const guarded = normalized.map((tool) => wrapGoogleAdkTool(run, tool));
  return {
    tools: guarded,
    wrapTool: (tool) =>
      wrapGoogleAdkTool(run, normalizeGoogleAdkTools([tool])[0]!),
  };
}

/** Alias matching bilingual Kit surface. */
export const instrument = createPaybondGoogleAdkConfig;

/** Alias matching bilingual Kit surface. */
export const instrumentGoogleAdk = createPaybondGoogleAdkConfig;

/** Alias matching bilingual Kit surface. */
export const wrapTools = createPaybondGoogleAdkConfig;
