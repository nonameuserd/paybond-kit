import {
  createGenericToolExecutor,
  createToolInputGuardAdapter,
  type PaybondGenericToolDefinition,
  type PaybondGenericWrappedToolDefinition,
  type PaybondToolInputGuardAdapter,
} from "./adapter.js";
import type { PaybondAgentRun } from "./run.js";

/** Wrapped generic tools plus authorize-only pre-checks for unknown frameworks. */
export type PaybondGenericAgentConfig = {
  tools: PaybondGenericWrappedToolDefinition[];
  inputGuard: PaybondToolInputGuardAdapter;
};

function isGenericToolDefinition(value: unknown): value is PaybondGenericToolDefinition {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.name === "string" &&
    record.name.trim().length > 0 &&
    typeof record.execute === "function"
  );
}

function normalizeGenericTools(tools: unknown): PaybondGenericToolDefinition[] {
  if (Array.isArray(tools)) {
    for (const tool of tools) {
      if (!isGenericToolDefinition(tool)) {
        throw new TypeError("each generic tool must have a non-empty name and an execute function");
      }
    }
    return tools;
  }
  if (typeof tools === "object" && tools !== null) {
    return Object.entries(tools).map(([name, tool]) => {
      if (typeof tool === "function") {
        return { name, execute: tool as PaybondGenericToolDefinition["execute"] };
      }
      if (typeof tool === "object" && tool !== null && "execute" in tool) {
        const record = tool as PaybondGenericToolDefinition;
        const resolvedName = record.name?.trim() || name;
        return { ...record, name: resolvedName };
      }
      throw new TypeError(
        "generic framework tools must be an array of { name, execute } or a record of executors",
      );
    });
  }
  throw new TypeError("generic framework tools must be an array or record");
}

/** Authorize-only dry run before side-effecting tool execution (framework-neutral). */
export function createPaybondGenericInputGuard(
  run: PaybondAgentRun,
): PaybondToolInputGuardAdapter {
  return createToolInputGuardAdapter(run);
}

/**
 * Recommended default when the agent framework is unknown: wrap `{ name, execute }`
 * tools with full middleware and expose an authorize-only input guard.
 */
export function createPaybondGenericAgentConfig(
  run: PaybondAgentRun,
  tools: unknown,
): PaybondGenericAgentConfig {
  const normalized = normalizeGenericTools(tools);
  return {
    tools: createGenericToolExecutor().wrapTools(run, normalized) as PaybondGenericWrappedToolDefinition[],
    inputGuard: createPaybondGenericInputGuard(run),
  };
}
