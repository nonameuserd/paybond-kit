import type { PaybondGenericToolCall, PaybondGenericToolDefinition } from "./adapter.js";

export const PAYBOND_LAZY_CONTEXT_MESSAGE =
  "context provider must return { intentId, capabilityToken } for the active request before executing side-effecting tools.";

/** Thrown when a lazy-context provider returns incomplete binding material. */
export class PaybondLazyContextError extends Error {
  constructor(message = PAYBOND_LAZY_CONTEXT_MESSAGE) {
    super(message);
    this.name = "PaybondLazyContextError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isGenericToolDefinition(value: unknown): value is PaybondGenericToolDefinition {
  if (!isRecord(value)) {
    return false;
  }
  return typeof value.name === "string" && value.name.trim().length > 0 && typeof value.execute === "function";
}

async function executeGuardedTool(
  runtimeTools: unknown,
  toolName: string,
  call?: PaybondGenericToolCall,
): Promise<unknown> {
  if (Array.isArray(runtimeTools)) {
    const tool = runtimeTools.find(
      (entry) => isGenericToolDefinition(entry) && entry.name === toolName,
    );
    if (!tool) {
      throw new Error(`guarded tool not found after lazy bind: ${toolName}`);
    }
    return tool.execute(call);
  }

  if (isRecord(runtimeTools)) {
    const tool = runtimeTools[toolName];
    if (typeof tool === "function") {
      return tool(call);
    }
    if (isGenericToolDefinition(tool)) {
      return tool.execute(call);
    }
  }

  throw new Error(`guarded tool not found after lazy bind: ${toolName}`);
}

export type LazyRuntimeResolver<TTools = unknown> = {
  resolve: () => Promise<{ tools: TTools }>;
};

/**
 * Wrap tools so each execution resolves request context via {@link LazyRuntimeResolver}.
 * Safe to register once; binding happens per active request at execute time.
 */
export function wrapLazyContextTools<TTools>(
  rawTools: TTools,
  resolver: LazyRuntimeResolver<TTools>,
): TTools {
  const runGuarded = async (toolName: string, call?: PaybondGenericToolCall): Promise<unknown> => {
    const runtime = await resolver.resolve();
    return executeGuardedTool(runtime.tools, toolName, call);
  };

  if (Array.isArray(rawTools)) {
    return rawTools.map((tool) => {
      if (!isGenericToolDefinition(tool)) {
        return tool;
      }
      const { execute: _ignored, ...rest } = tool;
      return {
        ...rest,
        name: tool.name,
        execute: async (call?: PaybondGenericToolCall) => runGuarded(tool.name, call),
      };
    }) as TTools;
  }

  if (isRecord(rawTools)) {
    const wrapped: Record<string, unknown> = {};
    for (const [name, tool] of Object.entries(rawTools)) {
      if (typeof tool === "function") {
        wrapped[name] = async (call?: PaybondGenericToolCall) => runGuarded(name, call);
        continue;
      }
      if (isGenericToolDefinition(tool)) {
        const toolName = tool.name.trim() || name;
        const { execute: _ignored, ...rest } = tool;
        wrapped[name] = {
          ...rest,
          name: toolName,
          execute: async (call?: PaybondGenericToolCall) => runGuarded(toolName, call),
        };
        continue;
      }
      wrapped[name] = tool;
    }
    return wrapped as TTools;
  }

  return rawTools;
}
