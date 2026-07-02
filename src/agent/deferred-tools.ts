import type { PaybondGenericToolCall, PaybondGenericToolDefinition } from "./adapter.js";

export const PAYBOND_BIND_CONTEXT_MESSAGE =
  "Call instrumented.bind({ intentId, capabilityToken }) to attach a funded intent before executing side-effecting tools.";

/** Thrown when a deferred tool executes before {@link PaybondInstrumented.bind}. */
export class PaybondUnboundContextError extends Error {
  readonly toolName: string;

  constructor(toolName: string) {
    super(`Tool "${toolName}" requires a bound Paybond context. ${PAYBOND_BIND_CONTEXT_MESSAGE}`);
    this.name = "PaybondUnboundContextError";
    this.toolName = toolName;
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

function deferredExecute(toolName: string): never {
  throw new PaybondUnboundContextError(toolName);
}

/**
 * Wrap tools for static instrumentation — safe to register with agent frameworks.
 * Side-effecting execution throws until {@link PaybondInstrumented.bind} supplies a runtime.
 */
export function wrapDeferredTools<TTools>(rawTools: TTools): TTools {
  if (Array.isArray(rawTools)) {
    return rawTools.map((tool) => {
      if (!isGenericToolDefinition(tool)) {
        return tool;
      }
      const { execute: _ignored, ...rest } = tool;
      return {
        ...rest,
        name: tool.name,
        execute: async (_call?: PaybondGenericToolCall) => deferredExecute(tool.name),
      };
    }) as TTools;
  }

  if (isRecord(rawTools)) {
    const wrapped: Record<string, unknown> = {};
    for (const [name, tool] of Object.entries(rawTools)) {
      if (typeof tool === "function") {
        wrapped[name] = async () => deferredExecute(name);
        continue;
      }
      if (isGenericToolDefinition(tool)) {
        const { execute: _ignored, ...rest } = tool;
        wrapped[name] = {
          ...rest,
          name: tool.name?.trim() || name,
          execute: async (_call?: PaybondGenericToolCall) => deferredExecute(tool.name?.trim() || name),
        };
        continue;
      }
      wrapped[name] = tool;
    }
    return wrapped as TTools;
  }

  return rawTools;
}
