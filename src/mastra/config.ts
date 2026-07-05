import type { PaybondAgentRun } from "../agent/run.js";

/** Minimal Mastra tool shape — matches `createTool()` output without importing `@mastra/core`. */
export type MastraToolLike = {
  id: string;
  description: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  suspendSchema?: unknown;
  resumeSchema?: unknown;
  requestContextSchema?: unknown;
  execute?: (inputData: unknown, context?: unknown) => unknown | Promise<unknown>;
};

/** Mastra runner config: guarded tools with wrapped `execute` handlers. */
export type PaybondMastraConfig<TTools extends MastraToolLike[]> = {
  tools: TTools;
};

function resolveMastraToolCallId(context: unknown, fallback: string): string {
  if (typeof context === "object" && context !== null) {
    const record = context as Record<string, unknown>;
    const agent = record.agent;
    if (typeof agent === "object" && agent !== null) {
      const toolCallId = (agent as Record<string, unknown>).toolCallId;
      if (typeof toolCallId === "string" && toolCallId.trim()) {
        return toolCallId.trim();
      }
    }
    const direct = record.toolCallId;
    if (typeof direct === "string" && direct.trim()) {
      return direct.trim();
    }
  }
  return fallback;
}

function wrapMastraTool<TTool extends MastraToolLike>(
  run: PaybondAgentRun,
  tool: TTool,
): TTool {
  const toolName = tool.id.trim();
  if (typeof tool.execute !== "function" || !run.registry.isSideEffecting(toolName)) {
    return tool;
  }

  const originalExecute = tool.execute.bind(tool);
  return {
    ...tool,
    execute: async (inputData: unknown, context?: unknown) => {
      const toolCallId = resolveMastraToolCallId(
        context,
        globalThis.crypto.randomUUID(),
      );
      const wrapped = await run.interceptor.wrapExecute({
        toolName,
        toolCallId,
        arguments: inputData,
        approvalToken: run.getApprovalToken(toolCallId),
        execute: () => originalExecute(inputData, context),
      });
      return wrapped.toolResult;
    },
  };
}

/**
 * Wrap side-effecting Mastra tools with Paybond `wrapExecute` so Harbor verify,
 * spend finalize, and auto-evidence run after successful execution.
 *
 * Read-only tools pass through unchanged.
 */
export function paybondMastraWrapTools<TTools extends MastraToolLike[]>(
  run: PaybondAgentRun,
  tools: TTools,
): TTools {
  return tools.map((tool) => wrapMastraTool(run, tool)) as TTools;
}

/**
 * Framework runner helper for Mastra `createTool({ execute })` definitions.
 *
 * Preserves schema, id, and description; replaces `execute` only on
 * side-effecting registry tools.
 */
export function createPaybondMastraConfig<TTools extends MastraToolLike[]>(
  run: PaybondAgentRun,
  tools: TTools,
): PaybondMastraConfig<TTools> {
  return {
    tools: paybondMastraWrapTools(run, tools),
  };
}
