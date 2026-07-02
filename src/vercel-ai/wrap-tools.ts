import type { Tool, ToolSet } from "ai";
import type { PaybondAgentRun } from "../agent/run.js";

function isClientExecutedTool(tool: Tool): tool is Tool & {
  execute: NonNullable<Tool["execute"]>;
} {
  if (typeof tool !== "object" || tool === null) {
    return false;
  }
  const record = tool as Record<string, unknown>;
  if (record.isProviderExecuted === true) {
    return false;
  }
  return typeof record.execute === "function";
}

/**
 * Wrap side-effecting Vercel AI SDK tools with Paybond `wrapExecute` so Harbor
 * verify, spend finalize, and auto-evidence run after successful execution.
 *
 * Read-only and provider-executed tools pass through unchanged.
 */
export function paybondVercelWrapTools<TOOLS extends ToolSet>(
  run: PaybondAgentRun,
  tools: TOOLS,
): TOOLS {
  const wrapped: Record<string, Tool> = {};

  for (const [toolName, tool] of Object.entries(tools) as Array<[string, Tool]>) {
    if (!isClientExecutedTool(tool) || !run.registry.isSideEffecting(toolName)) {
      wrapped[toolName] = tool;
      continue;
    }

    const originalExecute = tool.execute.bind(tool);
    wrapped[toolName] = {
      ...tool,
      execute: async (input, options) => {
        const result = await run.interceptor.wrapExecute({
          toolName,
          toolCallId: options.toolCallId,
          arguments: input,
          approvalToken: run.getApprovalToken(options.toolCallId),
          execute: () => originalExecute(input, options),
        });
        return result.toolResult;
      },
    };
  }

  return wrapped as TOOLS;
}
