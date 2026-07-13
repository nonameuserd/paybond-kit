import type { Tool, ToolSet } from "ai";
import type { PaybondAgentRun } from "../agent/run.js";
import {
  isProviderExecutedVercelTool,
  paybondProviderExecutedToolDenialReason,
} from "./provider-executed.js";

export type PaybondVercelWrapToolsOptions = {
  /**
   * Fail closed on provider-executed tools (`isProviderExecuted: true`).
   * When enabled, those tools cannot run — only locally executed registry tools are governed.
   */
  denyProviderExecutedTools?: boolean;
};

function isClientExecutedTool(tool: Tool): tool is Tool & {
  execute: NonNullable<Tool["execute"]>;
} {
  if (typeof tool !== "object" || tool === null) {
    return false;
  }
  if (isProviderExecutedVercelTool(tool)) {
    return false;
  }
  return typeof (tool as Record<string, unknown>).execute === "function";
}

function denyProviderExecutedTool(tool: Tool, toolName: string): Tool {
  return {
    ...tool,
    execute: async () => {
      throw new Error(
        `${paybondProviderExecutedToolDenialReason()} (tool=${toolName})`,
      );
    },
  };
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
  options?: PaybondVercelWrapToolsOptions,
): TOOLS {
  const wrapped: Record<string, Tool> = {};
  const denyProviderExecutedTools = options?.denyProviderExecutedTools === true;

  for (const [toolName, tool] of Object.entries(tools) as Array<[string, Tool]>) {
    if (denyProviderExecutedTools && isProviderExecutedVercelTool(tool)) {
      wrapped[toolName] = denyProviderExecutedTool(tool, toolName);
      continue;
    }
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
