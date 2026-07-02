import {
  createSdkMcpServer,
  type SdkMcpToolDefinition,
} from "@anthropic-ai/claude-agent-sdk";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  PaybondAutoEvidenceSubmitError,
  PaybondUnregisteredSideEffectingToolError,
} from "../agent/types.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../index.js";

/** Pre-built SDK tool from `tool()` in `@anthropic-ai/claude-agent-sdk`. */
export type ClaudeAgentSdkTool = SdkMcpToolDefinition;

type CallToolResult = {
  content: Array<{
    type: string;
    text?: string;
    [key: string]: unknown;
  }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

export type PaybondClaudeAgentsConfigOptions = {
  /** MCP server name; defaults to `"paybond"`. */
  serverName?: string;
  /** Optional version passed to `createSdkMcpServer`. */
  serverVersion?: string;
};

export type ClaudeAgentsConfig = {
  mcpServer: ReturnType<typeof createSdkMcpServer>;
  allowedTools: string[];
  /** Same tool array as input — side-effecting handlers are wrapped in-place. */
  agentTools: ClaudeAgentSdkTool[];
};

function claudeMcpAllowedToolName(serverName: string, toolName: string): string {
  return `mcp__${serverName}__${toolName}`;
}

function resolveClaudeToolCallId(extra: unknown): string {
  if (typeof extra === "object" && extra !== null) {
    const record = extra as Record<string, unknown>;
    for (const key of ["toolUseID", "tool_use_id", "toolCallId", "tool_call_id", "id"]) {
      const value = record[key];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }
  }
  return globalThis.crypto.randomUUID();
}

function extractCallToolResultPayload(result: CallToolResult): unknown {
  if (result.structuredContent && typeof result.structuredContent === "object") {
    return result.structuredContent;
  }
  for (const block of result.content) {
    if (block.type !== "text") {
      continue;
    }
    const text = "text" in block && typeof block.text === "string" ? block.text.trim() : "";
    if (!text) {
      continue;
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return { text };
    }
  }
  return result;
}

function toCallToolResult(payload: unknown): CallToolResult {
  if (typeof payload === "object" && payload !== null && "content" in payload) {
    return payload as CallToolResult;
  }
  if (typeof payload === "string") {
    return { content: [{ type: "text", text: payload }] };
  }
  if (payload === undefined || payload === null) {
    return { content: [{ type: "text", text: "" }] };
  }
  if (typeof payload === "object") {
    return {
      content: [{ type: "text", text: JSON.stringify(payload) }],
      structuredContent: payload as Record<string, unknown>,
    };
  }
  return { content: [{ type: "text", text: String(payload) }] };
}

function paybondErrorCallToolResult(message: string): CallToolResult {
  return {
    content: [{ type: "text", text: message }],
    isError: true,
  };
}

function assertClaudeAgentSdkTools(tools: unknown): ClaudeAgentSdkTool[] {
  if (!Array.isArray(tools)) {
    throw new TypeError("claude-agents framework tools must be an array of SDK tool() definitions");
  }
  for (const tool of tools) {
    if (typeof tool !== "object" || tool === null) {
      throw new TypeError("each claude-agents tool must be an SDK tool() definition");
    }
    const record = tool as ClaudeAgentSdkTool;
    if (typeof record.name !== "string" || !record.name.trim()) {
      throw new TypeError("each claude-agents tool must have a non-empty name");
    }
    if (typeof record.handler !== "function") {
      throw new TypeError("each claude-agents tool must have a handler function");
    }
  }
  return tools;
}

function wrapClaudeAgentSdkTool(run: PaybondAgentRun, sdkTool: ClaudeAgentSdkTool): ClaudeAgentSdkTool {
  if (!run.registry.isSideEffecting(sdkTool.name)) {
    return sdkTool;
  }

  const originalHandler = sdkTool.handler.bind(sdkTool);
  type MutableClaudeTool = {
    handler: (
      args: Record<string, unknown>,
      extra: unknown,
    ) => Promise<CallToolResult>;
  };
  const mutableTool = sdkTool as unknown as MutableClaudeTool;
  mutableTool.handler = async (args, extra) => {
    const toolCallId = resolveClaudeToolCallId(extra);
    try {
      const wrapped = await run.interceptor.wrapExecute({
        toolName: sdkTool.name,
        toolCallId,
        arguments: args,
        approvalToken: run.getApprovalToken(toolCallId),
        execute: async () => {
          const mcpResult = await originalHandler(
            args as Parameters<typeof originalHandler>[0],
            extra,
          );
          return extractCallToolResultPayload(mcpResult as CallToolResult);
        },
      });
      return toCallToolResult(wrapped.toolResult);
    } catch (err) {
      if (err instanceof PaybondUnregisteredSideEffectingToolError) {
        return paybondErrorCallToolResult(
          `Paybond capability denied: unregistered side-effecting tool (${err.message})`,
        );
      }
      if (err instanceof PaybondSpendApprovalRequiredError) {
        const decisionId = err.result.decisionId;
        const suffix = decisionId ? ` (decision_id=${decisionId})` : "";
        const msg = err.result.message ?? err.result.code ?? "approval required";
        return paybondErrorCallToolResult(`Paybond capability approval required: ${msg}${suffix}`);
      }
      if (err instanceof PaybondSpendDeniedError) {
        const msg = err.result.message ?? err.result.code ?? "capability denied";
        return paybondErrorCallToolResult(`Paybond capability denied: ${msg}`);
      }
      if (err instanceof PaybondAutoEvidenceSubmitError) {
        return paybondErrorCallToolResult(`Paybond evidence submit failed: ${err.message}`);
      }
      throw err;
    }
  };
  return sdkTool;
}

/**
 * Wrap Claude Agent SDK `tool()` handlers with Paybond middleware and bundle them
 * into an in-process MCP server for `query({ options: { mcpServers, allowedTools } })`.
 */
export function createPaybondClaudeAgentsConfig(
  run: PaybondAgentRun,
  tools: ClaudeAgentSdkTool[],
  options?: PaybondClaudeAgentsConfigOptions,
): ClaudeAgentsConfig {
  const sdkTools = assertClaudeAgentSdkTools(tools);
  const serverName = options?.serverName?.trim() || "paybond";

  for (const sdkTool of sdkTools) {
    wrapClaudeAgentSdkTool(run, sdkTool);
  }

  const mcpServer = createSdkMcpServer({
    name: serverName,
    ...(options?.serverVersion ? { version: options.serverVersion } : {}),
    tools: sdkTools as SdkMcpToolDefinition[],
  });

  return {
    mcpServer,
    allowedTools: sdkTools.map((sdkTool) => claudeMcpAllowedToolName(serverName, sdkTool.name)),
    agentTools: sdkTools,
  };
}
