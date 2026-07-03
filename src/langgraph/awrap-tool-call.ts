import { createRequire } from "node:module";

import type { ToolMessage } from "@langchain/core/messages";
import type { Command } from "@langchain/langgraph";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  PaybondAutoEvidenceSubmitError,
  PaybondUnregisteredSideEffectingToolError,
} from "../agent/types.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../index.js";

/** LangGraph `ToolCallRequest`-compatible shape used by Paybond interceptors. */
export type PaybondLangGraphToolCallRequest = {
  tool_call: {
    name: string;
    id?: string;
    args?: Record<string, unknown>;
  };
};

export type PaybondLangGraphAwrapToolCall = (
  request: PaybondLangGraphToolCallRequest,
  execute: (request: PaybondLangGraphToolCallRequest) => Promise<unknown>,
) => Promise<unknown>;

type LangGraphCoreMessagesModule = typeof import("@langchain/core/messages");
type LangGraphModule = typeof import("@langchain/langgraph");

let cachedCoreMessages: LangGraphCoreMessagesModule | undefined;
let cachedLangGraph: LangGraphModule | undefined;

function missingLangGraphPeerError(err: unknown): Error {
  return new Error(
    'The LangGraph integration requires the optional peer dependencies "@langchain/core" and "@langchain/langgraph"; install them with: npm install @langchain/core @langchain/langgraph',
    { cause: err },
  );
}

/**
 * Lazily resolve `@langchain/core/messages`; importing this module must not require the peer.
 */
function loadCoreMessages(): LangGraphCoreMessagesModule {
  if (cachedCoreMessages === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedCoreMessages = require("@langchain/core/messages") as LangGraphCoreMessagesModule;
    } catch (err) {
      throw missingLangGraphPeerError(err);
    }
  }
  return cachedCoreMessages;
}

/**
 * Lazily resolve `@langchain/langgraph`; importing this module must not require the peer.
 */
function loadLangGraph(): LangGraphModule {
  if (cachedLangGraph === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedLangGraph = require("@langchain/langgraph") as LangGraphModule;
    } catch (err) {
      throw missingLangGraphPeerError(err);
    }
  }
  return cachedLangGraph;
}

function toolCallFields(request: PaybondLangGraphToolCallRequest): {
  name: string;
  toolCallId: string;
  args: Record<string, unknown>;
} {
  const call = request.tool_call;
  return {
    name: String(call.name ?? "").trim(),
    toolCallId: String(call.id ?? "").trim(),
    args: (call.args ?? {}) as Record<string, unknown>,
  };
}

function denyToolMessage(
  name: string,
  toolCallId: string,
  content: string,
): ToolMessage {
  const { ToolMessage } = loadCoreMessages();
  return new ToolMessage({
    content,
    name: name || "unknown",
    tool_call_id: toolCallId,
    status: "error",
  });
}

function isToolMessage(value: unknown): value is ToolMessage {
  return value instanceof loadCoreMessages().ToolMessage;
}

export function normalizeLangGraphHookResult(
  call: { name: string; id?: string },
  result: unknown,
): ToolMessage | Command {
  const { isCommand } = loadLangGraph();
  const { ToolMessage } = loadCoreMessages();
  if (isToolMessage(result) || isCommand(result)) {
    return result;
  }
  return new ToolMessage({
    status: "success",
    name: call.name,
    content: typeof result === "string" ? result : JSON.stringify(result),
    tool_call_id: call.id ?? "",
  });
}

/**
 * Build a LangGraph `awrapToolCall` interceptor backed by {@link PaybondToolInterceptor}.
 *
 * Prefer this over manual `guardTool` wrappers when the agent run is bound with a tool registry
 * (registry spend resolvers, auto-evidence, and `defaultDeny`).
 */
export function paybondAwrapToolCall(run: PaybondAgentRun): PaybondLangGraphAwrapToolCall {
  return async (request, execute) => {
    const { name, toolCallId, args } = toolCallFields(request);
    if (!name) {
      return denyToolMessage("unknown", toolCallId, "Paybond: tool call missing name");
    }
    if (!toolCallId) {
      return denyToolMessage(name, "", "Paybond: tool call missing id");
    }

    try {
      const wrapped = await run.interceptor.wrapExecute({
        toolName: name,
        toolCallId,
        arguments: args,
        execute: () => execute(request),
      });
      return wrapped.toolResult;
    } catch (err) {
      if (err instanceof PaybondUnregisteredSideEffectingToolError) {
        return denyToolMessage(
          name,
          toolCallId,
          `Paybond capability denied: unregistered side-effecting tool (${err.message})`,
        );
      }
      if (err instanceof PaybondSpendApprovalRequiredError) {
        const decisionId = err.result?.decisionId;
        const suffix = decisionId ? ` (decision_id=${decisionId})` : "";
        const msg = err.result?.message ?? err.result?.code ?? "approval required";
        return denyToolMessage(
          name,
          toolCallId,
          `Paybond capability approval required: ${msg}${suffix}`,
        );
      }
      if (err instanceof PaybondSpendDeniedError) {
        const msg = err.result?.message ?? err.result?.code ?? "capability denied";
        return denyToolMessage(name, toolCallId, `Paybond capability denied: ${msg}`);
      }
      if (err instanceof PaybondAutoEvidenceSubmitError) {
        return denyToolMessage(
          name,
          toolCallId,
          `Paybond evidence submit failed: ${err.message}`,
        );
      }
      throw err;
    }
  };
}

/** @deprecated Use {@link paybondAwrapToolCall}. */
export const paybondAwrapToolCallCapability = paybondAwrapToolCall;
