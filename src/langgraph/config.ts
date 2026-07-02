import type { ToolNodeOptions } from "@langchain/langgraph/prebuilt";

import type { PaybondAgentRun } from "../agent/run.js";
import { paybondAwrapToolCall, type PaybondLangGraphAwrapToolCall } from "./awrap-tool-call.js";
import { paybondToolNode } from "./tool-node.js";

/** LangGraph runner hooks: async tool-call wrapper and guarded `ToolNode` factory. */
export type PaybondLangGraphHooks = {
  awrapToolCall: PaybondLangGraphAwrapToolCall;
  createToolNode: (
    tools: Parameters<typeof paybondToolNode>[0],
    options?: ToolNodeOptions,
  ) => ReturnType<typeof paybondToolNode>;
};

/**
 * Framework runner helper for LangGraph `ToolNode` and `awrap_tool_call` integration.
 */
export function createPaybondLangGraphHooks(run: PaybondAgentRun): PaybondLangGraphHooks {
  return {
    awrapToolCall: paybondAwrapToolCall(run),
    createToolNode: (tools, options) => paybondToolNode(tools, run, options),
  };
}
