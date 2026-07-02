import { ToolMessage } from "@langchain/core/messages";
import type { DynamicTool, StructuredToolInterface } from "@langchain/core/tools";
import type { RunnableToolLike } from "@langchain/core/runnables";
import { ToolNode, type ToolNodeOptions } from "@langchain/langgraph/prebuilt";
import type { ToolCall } from "@langchain/core/messages/tool";
import type { RunnableConfig } from "@langchain/core/runnables";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  normalizeLangGraphHookResult,
  paybondAwrapToolCall,
  type PaybondLangGraphToolCallRequest,
} from "./awrap-tool-call.js";

type LangGraphTool = StructuredToolInterface | DynamicTool | RunnableToolLike;

/**
 * `ToolNode` subclass that runs {@link paybondAwrapToolCall} before each tool invocation.
 *
 * LangGraph JS does not yet expose `awrapToolCall` on `ToolNode`; this wrapper provides the
 * same interceptor boundary as Python's `ToolNode(..., awrap_tool_call=...)`.
 */
class PaybondGuardedToolNode extends ToolNode {
  private readonly awrap: ReturnType<typeof paybondAwrapToolCall>;

  constructor(
    tools: LangGraphTool[],
    run: PaybondAgentRun,
    options?: ToolNodeOptions,
  ) {
    super(tools, options);
    this.awrap = paybondAwrapToolCall(run);
  }

  protected override async runTool(
    call: ToolCall,
    config: RunnableConfig,
    state: unknown,
  ): Promise<ToolMessage | import("@langchain/langgraph").Command> {
    const request: PaybondLangGraphToolCallRequest = {
      tool_call: {
        name: call.name,
        id: call.id,
        args: (call.args ?? {}) as Record<string, unknown>,
      },
    };

    const execute = async (req: PaybondLangGraphToolCallRequest) =>
      super.runTool(
        {
          ...call,
          name: req.tool_call.name,
          id: req.tool_call.id ?? call.id,
          args: req.tool_call.args ?? call.args,
        },
        config,
        state,
      );

    const result = await this.awrap(request, execute);
    return normalizeLangGraphHookResult(call, result);
  }
}

/**
 * Convenience factory: `ToolNode` with Paybond spend guard + auto-evidence on every tool call.
 */
export function paybondToolNode(
  tools: LangGraphTool[],
  run: PaybondAgentRun,
  options?: ToolNodeOptions,
): ToolNode {
  return new PaybondGuardedToolNode(tools, run, options);
}
