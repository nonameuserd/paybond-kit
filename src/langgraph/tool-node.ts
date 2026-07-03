import { createRequire } from "node:module";

import type { ToolMessage } from "@langchain/core/messages";
import type { DynamicTool, StructuredToolInterface } from "@langchain/core/tools";
import type { RunnableToolLike } from "@langchain/core/runnables";
import type { ToolNode, ToolNodeOptions } from "@langchain/langgraph/prebuilt";
import type { ToolCall } from "@langchain/core/messages/tool";
import type { RunnableConfig } from "@langchain/core/runnables";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  normalizeLangGraphHookResult,
  paybondAwrapToolCall,
  type PaybondLangGraphToolCallRequest,
} from "./awrap-tool-call.js";

type LangGraphTool = StructuredToolInterface | DynamicTool | RunnableToolLike;

type LangGraphPrebuiltModule = typeof import("@langchain/langgraph/prebuilt");

let cachedPrebuilt: LangGraphPrebuiltModule | undefined;

/**
 * Lazily resolve the optional `@langchain/langgraph` peer dependency.
 *
 * Importing this module must not require the peer to be installed, so the Paybond barrel
 * can load for consumers of other frameworks. The peer is only needed when a guarded
 * LangGraph `ToolNode` is actually constructed.
 */
function loadLangGraphPrebuilt(): LangGraphPrebuiltModule {
  if (cachedPrebuilt === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedPrebuilt = require("@langchain/langgraph/prebuilt") as LangGraphPrebuiltModule;
    } catch (err) {
      throw new Error(
        'The LangGraph integration requires the optional peer dependencies "@langchain/core" and "@langchain/langgraph"; install them with: npm install @langchain/core @langchain/langgraph',
        { cause: err },
      );
    }
  }
  return cachedPrebuilt;
}

/**
 * Convenience factory: `ToolNode` with Paybond spend guard + auto-evidence on every tool call.
 *
 * LangGraph JS does not yet expose `awrapToolCall` on `ToolNode`; the returned subclass provides
 * the same interceptor boundary as Python's `ToolNode(..., awrap_tool_call=...)`.
 */
export function paybondToolNode(
  tools: LangGraphTool[],
  run: PaybondAgentRun,
  options?: ToolNodeOptions,
): ToolNode {
  const { ToolNode: ToolNodeCtor } = loadLangGraphPrebuilt();

  class PaybondGuardedToolNode extends ToolNodeCtor {
    private readonly awrap: ReturnType<typeof paybondAwrapToolCall>;

    constructor(
      guardedTools: LangGraphTool[],
      guardedRun: PaybondAgentRun,
      guardedOptions?: ToolNodeOptions,
    ) {
      super(guardedTools, guardedOptions);
      this.awrap = paybondAwrapToolCall(guardedRun);
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

  return new PaybondGuardedToolNode(tools, run, options);
}
