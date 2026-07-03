import { createRequire } from "node:module";

import type {
  FunctionTool,
  RunConfig,
  ToolInputGuardrailDefinition,
} from "@openai/agents";
import {
  createToolInputGuardAdapter,
  type PaybondAgentRun,
  type PaybondToolInputGuardDecision,
} from "../agent/index.js";

type OpenAIAgentsModule = typeof import("@openai/agents");

let cachedOpenAIAgents: OpenAIAgentsModule | undefined;

/**
 * Lazily resolve the optional `@openai/agents` peer dependency.
 *
 * Importing this module must not require the peer to be installed, so consumers of
 * other frameworks (LangGraph, Vercel AI, etc.) can load the Paybond barrel without it.
 * The peer is only needed when the OpenAI Agents adapter functions actually run.
 */
function loadOpenAIAgents(): OpenAIAgentsModule {
  if (cachedOpenAIAgents === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedOpenAIAgents = require("@openai/agents") as OpenAIAgentsModule;
    } catch (err) {
      throw new Error(
        'The OpenAI Agents integration requires the optional peer dependency "@openai/agents"; install it with: npm install @openai/agents',
        { cause: err },
      );
    }
  }
  return cachedOpenAIAgents;
}

export type PaybondOpenAIAgentsAdapterOptions = {
  /**
   * When true, side-effecting registered tools also set `needsApproval: true`
   * so the OpenAI Agents SDK pauses for human review after Paybond pre-check passes.
   */
  bridgeNeedsApproval?: boolean;
};

function parseToolArguments(raw: string): unknown {
  if (!raw.trim()) {
    return {};
  }
  return JSON.parse(raw) as unknown;
}

function isFunctionTool(value: unknown): value is FunctionTool {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return record.type === "function" && typeof record.name === "string" && typeof record.invoke === "function";
}

/** Detect OpenAI Agents SDK function tools (`type: "function"`). */
export { isFunctionTool as isOpenAIFunctionTool };

/** Map a framework-neutral Paybond decision to OpenAI tool guardrail output. */
export function mapPaybondDecisionToOpenAIToolGuardrail(
  decision: PaybondToolInputGuardDecision,
): ReturnType<
  typeof import("@openai/agents").ToolGuardrailFunctionOutputFactory.allow
> {
  const { ToolGuardrailFunctionOutputFactory } = loadOpenAIAgents();
  if (decision.kind === "allow") {
    return ToolGuardrailFunctionOutputFactory.allow({
      paybond: {
        operation: decision.operation,
        auditId: decision.auditId,
        decisionId: decision.decisionId,
        passthrough: decision.passthrough ?? false,
      },
    });
  }

  return ToolGuardrailFunctionOutputFactory.rejectContent(decision.message, {
    paybond: {
      kind: decision.kind,
      operation: decision.operation,
      auditId: decision.auditId,
      code: decision.code,
    },
  });
}

function buildPaybondInputGuardrail(
  run: PaybondAgentRun,
  toolName: string,
): ToolInputGuardrailDefinition {
  const { defineToolInputGuardrail } = loadOpenAIAgents();
  const guard = createToolInputGuardAdapter(run);
  return defineToolInputGuardrail({
    name: `paybond_spend_${toolName}`,
    run: async ({ toolCall }) => {
      const args = parseToolArguments(toolCall.arguments);
      const decision = await guard.evaluate({
        toolName: toolCall.name,
        toolCallId: toolCall.callId,
        arguments: args,
      });
      return mapPaybondDecisionToOpenAIToolGuardrail(decision);
    },
  });
}

function resolveToolCallId(details?: { toolCall?: { callId?: string } }): string {
  const callId = details?.toolCall?.callId?.trim();
  if (callId) {
    return callId;
  }
  return globalThis.crypto.randomUUID();
}

function guardFunctionTool<TContext>(
  run: PaybondAgentRun,
  fnTool: FunctionTool<TContext>,
  options?: PaybondOpenAIAgentsAdapterOptions,
): FunctionTool<TContext> {
  if (!run.registry.isSideEffecting(fnTool.name)) {
    return fnTool;
  }

  const paybondGuardrail = buildPaybondInputGuardrail(run, fnTool.name);
  const originalInvoke = fnTool.invoke.bind(fnTool);
  const bridgeApproval = options?.bridgeNeedsApproval === true;

  return {
    ...fnTool,
    inputGuardrails: [...(fnTool.inputGuardrails ?? []), paybondGuardrail],
    needsApproval: bridgeApproval
      ? async (runContext, input, callId) => {
          const baseNeedsApproval =
            typeof fnTool.needsApproval === "function"
              ? await fnTool.needsApproval(runContext, input, callId)
              : Boolean(fnTool.needsApproval);
          return baseNeedsApproval || bridgeApproval;
        }
      : fnTool.needsApproval,
    invoke: async (runContext, input, details) => {
      const args = parseToolArguments(input);
      const wrapped = await run.interceptor.wrapExecute({
        toolName: fnTool.name,
        toolCallId: resolveToolCallId(details),
        arguments: args,
        execute: async () => {
          const raw = await originalInvoke(runContext, input, details);
          if (typeof raw === "string") {
            try {
              return JSON.parse(raw) as unknown;
            } catch {
              return raw;
            }
          }
          return raw;
        },
      });

      const { toolResult } = wrapped;
      if (typeof toolResult === "string") {
        return toolResult;
      }
      if (toolResult === undefined || toolResult === null) {
        return "";
      }
      if (typeof toolResult === "object") {
        return JSON.stringify(toolResult);
      }
      return toolResult;
    },
  };
}

/** RunConfig fragment enabling Paybond verify before OpenAI approval interruptions. */
export const paybondOpenAIAgentsRunConfig: Pick<RunConfig, "toolExecution"> = {
  toolExecution: {
    preApprovalInputGuardrails: true,
  },
};

/** Translate Paybond middleware into OpenAI Agents SDK tool input guardrails. */
export function createOpenAIAgentsAdapter(
  run: PaybondAgentRun,
  options?: PaybondOpenAIAgentsAdapterOptions,
) {
  const guard = createToolInputGuardAdapter(run);

  return {
    name: "openai-agents" as const,
    evaluate: guard.evaluate.bind(guard),
    wrapExecutors: guard.wrapExecutors.bind(guard),
    runConfig: paybondOpenAIAgentsRunConfig,
    inputGuardrailFor(toolName: string): ToolInputGuardrailDefinition {
      return buildPaybondInputGuardrail(run, toolName);
    },
    guardFunctionTools<TContext>(
      tools: Array<FunctionTool<TContext>>,
    ): Array<FunctionTool<TContext>> {
      return tools.map((tool) => guardFunctionTool(run, tool, options));
    },
  };
}

/** Convenience alias for {@link createOpenAIAgentsAdapter}. */
export function paybondOpenAIAgentsAdapter(
  run: PaybondAgentRun,
  options?: PaybondOpenAIAgentsAdapterOptions,
): ReturnType<typeof createOpenAIAgentsAdapter> {
  return createOpenAIAgentsAdapter(run, options);
}

export {
  runOpenAIAgentsSandboxDemo,
  type RunOpenAIAgentsSandboxDemoInput,
  type RunOpenAIAgentsSandboxDemoResult,
} from "./sandbox-demo.js";

/** OpenAI Agents SDK runner config: guarded tools plus `runConfig` for pre-approval guardrails. */
export type PaybondOpenAIAgentsConfig<TContext = unknown> = {
  tools: Array<FunctionTool<TContext>>;
  runConfig: Pick<RunConfig, "toolExecution">;
};

/**
 * Framework runner helper for OpenAI Agents SDK `Runner.run`.
 *
 * Returns guarded function tools and the `runConfig` fragment that enables
 * Paybond verify before approval interruptions.
 */
export function createPaybondOpenAIAgentsConfig<TContext>(
  run: PaybondAgentRun,
  tools: Array<FunctionTool<TContext>>,
  options?: PaybondOpenAIAgentsAdapterOptions,
): PaybondOpenAIAgentsConfig<TContext> {
  const adapter = createOpenAIAgentsAdapter(run, options);
  return {
    tools: adapter.guardFunctionTools(tools),
    runConfig: adapter.runConfig,
  };
}
