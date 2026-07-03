import { createPaybondClaudeAgentsConfig } from "../claude-agents/config.js";
import type { ClaudeAgentsConfig } from "../claude-agents/config.js";
import type { PaybondLangGraphHooks } from "../langgraph/config.js";
import { createOpenAIAgentsAdapter, createPaybondOpenAIAgentsConfig } from "../openai-agents/index.js";
import type { PaybondPolicy } from "../policy/load.js";
import type { PaybondPolicyLoadSource } from "../policy/load.js";
import { isKnownPolicyPresetId, resolvePolicyPresetPath } from "../policy/presets.js";
import { createPaybondVercelAgentConfig } from "../vercel-ai/config.js";
import { paybondVercelToolApproval } from "../vercel-ai/tool-approval.js";
import {
  createPaybondGenericAgentConfig,
  createPaybondGenericInputGuard,
} from "./generic-runner.js";
import type { PaybondToolInputGuardAdapter } from "./adapter.js";
import {
  createGuardedAgent,
  type CreateGuardedAgentInput,
  type CreateGuardedAgentResult,
  type GuardedAgentFramework,
} from "./guarded-agent.js";
import {
  instrumentPaybondAgent,
  PaybondInstrumentRuntime,
  type PaybondInstrumentInput,
} from "./instrument.js";
import type { PaybondAgentRun, PaybondAgentRunHost } from "./run.js";

const POLICY_PATH_PATTERN = /[/\\]|\.ya?ml$|\.json$/i;

/**
 * Resolve a policy preset id (for example `travel`) or pass through file paths and in-memory documents.
 */
export function resolveAgentPolicySource(policy: PaybondPolicyLoadSource): PaybondPolicyLoadSource {
  if (typeof policy !== "string") {
    return policy;
  }
  const trimmed = policy.trim();
  if (!trimmed) {
    throw new Error("policy must be a non-empty preset id or file path");
  }
  if (POLICY_PATH_PATTERN.test(trimmed)) {
    return trimmed;
  }
  if (isKnownPolicyPresetId(trimmed)) {
    return resolvePolicyPresetPath(trimmed);
  }
  return trimmed;
}

export type PaybondAgentInput<TTools = unknown> = PaybondInstrumentInput<TTools> & {
  policy: PaybondPolicyLoadSource;
};

/** Framework-native wiring returned by {@link createPaybondAgent} / {@link Paybond.agent}. */
export type PaybondAgentHooks = {
  inputGuard?: PaybondToolInputGuardAdapter;
  toolApproval?: ReturnType<typeof paybondVercelToolApproval>;
  awrapToolCall?: PaybondLangGraphHooks["awrapToolCall"];
  createToolNode?: PaybondLangGraphHooks["createToolNode"];
  runConfig?: ReturnType<typeof createOpenAIAgentsAdapter>["runConfig"];
  openAIAgentsAdapter?: ReturnType<typeof createOpenAIAgentsAdapter>;
  mcpServer?: ClaudeAgentsConfig["mcpServer"];
  allowedTools?: ClaudeAgentsConfig["allowedTools"];
};

/** Opinionated quickstart result: guarded tools plus framework hooks. */
export type PaybondAgentResult<TTools = unknown> = {
  run: PaybondAgentRun;
  tools: TTools;
  hooks: PaybondAgentHooks;
  policy: PaybondPolicy;
};

/** Normalize {@link CreateGuardedAgentResult} into the quickstart `{ run, tools, hooks, policy }` shape. */
export function toPaybondAgentResult<TTools>(
  result: CreateGuardedAgentResult<TTools>,
): PaybondAgentResult<TTools> {
  const hooks: PaybondAgentHooks = {};

  switch (result.framework) {
    case "generic":
      hooks.inputGuard = createPaybondGenericInputGuard(result.run);
      break;
    case "vercel-ai":
      if (result.toolApproval) {
        hooks.toolApproval = result.toolApproval;
      }
      break;
    case "langgraph":
      if (result.awrapToolCall) {
        hooks.awrapToolCall = result.awrapToolCall;
      }
      if (result.createToolNode) {
        hooks.createToolNode = result.createToolNode;
      }
      break;
    case "openai-agents":
      if (result.runConfig) {
        hooks.runConfig = result.runConfig;
      }
      if (result.openAIAgentsAdapter) {
        hooks.openAIAgentsAdapter = result.openAIAgentsAdapter;
      }
      break;
    case "claude-agents":
      if (result.claudeAgentsConfig) {
        hooks.mcpServer = result.claudeAgentsConfig.mcpServer;
        hooks.allowedTools = result.claudeAgentsConfig.allowedTools;
      }
      break;
    default: {
      const exhaustive: never = result.framework;
      throw new Error(`unsupported guarded agent framework: ${String(exhaustive)}`);
    }
  }

  return {
    run: result.run,
    tools: result.agentTools,
    hooks,
    policy: result.policy,
  };
}

/** Opinionated quickstart: resolve named presets, then delegate to {@link instrumentPaybondAgent}. */
export async function createPaybondAgent<TTools>(
  paybond: PaybondAgentRunHost,
  input: PaybondAgentInput<TTools>,
): Promise<PaybondAgentResult<TTools>> {
  const policy =
    typeof input.policy === "string" ? resolveAgentPolicySource(input.policy) : input.policy;
  const result = await instrumentPaybondAgent(paybond, {
    ...input,
    policy,
    sandbox: input.context || input.attach ? false : (input.sandbox ?? true),
    attach: input.attach,
    context: input.context,
  });
  if (!(result instanceof PaybondInstrumentRuntime)) {
    throw new Error("paybond.agent() requires sandbox bootstrap or an explicit context");
  }
  return {
    run: result.run,
    tools: result.tools,
    hooks: result.hooks,
    policy: result.policy,
  };
}

export type PaybondWrapToolsOptions = {
  framework?: GuardedAgentFramework;
  sandbox?: boolean;
  attach?: import("./instrument.js").PaybondInstrumentAttachInput;
  context?: import("./instrument.js").PaybondInstrumentContextInput;
};

/** Wrap tools for an existing bound run without reloading policy. */
export function wrapPaybondTools(
  run: PaybondAgentRun,
  tools: unknown,
  options?: PaybondWrapToolsOptions,
): unknown {
  const framework = options?.framework ?? "generic";

  switch (framework) {
    case "generic":
      return createPaybondGenericAgentConfig(run, tools).tools;
    case "vercel-ai":
      return createPaybondVercelAgentConfig(run, tools as never).tools;
    case "openai-agents":
      return createPaybondOpenAIAgentsConfig(run, tools as never).tools;
    case "claude-agents":
      return createPaybondClaudeAgentsConfig(run, tools as never).agentTools;
    case "langgraph":
      throw new Error(
        'framework "langgraph" does not wrap tools in place; use instrument() or createPaybondLangGraphHooks(run)',
      );
    default: {
      const exhaustive: never = framework;
      throw new Error(`unsupported framework for wrapTools: ${String(exhaustive)}`);
    }
  }
}

export type { PaybondInstrumentInput } from "./instrument.js";
