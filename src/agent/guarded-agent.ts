import type { ToolSet } from "ai";
import type { FunctionTool } from "@openai/agents";
import type { ToolNodeOptions } from "@langchain/langgraph/prebuilt";

import {
  createOpenAIAgentsAdapter,
  createPaybondOpenAIAgentsConfig,
  type PaybondOpenAIAgentsAdapterOptions,
} from "../openai-agents/index.js";
import { PaybondPolicy, type PaybondPolicyLoadSource } from "../policy/load.js";
import type { PaybondPolicySandboxBootstrapOptions } from "../policy/sandbox-bootstrap.js";
import type { PolicyValidatorOptions } from "../policy/validate.js";
import { createPaybondVercelAgentConfig } from "../vercel-ai/config.js";
import { paybondVercelToolApproval } from "../vercel-ai/tool-approval.js";
import { createPaybondLangGraphHooks } from "../langgraph/config.js";
import { type PaybondLangGraphAwrapToolCall } from "../langgraph/awrap-tool-call.js";
import { paybondToolNode } from "../langgraph/tool-node.js";
import {
  createPaybondClaudeAgentsConfig,
  type ClaudeAgentsConfig,
} from "../claude-agents/config.js";
import {
  createPaybondCloudflareAgentsConfig,
  type CloudflareAgentsToolSet,
} from "../cloudflare-agents/config.js";
import {
  createPaybondMastraConfig,
  type MastraToolLike,
} from "../mastra/config.js";
import {
  createPaybondGenericAgentConfig,
} from "./generic-runner.js";
import type { PaybondToolRegistry } from "./registry.js";
import type { PaybondAgentRunHost } from "./run.js";
import { PaybondAgentRun } from "./run.js";
import type { PaybondAgentRunBindInput, PaybondRunBindingAttachInput } from "./types.js";

export type GuardedAgentFramework =
  | "generic"
  | "openai-agents"
  | "vercel-ai"
  | "langgraph"
  | "claude-agents"
  | "mastra"
  | "cloudflare-agents";

export type CreateGuardedAgentInput<TTools = unknown> = {
  policy: PaybondPolicyLoadSource | PaybondPolicy;
  /** Agent-agnostic wrapping when omitted. Pass a framework only when SDK-specific hooks are required. */
  framework?: GuardedAgentFramework;
  tools: TTools;
  /** Sandbox bootstrap options; ignored when `attach` is set. */
  bootstrap?: PaybondPolicySandboxBootstrapOptions;
  attach?: PaybondRunBindingAttachInput;
  runId?: string;
  traceSink?: import("./types.js").PaybondTraceSink;
  /** @deprecated Use {@link CreateGuardedAgentInput.traceSink}. */
  onTrace?: import("./types.js").PaybondTraceSink;
  validatePolicy?: boolean | PolicyValidatorOptions;
  openAIAgentsOptions?: PaybondOpenAIAgentsAdapterOptions;
};

export type CreateGuardedAgentResultBase = {
  run: PaybondAgentRun;
  policy: PaybondPolicy;
  registry: PaybondToolRegistry;
  framework: GuardedAgentFramework;
  agentTools: unknown;
  toolApproval?: ReturnType<typeof paybondVercelToolApproval>;
  awrapToolCall?: PaybondLangGraphAwrapToolCall;
  createToolNode?: (
    tools: Parameters<typeof paybondToolNode>[0],
    options?: ToolNodeOptions,
  ) => ReturnType<typeof paybondToolNode>;
  openAIAgentsAdapter?: ReturnType<typeof createOpenAIAgentsAdapter>;
  runConfig?: ReturnType<typeof createOpenAIAgentsAdapter>["runConfig"];
  claudeAgentsConfig?: ClaudeAgentsConfig;
};

export type CreateGuardedAgentResult<TTools = unknown> = CreateGuardedAgentResultBase & {
  agentTools: TTools;
};

async function resolvePolicy(source: PaybondPolicyLoadSource | PaybondPolicy): Promise<PaybondPolicy> {
  if (source instanceof PaybondPolicy) {
    return source;
  }
  return PaybondPolicy.load(source);
}

async function maybeValidatePolicy(
  policy: PaybondPolicy,
  validatePolicy: CreateGuardedAgentInput["validatePolicy"],
): Promise<void> {
  if (!validatePolicy) {
    return;
  }
  const options = validatePolicy === true ? undefined : validatePolicy;
  const result = await policy.validate(options);
  if (!result.valid) {
    const messages = result.errors.map((entry) => entry.message).join("; ");
    throw new Error(`policy validation failed: ${messages}`);
  }
}


async function bindGuardedRun(
  paybond: PaybondAgentRunHost,
  policy: PaybondPolicy,
  input: CreateGuardedAgentInput,
): Promise<PaybondAgentRun> {
  const registry = policy.toToolRegistry();
  const bindInput: PaybondAgentRunBindInput = {
    registry,
    runId: input.runId,
    traceSink: input.traceSink,
    onTrace: input.onTrace,
  };
  if (input.attach) {
    bindInput.attach = input.attach;
  } else {
    bindInput.bootstrap = policy.sandboxBootstrap(input.bootstrap ?? {});
  }
  return PaybondAgentRun.bind(paybond, bindInput);
}

/** Policy-driven agent factory: load policy, bind a run, and wire framework tools. */
export async function createGuardedAgent<TTools>(
  paybond: PaybondAgentRunHost,
  input: CreateGuardedAgentInput<TTools>,
): Promise<CreateGuardedAgentResult<TTools>> {
  const policy = await resolvePolicy(input.policy);
  await maybeValidatePolicy(policy, input.validatePolicy);

  const registry = policy.toToolRegistry();
  const run = await bindGuardedRun(paybond, policy, input);
  const base = { run, policy, registry };
  const framework = input.framework ?? "generic";

  switch (framework) {
    case "generic": {
      const config = createPaybondGenericAgentConfig(run, input.tools);
      return { ...base, framework: "generic", agentTools: config.tools } as CreateGuardedAgentResult<TTools>;
    }
    case "vercel-ai": {
      const config = createPaybondVercelAgentConfig(run, input.tools as ToolSet);
      return {
        ...base,
        framework: "vercel-ai",
        agentTools: config.tools,
        toolApproval: config.toolApproval,
      } as CreateGuardedAgentResult<TTools>;
    }
    case "openai-agents": {
      const config = createPaybondOpenAIAgentsConfig(
        run,
        input.tools as Array<FunctionTool>,
        input.openAIAgentsOptions,
      );
      const adapter = createOpenAIAgentsAdapter(run, input.openAIAgentsOptions);
      return {
        ...base,
        framework: "openai-agents",
        agentTools: config.tools,
        openAIAgentsAdapter: adapter,
        runConfig: config.runConfig,
      } as CreateGuardedAgentResult<TTools>;
    }
    case "langgraph": {
      const hooks = createPaybondLangGraphHooks(run);
      return {
        ...base,
        framework: "langgraph",
        agentTools: input.tools,
        awrapToolCall: hooks.awrapToolCall,
        createToolNode: hooks.createToolNode,
      } as CreateGuardedAgentResult<TTools>;
    }
    case "claude-agents": {
      const claudeAgentsConfig = createPaybondClaudeAgentsConfig(
        run,
        input.tools as Parameters<typeof createPaybondClaudeAgentsConfig>[1],
      );
      return {
        ...base,
        framework: "claude-agents",
        agentTools: claudeAgentsConfig.agentTools,
        claudeAgentsConfig,
      } as CreateGuardedAgentResult<TTools>;
    }
    case "mastra": {
      const config = createPaybondMastraConfig(run, input.tools as MastraToolLike[]);
      return {
        ...base,
        framework: "mastra",
        agentTools: config.tools,
      } as CreateGuardedAgentResult<TTools>;
    }
    case "cloudflare-agents": {
      const config = createPaybondCloudflareAgentsConfig(
        run,
        input.tools as CloudflareAgentsToolSet,
      );
      return {
        ...base,
        framework: "cloudflare-agents",
        agentTools: config.tools,
        toolApproval: config.toolApproval,
      } as CreateGuardedAgentResult<TTools>;
    }
    default: {
      const exhaustive: never = framework;
      throw new Error(`unsupported guarded agent framework: ${String(exhaustive)}`);
    }
  }
}

/** Alias for {@link createGuardedAgent} matching facade runner naming. */
export const createGuardedAgentRunner = createGuardedAgent;
