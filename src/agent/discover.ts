import type { PaybondInlinePolicy } from "./instrument.js";
import type { PaybondPolicyLoadSource } from "../policy/load.js";
import type { PaybondTraceSink } from "./types.js";

const INSTRUMENT_CONFIG_KEYS = new Set([
  "policy",
  "tools",
  "framework",
  "bootstrap",
  "attach",
  "runId",
  "validatePolicy",
  "openAIAgentsOptions",
  "sandbox",
  "context",
]);

/** Metadata attached to framework agent instances after {@link instrumentPaybondAgent}. */
export type PaybondAgentInstrumentation = {
  run?: import("./run.js").PaybondAgentRun;
  policy: import("../policy/load.js").PaybondPolicy;
  hooks: import("./facade.js").PaybondAgentHooks;
  tools?: unknown;
  binding: import("./instrument.js").PaybondInstrumentBinding;
  status?: import("./instrument.js").PaybondInstrumentBinding;
  bind?: (
    context: import("./instrument.js").PaybondInstrumentContext,
  ) => Promise<PaybondAgentInstrumentation>;
  /** @deprecated Use {@link PaybondAgentInstrumentation.bind}. */
  withContext?: (
    context: import("./instrument.js").PaybondInstrumentContext,
  ) => Promise<PaybondAgentInstrumentation>;
};

export type PaybondInstrumentAgentOptions = {
  policy?: PaybondPolicyLoadSource | PaybondInlinePolicy;
  framework?: import("./guarded-agent.js").GuardedAgentFramework;
  sandbox?: boolean;
  attach?: import("./instrument.js").PaybondInstrumentAttachInput;
  context?: import("./instrument.js").PaybondInstrumentContextInput;
  traceSink?: PaybondTraceSink;
  /** @deprecated Use {@link PaybondInstrumentAgentOptions.traceSink}. */
  onTrace?: PaybondTraceSink;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isPlainInstrumentConfig(value: Record<string, unknown>): boolean {
  if (!("policy" in value) || !("tools" in value)) {
    return false;
  }
  return Object.keys(value).every((key) => INSTRUMENT_CONFIG_KEYS.has(key));
}

function hasAgentRuntimeShape(value: Record<string, unknown>): boolean {
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    return true;
  }
  return (
    "model" in value ||
    "run" in value ||
    "invoke" in value ||
    "execute" in value ||
    "stream" in value ||
    "mcpServer" in value ||
    "paybond" in value
  );
}

/**
 * Discover tools from a framework agent instance.
 * Supports tool maps, `{ name, execute }[]`, and common SDK property names.
 */
export function discoverToolsFromAgent(agent: unknown): unknown {
  if (!isRecord(agent)) {
    throw new TypeError("instrument(agent) requires an object with discoverable tools");
  }

  const candidates: unknown[] = [
    agent.tools,
    agent.functionTools,
    agent.function_tools,
    agent.toolDefinitions,
    agent.tool_definitions,
  ];

  for (const candidate of candidates) {
    if (candidate === undefined) {
      continue;
    }
    if (Array.isArray(candidate) && candidate.length === 0) {
      continue;
    }
    if (Array.isArray(candidate) || isRecord(candidate)) {
      return candidate;
    }
  }

  throw new TypeError(
    "could not discover tools on agent; expected .tools, .functionTools, or a tool map/array",
  );
}

/**
 * Resolve policy for agent instrumentation.
 * Order: explicit option → agent.policy → agent.paybondPolicy → PAYBOND_POLICY env → ./paybond.policy.yaml
 */
export function discoverPolicyFromAgent(
  agent: unknown,
  options?: PaybondInstrumentAgentOptions,
): PaybondPolicyLoadSource | PaybondInlinePolicy {
  if (options?.policy !== undefined) {
    return options.policy;
  }
  if (isRecord(agent)) {
    if (agent.policy !== undefined) {
      return agent.policy as PaybondPolicyLoadSource | PaybondInlinePolicy;
    }
    if (agent.paybondPolicy !== undefined) {
      return agent.paybondPolicy as PaybondPolicyLoadSource | PaybondInlinePolicy;
    }
  }
  const envPolicy = typeof process !== "undefined" ? process.env.PAYBOND_POLICY?.trim() : "";
  if (envPolicy) {
    return envPolicy;
  }
  return "./paybond.policy.yaml";
}

/** True when `value` is a framework agent object rather than an explicit `{ policy, tools }` config. */
export function isInstrumentableAgentObject(value: unknown): value is Record<string, unknown> {
  if (!isRecord(value)) {
    return false;
  }
  if (isPlainInstrumentConfig(value) && !hasAgentRuntimeShape(value)) {
    return false;
  }
  if (hasExplicitInstrumentOnlyFields(value)) {
    return false;
  }
  try {
    discoverToolsFromAgent(value);
    return true;
  } catch {
    return false;
  }
}

function hasExplicitInstrumentOnlyFields(value: Record<string, unknown>): boolean {
  return (
    ("attach" in value || "bootstrap" in value || "validatePolicy" in value) &&
  !("tools" in value && hasAgentRuntimeShape(value))
  );
}

const PAYBOND_AGENT_SYMBOL = Symbol.for("paybond.agent.instrumentation");

/** Read Paybond instrumentation previously attached to an agent instance. */
export function readPaybondAgentInstrumentation(
  agent: unknown,
): PaybondAgentInstrumentation | undefined {
  if (!isRecord(agent)) {
    return undefined;
  }
  const attached = (agent as Record<symbol, unknown>)[PAYBOND_AGENT_SYMBOL] as
    | PaybondAgentInstrumentation
    | undefined;
  if (attached) {
    return attached;
  }
  const legacy = agent.paybond as PaybondAgentInstrumentation | undefined;
  return legacy;
}

/** Attach guarded tools and Paybond metadata to a framework agent instance (in place). */
export function attachPaybondAgentInstrumentation(
  agent: object,
  instrumentation: PaybondAgentInstrumentation,
  guardedTools: unknown,
): void {
  const record = agent as Record<string, unknown>;
  if ("tools" in record) {
    record.tools = guardedTools;
  } else if ("functionTools" in record) {
    record.functionTools = guardedTools;
  } else if ("function_tools" in record) {
    record.function_tools = guardedTools;
  } else {
    record.tools = guardedTools;
  }

  Object.defineProperty(agent, PAYBOND_AGENT_SYMBOL, {
    value: instrumentation,
    writable: true,
    configurable: true,
    enumerable: false,
  });
  Object.defineProperty(agent, "paybond", {
    value: instrumentation,
    writable: true,
    configurable: true,
    enumerable: false,
  });
}
