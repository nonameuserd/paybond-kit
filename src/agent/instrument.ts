import type { PaybondPolicy, PaybondPolicyLoadSource } from "../policy/load.js";
import { PaybondPolicy as PaybondPolicyClass } from "../policy/load.js";
import type { PaybondPolicyDocumentV1 } from "../policy/schema.js";
import { wrapDeferredTools } from "./deferred-tools.js";
import { PaybondLazyContextError, wrapLazyContextTools } from "./lazy-context-tools.js";
import {
  attachPaybondAgentInstrumentation,
  discoverPolicyFromAgent,
  discoverToolsFromAgent,
  isInstrumentableAgentObject,
  type PaybondAgentInstrumentation,
  type PaybondInstrumentAgentOptions,
} from "./discover.js";
import {
  createGuardedAgent,
  type CreateGuardedAgentInput,
  type CreateGuardedAgentResult,
  type GuardedAgentFramework,
} from "./guarded-agent.js";
import {
  toPaybondAgentResult,
  wrapPaybondTools,
  type PaybondAgentHooks,
  type PaybondWrapToolsOptions,
} from "./facade.js";
import { PaybondAgentRun, type PaybondAgentRunHost } from "./run.js";
import type {
  PaybondRunBinding,
  PaybondRunBindingAttachInput,
  PaybondRunProductionEvidenceCredentials,
  PaybondTraceSink,
} from "./types.js";
import {
  resolveAttachContextFromEnv,
  type PaybondAttachEnvRecord,
} from "./attach-bundle.js";

/** Production attach from console env vars or an explicit funded-intent binding. */
export type PaybondInstrumentAttachInput = PaybondRunBindingAttachInput | "env";

/** Simplified inline policy for tutorials and quick examples. */
export type PaybondInlinePolicy = {
  name?: string;
  budget?: string | { max_spend_usd?: number; currency?: string; period?: string };
  approve?: readonly string[];
  deny?: readonly string[];
};

/** Intent + capability for a single agent session, HTTP request, or task. */
export type PaybondInstrumentContext = {
  intentId: string;
  capabilityToken: string;
  /** Optional operator or end-user id for audit attribution (`agentSubject` on intercept). */
  userId?: string;
  allowedTools?: readonly string[];
  productionEvidence?: PaybondRunProductionEvidenceCredentials;
  sandbox?: PaybondRunBinding["sandbox"];
};

/** Resolves request-local intent binding on each tool execution. */
export type PaybondInstrumentContextProvider = () =>
  | PaybondInstrumentContext
  | Promise<PaybondInstrumentContext>;

/** Static bind object or per-request provider passed to {@link instrumentPaybondAgent}. */
export type PaybondInstrumentContextInput =
  | PaybondInstrumentContext
  | PaybondInstrumentContextProvider;

/**
 * Where the active intent comes from — inspect via `.binding` or `.status` on any instrument surface.
 */
export type PaybondInstrumentBinding =
  | { phase: "deferred" }
  | { phase: "lazy" }
  | {
      phase: "bound";
      mode: "sandbox" | "attach";
      intentId: string;
      capabilityToken: string;
      tenantId: string;
      userId?: string;
    };

export type {
  PaybondAgentInstrumentation,
  PaybondInstrumentAgentOptions,
} from "./discover.js";
export { PaybondUnboundContextError, wrapDeferredTools } from "./deferred-tools.js";
export {
  PaybondLazyContextError,
  wrapLazyContextTools,
  type LazyRuntimeResolver,
} from "./lazy-context-tools.js";
export {
  discoverPolicyFromAgent,
  discoverToolsFromAgent,
  isInstrumentableAgentObject,
  readPaybondAgentInstrumentation,
} from "./discover.js";

type PaybondInstrumentBaseInput<TTools = unknown> = Omit<
  CreateGuardedAgentInput<TTools>,
  "framework" | "policy" | "tools" | "attach"
> & {
  policy?: PaybondPolicyLoadSource | PaybondInlinePolicy | PaybondPolicy;
  tools?: TTools;
  framework?: GuardedAgentFramework;
  /** Bootstrap a sandbox intent immediately (local dev). Default is deferred bind via {@link PaybondInstrumented.bind}. */
  sandbox?: boolean;
  /**
   * Attach a funded production intent from console env vars (`attach: "env"`) or an explicit binding object.
   * Returns a bound {@link PaybondInstrumentRuntime} immediately.
   */
  attach?: PaybondInstrumentAttachInput;
  /**
   * Attach a funded intent during `instrument()` and return a bound {@link PaybondInstrumentRuntime},
   * or pass a provider function for lazy per-execution binding (request-local context).
   */
  context?: PaybondInstrumentContextInput;
};

/** Input for {@link instrumentPaybondAgent} — pass `{ policy, tools }` or a framework agent instance. */
export type PaybondInstrumentInput<TTools = unknown> = PaybondInstrumentBaseInput<TTools>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isFullPolicyDocument(value: Record<string, unknown>): boolean {
  return (
    typeof value.version === "number" ||
    typeof value.default_deny === "boolean" ||
    (isRecord(value.tools) &&
      Object.values(value.tools).some(
        (entry) => isRecord(entry) && typeof entry.side_effecting === "boolean",
      ))
  );
}

export function isInlinePolicy(value: unknown): value is PaybondInlinePolicy {
  if (!isRecord(value)) {
    return false;
  }
  if (isFullPolicyDocument(value)) {
    return false;
  }
  return "budget" in value || "approve" in value || "deny" in value;
}

function globPatternToRegExp(pattern: string): RegExp {
  const escaped = pattern
    .trim()
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

function matchesAnyGlob(value: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => globPatternToRegExp(pattern).test(value));
}

function parseBudgetString(
  budget: string,
): NonNullable<PaybondPolicyDocumentV1["intent"]>["budget"] {
  const trimmed = budget.trim();
  const match = /^\$?([\d,]+(?:\.\d+)?)(?:\s*\/\s*(day|week|month|year))?$/i.exec(trimmed);
  if (!match) {
    throw new Error(`inline policy budget must look like "$500/day" (got ${JSON.stringify(budget)})`);
  }
  const amount = Number.parseFloat(match[1]!.replace(/,/g, ""));
  const period = match[2]?.toLowerCase();
  return {
    currency: "usd",
    max_spend_usd: amount,
    ...(period ? { period } : {}),
  };
}

function resolveInlineBudget(
  budget: PaybondInlinePolicy["budget"],
): NonNullable<PaybondPolicyDocumentV1["intent"]>["budget"] | undefined {
  if (budget === undefined) {
    return undefined;
  }
  if (typeof budget === "string") {
    return parseBudgetString(budget);
  }
  return {
    currency: budget.currency ?? "usd",
    ...(budget.max_spend_usd !== undefined ? { max_spend_usd: budget.max_spend_usd } : {}),
    ...(budget.period ? { period: budget.period } : {}),
  };
}

export function discoverToolNames(tools: unknown): string[] {
  if (Array.isArray(tools)) {
    const names: string[] = [];
    for (const tool of tools) {
      if (!isRecord(tool) || typeof tool.name !== "string" || !tool.name.trim()) {
        throw new TypeError("discovered tool array entries must include a non-empty name");
      }
      names.push(tool.name.trim());
    }
    return names;
  }
  if (isRecord(tools)) {
    return Object.keys(tools).filter((key) => key.trim().length > 0);
  }
  throw new TypeError("could not discover tool names; pass an object map or { name, execute }[]");
}

export function inlinePolicyToDocument(
  inline: PaybondInlinePolicy,
  tools: unknown,
): PaybondPolicyDocumentV1 {
  const toolNames = discoverToolNames(tools);
  const approve = inline.approve ?? ["*"];
  const deny = inline.deny ?? [];
  const allowedTools: string[] = [];
  const toolsSection: PaybondPolicyDocumentV1["tools"] = {};

  for (const toolName of toolNames) {
    if (deny.length > 0 && matchesAnyGlob(toolName, deny)) {
      continue;
    }
    if (!matchesAnyGlob(toolName, approve)) {
      continue;
    }
    allowedTools.push(toolName);
    toolsSection[toolName] = {
      side_effecting: true,
      evidence_preset: "cost_and_completion",
    };
  }

  if (allowedTools.length === 0) {
    throw new Error("inline policy matched no tools; widen approve patterns or pass explicit tools");
  }

  const budget = resolveInlineBudget(inline.budget);
  return {
    version: 1,
    name: inline.name ?? "inline-policy",
    default_deny: true,
    tools: toolsSection,
    intent: {
      allowed_tools: allowedTools,
      ...(budget ? { budget } : {}),
    },
  };
}

function isContextProvider(
  value: PaybondInstrumentContextInput,
): value is PaybondInstrumentContextProvider {
  return typeof value === "function";
}

function runtimeCacheKey(context: PaybondInstrumentContext): string {
  return `${context.intentId}\0${context.capabilityToken}\0${context.userId ?? ""}`;
}

function assertInstrumentContext(context: PaybondInstrumentContext): void {
  if (!context.intentId?.trim() || !context.capabilityToken?.trim()) {
    throw new PaybondLazyContextError();
  }
}

function resolveInstrumentAttachContext(
  attach: PaybondInstrumentAttachInput | undefined,
  env: PaybondAttachEnvRecord = process.env as PaybondAttachEnvRecord,
): PaybondInstrumentContext | undefined {
  if (attach === undefined) {
    return undefined;
  }
  if (attach === "env") {
    const resolved = resolveAttachContextFromEnv(env);
    return {
      intentId: resolved.intentId,
      capabilityToken: resolved.capabilityToken,
      productionEvidence: resolved.productionEvidence,
    };
  }
  return {
    intentId: attach.intentId,
    capabilityToken: attach.capabilityToken,
    allowedTools: attach.allowedTools,
    productionEvidence: attach.productionEvidence,
    sandbox: attach.sandbox,
  };
}

function normalizeInstrumentConfig<TTools>(
  input: PaybondInstrumentBaseInput<TTools>,
): PaybondInstrumentBaseInput<TTools> & { tools: TTools } {
  if (input.tools === undefined) {
    throw new Error("instrument() requires tools when using { policy, tools } config");
  }
  if (input.policy === undefined) {
    throw new Error("instrument() requires policy when using { policy, tools } config");
  }
  if (input.sandbox && (input.context !== undefined || input.attach !== undefined)) {
    throw new Error('instrument() accepts either sandbox: true, attach, or context — not multiple bind modes');
  }
  if (input.attach !== undefined && input.context !== undefined) {
    throw new Error('instrument() accepts either attach or context, not both');
  }
  return { ...input, tools: input.tools };
}

async function resolveInstrumentPolicy<TTools>(
  policySource: PaybondPolicyLoadSource | PaybondInlinePolicy | PaybondPolicy | undefined,
  tools: TTools,
): Promise<PaybondPolicy> {
  if (policySource instanceof PaybondPolicyClass) {
    return policySource;
  }
  if (policySource === undefined) {
    throw new Error("instrument() requires policy (file path, preset id, inline object, or PaybondPolicy)");
  }
  if (isInlinePolicy(policySource)) {
    return PaybondPolicyClass.fromDocument(inlinePolicyToDocument(policySource, tools));
  }
  return PaybondPolicyClass.load(policySource);
}

function bindingFromRun(
  run: PaybondAgentRun,
  mode: "sandbox" | "attach",
  userId?: string,
): Extract<PaybondInstrumentBinding, { phase: "bound" }> {
  return {
    phase: "bound",
    mode,
    intentId: run.binding.intentId,
    capabilityToken: run.binding.capabilityToken,
    tenantId: run.binding.tenantId,
    ...(userId ? { userId } : {}),
  };
}

function hooksFromGuardedResult(result: CreateGuardedAgentResult): PaybondAgentHooks {
  return toPaybondAgentResult(result).hooks;
}

function wrapToolsForFramework<TTools>(
  run: PaybondAgentRun,
  rawTools: TTools,
  framework: GuardedAgentFramework,
  guarded?: CreateGuardedAgentResult<TTools>,
): TTools {
  if (framework === "langgraph") {
    return rawTools;
  }
  if (guarded) {
    return guarded.agentTools as TTools;
  }
  return wrapPaybondTools(run, rawTools, { framework }) as TTools;
}

/**
 * Bound Paybond runtime for one agent session — immutable; create a new runtime per request.
 */
export class PaybondInstrumentRuntime<TTools = unknown> {
  readonly tools: TTools;
  readonly run: PaybondAgentRun;
  readonly policy: PaybondPolicy;
  readonly hooks: PaybondAgentHooks;
  readonly binding: Extract<PaybondInstrumentBinding, { phase: "bound" }>;

  constructor(
    tools: TTools,
    run: PaybondAgentRun,
    policy: PaybondPolicy,
    hooks: PaybondAgentHooks,
    binding: Extract<PaybondInstrumentBinding, { phase: "bound" }>,
  ) {
    this.tools = tools;
    this.run = run;
    this.policy = policy;
    this.hooks = hooks;
    this.binding = binding;
  }

  /** Alias for {@link PaybondInstrumentRuntime.binding}. */
  get status(): PaybondInstrumentBinding {
    return this.binding;
  }

  /** Release hooks for this runtime (no-op today; reserved for long-lived sessions). */
  close(): void {}
}

/**
 * Static instrumentation: policy + tool shells. Call {@link PaybondInstrumented.bind}
 * per session, or pass a `context` provider for lazy per-execution binding.
 */
export class PaybondInstrumented<TTools = unknown> {
  readonly tools: TTools;
  readonly policy: PaybondPolicy;
  readonly binding: Extract<PaybondInstrumentBinding, { phase: "deferred" } | { phase: "lazy" }>;

  private readonly paybond: PaybondAgentRunHost;
  private readonly rawTools: TTools;
  private readonly framework: GuardedAgentFramework;
  private readonly contextProvider?: PaybondInstrumentContextProvider;
  private readonly traceSink?: PaybondTraceSink;
  private readonly runtimeCache = new Map<string, PaybondInstrumentRuntime<TTools>>();

  constructor(
    paybond: PaybondAgentRunHost,
    policy: PaybondPolicy,
    rawTools: TTools,
    framework: GuardedAgentFramework,
    options?: { contextProvider?: PaybondInstrumentContextProvider; traceSink?: PaybondTraceSink },
  ) {
    this.paybond = paybond;
    this.policy = policy;
    this.rawTools = rawTools;
    this.framework = framework;
    this.contextProvider = options?.contextProvider;
    this.traceSink = options?.traceSink;
    this.binding = options?.contextProvider ? { phase: "lazy" } : { phase: "deferred" };
    this.tools = options?.contextProvider
      ? wrapLazyContextTools(rawTools, { resolve: () => this.resolveRuntimeFromProvider() })
      : wrapDeferredTools(rawTools);
  }

  /** Alias for {@link PaybondInstrumented.binding}. */
  get status(): PaybondInstrumentBinding {
    return this.binding;
  }

  private async resolveRuntime(context: PaybondInstrumentContext): Promise<PaybondInstrumentRuntime<TTools>> {
    assertInstrumentContext(context);
    const key = runtimeCacheKey(context);
    const cached = this.runtimeCache.get(key);
    if (cached) {
      return cached;
    }
    const runtime = await createBoundRuntime(
      this.paybond,
      this.policy,
      this.rawTools,
      this.framework,
      context,
      "attach",
      this.traceSink,
    );
    this.runtimeCache.set(key, runtime);
    return runtime;
  }

  private async resolveRuntimeFromProvider(): Promise<PaybondInstrumentRuntime<TTools>> {
    if (!this.contextProvider) {
      throw new Error("lazy context resolution requires a context provider on instrument()");
    }
    const context = await this.contextProvider();
    return this.resolveRuntime(context);
  }

  /**
   * Bind a per-request intent and capability. Returns a new immutable runtime — safe for concurrent sessions.
   */
  bind(context: PaybondInstrumentContext): Promise<PaybondInstrumentRuntime<TTools>> {
    return createBoundRuntime(
      this.paybond,
      this.policy,
      this.rawTools,
      this.framework,
      context,
      "attach",
      this.traceSink,
    );
  }

  /** @deprecated Use {@link PaybondInstrumented.bind}. */
  withContext(context: PaybondInstrumentContext): Promise<PaybondInstrumentRuntime<TTools>> {
    return this.bind(context);
  }
}

async function createBoundRuntime<TTools>(
  paybond: PaybondAgentRunHost,
  policy: PaybondPolicy,
  rawTools: TTools,
  framework: GuardedAgentFramework,
  context: PaybondInstrumentContext,
  bindMode: "sandbox" | "attach",
  traceSink?: PaybondTraceSink,
): Promise<PaybondInstrumentRuntime<TTools>> {
  if (bindMode === "sandbox") {
    const result = await createGuardedAgent(paybond, {
      policy,
      framework,
      tools: rawTools,
      traceSink,
    });
    return toPaybondInstrumentRuntime(
      result,
      rawTools,
      result.run.binding.sandbox ? "sandbox" : "attach",
      context.userId,
    );
  }

  const attach: PaybondRunBindingAttachInput = {
    intentId: context.intentId,
    capabilityToken: context.capabilityToken,
    allowedTools: context.allowedTools,
    productionEvidence: context.productionEvidence,
    sandbox: context.sandbox,
  };
  const run = await PaybondAgentRun.bind(paybond, {
    registry: policy.toToolRegistry(),
    attach,
    traceSink,
  });
  const tools = wrapToolsForFramework(run, rawTools, framework);
  const hooks = hooksFromGuardedResult({
    run,
    policy,
    registry: policy.toToolRegistry(),
    framework,
    agentTools: tools,
  } as CreateGuardedAgentResult<TTools>);
  return new PaybondInstrumentRuntime(
    tools,
    run,
    policy,
    hooks,
    bindingFromRun(run, "attach", context.userId),
  );
}

function toPaybondInstrumentRuntime<TTools>(
  result: CreateGuardedAgentResult<TTools>,
  rawTools: TTools,
  bindMode: "sandbox" | "attach",
  userId?: string,
): PaybondInstrumentRuntime<TTools> {
  const agentResult = toPaybondAgentResult(result);
  return new PaybondInstrumentRuntime(
    agentResult.tools,
    agentResult.run,
    agentResult.policy,
    agentResult.hooks,
    bindingFromRun(agentResult.run, bindMode, userId),
  );
}

function createDeferredInstrumented<TTools>(
  paybond: PaybondAgentRunHost,
  policy: PaybondPolicy,
  rawTools: TTools,
  framework: GuardedAgentFramework,
  options?: { contextProvider?: PaybondInstrumentContextProvider; traceSink?: PaybondTraceSink },
): PaybondInstrumented<TTools> {
  return new PaybondInstrumented(paybond, policy, rawTools, framework, options);
}

function resolveInstrumentFramework(framework?: GuardedAgentFramework): GuardedAgentFramework {
  return framework ?? "generic";
}

/** Fluent builder: `paybond.policy("./paybond.policy.yaml").instrument(tools)`. */
export class PaybondInstrumentBuilder<TTools = unknown> {
  constructor(
    private readonly paybond: PaybondAgentRunHost,
    private readonly policy: PaybondPolicyLoadSource | PaybondInlinePolicy,
    private readonly framework?: GuardedAgentFramework,
  ) {}

  instrument(
    tools: TTools,
    options?: { sandbox?: boolean; context?: PaybondInstrumentContextInput },
  ): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
    return instrumentPaybondAgent(this.paybond, {
      policy: this.policy,
      tools,
      framework: this.framework,
      sandbox: options?.sandbox,
      context: options?.context,
    });
  }

  withFramework(framework: GuardedAgentFramework): PaybondInstrumentBuilder<TTools> {
    return new PaybondInstrumentBuilder(this.paybond, this.policy, framework);
  }
}

function instrumentationFromRuntime<TTools>(
  runtime: PaybondInstrumentRuntime<TTools>,
): PaybondAgentInstrumentation {
  return {
    run: runtime.run,
    policy: runtime.policy,
    hooks: runtime.hooks,
    tools: runtime.tools,
    binding: runtime.binding,
    status: runtime.status,
  };
}

function instrumentationFromInstrumented<TTools>(
  agent: object,
  instrumented: PaybondInstrumented<TTools>,
): PaybondAgentInstrumentation {
  const surface: PaybondAgentInstrumentation = {
    policy: instrumented.policy,
    hooks: {},
    tools: instrumented.tools,
    binding: instrumented.binding,
    status: instrumented.status,
    bind: async (context) => {
      const runtime = await instrumented.bind(context);
      const bound = instrumentationFromRuntime(runtime);
      attachPaybondAgentInstrumentation(agent, bound, runtime.tools);
      return bound;
    },
    withContext: async (context) => surface.bind!(context),
  };
  return surface;
}

async function instrumentAgentObject<TAgent extends object>(
  paybond: PaybondAgentRunHost,
  agent: TAgent,
  options?: PaybondWrapToolsOptions & PaybondInstrumentAgentOptions,
): Promise<TAgent> {
  const rawTools = discoverToolsFromAgent(agent);
  const policySource = discoverPolicyFromAgent(agent, options);
  const framework = resolveInstrumentFramework(options?.framework);
  const policy = await resolveInstrumentPolicy(policySource, rawTools);
  const traceSink = options?.traceSink ?? options?.onTrace;

  if (options?.sandbox) {
    const runtime = await createBoundRuntime(
      paybond,
      policy,
      rawTools,
      framework,
      { intentId: "", capabilityToken: "" },
      "sandbox",
      traceSink,
    );
    attachPaybondAgentInstrumentation(agent, instrumentationFromRuntime(runtime), runtime.tools);
    return agent;
  }

  if (options?.context) {
    if (isContextProvider(options.context)) {
      const instrumented = createDeferredInstrumented(paybond, policy, rawTools, framework, {
        contextProvider: options.context,
        traceSink,
      });
      attachPaybondAgentInstrumentation(
        agent,
        instrumentationFromInstrumented(agent, instrumented),
        instrumented.tools,
      );
      return agent;
    }
    const runtime = await createBoundRuntime(
      paybond,
      policy,
      rawTools,
      framework,
      options.context,
      "attach",
      traceSink,
    );
    attachPaybondAgentInstrumentation(agent, instrumentationFromRuntime(runtime), runtime.tools);
    return agent;
  }

  const instrumented = createDeferredInstrumented(paybond, policy, rawTools, framework, { traceSink });
  attachPaybondAgentInstrumentation(
    agent,
    instrumentationFromInstrumented(agent, instrumented),
    instrumented.tools,
  );
  return agent;
}

export async function instrumentPaybondAgent<TTools>(
  paybond: PaybondAgentRunHost,
  input: PaybondInstrumentInput<TTools>,
  options?: PaybondWrapToolsOptions & PaybondInstrumentAgentOptions,
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>>;
export async function instrumentPaybondAgent<TAgent extends object>(
  paybond: PaybondAgentRunHost,
  agent: TAgent,
  options?: PaybondWrapToolsOptions & PaybondInstrumentAgentOptions,
): Promise<TAgent>;
export async function instrumentPaybondAgent<TTools, TAgent extends object>(
  paybond: PaybondAgentRunHost,
  input: PaybondInstrumentInput<TTools> | TAgent,
  options?: PaybondWrapToolsOptions & PaybondInstrumentAgentOptions,
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools> | TAgent> {
  if (isInstrumentableAgentObject(input)) {
    return instrumentAgentObject(paybond, input as TAgent, options);
  }

  const normalized = normalizeInstrumentConfig(input as PaybondInstrumentInput<TTools>);
  const framework = resolveInstrumentFramework(options?.framework ?? normalized.framework);
  const policy = await resolveInstrumentPolicy(normalized.policy, normalized.tools);
  const traceSink = normalized.traceSink ?? normalized.onTrace;
  const sandbox = normalized.sandbox ?? options?.sandbox ?? false;
  const attachContext = resolveInstrumentAttachContext(
    normalized.attach ?? options?.attach,
  );
  const context = attachContext ?? normalized.context ?? options?.context;

  if (sandbox) {
    return createBoundRuntime(
      paybond,
      policy,
      normalized.tools,
      framework,
      { intentId: "", capabilityToken: "" },
      "sandbox",
      traceSink,
    );
  }

  if (context !== undefined) {
    if (isContextProvider(context)) {
      return createDeferredInstrumented(paybond, policy, normalized.tools, framework, {
        contextProvider: context,
        traceSink,
      });
    }
    return createBoundRuntime(paybond, policy, normalized.tools, framework, context, "attach", traceSink);
  }

  return createDeferredInstrumented(paybond, policy, normalized.tools, framework, { traceSink });
}

function frameworkInstrument<TTools>(
  paybond: PaybondAgentRunHost,
  framework: GuardedAgentFramework,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return instrumentPaybondAgent(paybond, { ...input, framework });
}

export function instrumentPaybondLangGraph<TTools>(
  paybond: PaybondAgentRunHost,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return frameworkInstrument(paybond, "langgraph", input);
}

export function instrumentPaybondOpenAI<TTools>(
  paybond: PaybondAgentRunHost,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return frameworkInstrument(paybond, "openai-agents", input);
}

export function instrumentPaybondVercel<TTools>(
  paybond: PaybondAgentRunHost,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return frameworkInstrument(paybond, "vercel-ai", input);
}

export function instrumentPaybondClaudeAgents<TTools>(
  paybond: PaybondAgentRunHost,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return frameworkInstrument(paybond, "claude-agents", input);
}

export function instrumentPaybondMCP<TTools>(
  paybond: PaybondAgentRunHost,
  input: Omit<PaybondInstrumentBaseInput<TTools>, "framework"> & { tools: TTools },
): Promise<PaybondInstrumented<TTools> | PaybondInstrumentRuntime<TTools>> {
  return frameworkInstrument(paybond, "generic", input);
}
