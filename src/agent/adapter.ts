import type { PaybondAgentRun } from "./run.js";
import type {
  PaybondAuthorizeToolCallInput,
  PaybondInterceptWrapExecuteResult,
  PaybondToolInputGuardDecision,
} from "./types.js";

/**
 * Framework adapter contract: translate framework tool definitions into
 * {@link PaybondAgentRun.interceptor} `wrapExecute` calls. Adapters must not
 * embed Harbor or Gateway logic.
 */
export interface PaybondFrameworkAdapter {
  readonly name: string;
  wrapTools(run: PaybondAgentRun, tools: unknown): unknown;
}

/** Generic tool-call envelope for provider-agnostic runtimes. */
export type PaybondGenericToolCall<TArgs = unknown> = {
  toolName: string;
  toolCallId: string;
  arguments: TArgs;
  operation?: string;
  requestedSpendCents?: number;
  vendorId?: string;
  taskId?: string;
  workflowId?: string;
  currency?: string;
  agentSubject?: string;
  approvalToken?: string;
  idempotencyKey?: string;
};

/** Generic tool definition before middleware wrapping. */
export type PaybondGenericToolDefinition<
  TArgs = unknown,
  TResult = unknown,
  TMeta extends Record<string, unknown> = Record<string, unknown>,
> = TMeta & {
  name: string;
  execute: (args: TArgs) => TResult | Promise<TResult>;
};

/** Generic tool definition after middleware wrapping. */
export type PaybondGenericWrappedToolDefinition<
  TArgs = unknown,
  TResult = unknown,
  TMeta extends Record<string, unknown> = Record<string, unknown>,
> = Omit<PaybondGenericToolDefinition<TArgs, TResult, TMeta>, "execute"> & {
  execute: (
    call: PaybondGenericToolCall<TArgs>,
  ) => Promise<PaybondInterceptWrapExecuteResult<TResult>>;
};

/** Agent-agnostic pre-execution spend guard for any framework runtime. */
export interface PaybondToolInputGuardAdapter {
  readonly name: string;
  /** Authorize-only dry run before side-effecting tool execution. */
  evaluate(input: PaybondAuthorizeToolCallInput): Promise<PaybondToolInputGuardDecision>;
  /** Wrap `{ name, execute }` tools with full middleware (authorize → execute → evidence). */
  wrapExecutors<T extends PaybondGenericToolDefinition>(
    tools: T[],
  ): PaybondGenericWrappedToolDefinition[];
}

function isGenericToolDefinition(value: unknown): value is PaybondGenericToolDefinition {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    typeof record.name === "string" &&
    record.name.trim().length > 0 &&
    typeof record.execute === "function"
  );
}

function assertGenericTools(tools: unknown): PaybondGenericToolDefinition[] {
  if (!Array.isArray(tools)) {
    throw new TypeError(
      "generic tool adapter expects an array of { name, execute } tool definitions",
    );
  }
  for (const tool of tools) {
    if (!isGenericToolDefinition(tool)) {
      throw new TypeError("each generic tool must have a non-empty name and an execute function");
    }
  }
  return tools;
}

function wrapGenericTool<TArgs, TResult>(
  run: PaybondAgentRun,
  tool: PaybondGenericToolDefinition<TArgs, TResult>,
): PaybondGenericWrappedToolDefinition<TArgs, TResult> {
  const { execute: originalExecute, ...rest } = tool;
  return {
    ...rest,
    name: tool.name,
    execute: async (call: PaybondGenericToolCall<TArgs>) =>
      run.interceptor.wrapExecute({
        toolName: call.toolName,
        toolCallId: call.toolCallId,
        arguments: call.arguments,
        execute: () => originalExecute(call.arguments),
        operation: call.operation,
        requestedSpendCents: call.requestedSpendCents,
        vendorId: call.vendorId,
        taskId: call.taskId,
        workflowId: call.workflowId,
        currency: call.currency,
        agentSubject: call.agentSubject,
        approvalToken: call.approvalToken,
        idempotencyKey: call.idempotencyKey,
      }),
  };
}

const genericToolExecutorAdapter: PaybondFrameworkAdapter = {
  name: "generic",
  wrapTools(run: PaybondAgentRun, tools: unknown): PaybondGenericWrappedToolDefinition[] {
    return assertGenericTools(tools).map((tool) => wrapGenericTool(run, tool));
  },
};

/** Provider-agnostic framework adapter for `{ name, execute }` tool definitions. */
export function createGenericToolExecutor(): PaybondFrameworkAdapter {
  return genericToolExecutorAdapter;
}

/** Singleton generic adapter instance. */
export const paybondGenericToolExecutorAdapter = genericToolExecutorAdapter;

/** Build a run-scoped tool input guard adapter (framework-neutral). */
export function createToolInputGuardAdapter(run: PaybondAgentRun): PaybondToolInputGuardAdapter {
  return {
    name: "tool-input-guard",
    evaluate: (input) => run.interceptor.authorizeToolCall(input),
    wrapExecutors: (tools) => assertGenericTools(tools).map((tool) => wrapGenericTool(run, tool)),
  };
}

/** Convenience alias for {@link createToolInputGuardAdapter}. */
export function paybondToolInputGuardAdapter(run: PaybondAgentRun): PaybondToolInputGuardAdapter {
  return createToolInputGuardAdapter(run);
}
