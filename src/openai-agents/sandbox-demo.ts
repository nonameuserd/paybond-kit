import { type FunctionTool } from "@openai/agents";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { createPaybondOpenAIAgentsConfig } from "./index.js";

export type RunOpenAIAgentsSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunOpenAIAgentsSandboxDemoResult = {
  bind: {
    run_id: string;
    tenant_id: string;
    intent_id: string;
    capability_token: string;
    operation: string;
    sandbox_lifecycle_status?: string;
  };
  guardrail: {
    behavior: string;
  };
  execute: {
    tool_result?: unknown;
    evidence?: {
      submitted: boolean;
      sandbox_lifecycle_status?: string;
      predicate_passed?: boolean | null;
    };
  };
};

function makePaidFunctionTool(name: string): FunctionTool {
  return {
    type: "function",
    name,
    description: `Paid operation ${name}`,
    parameters: {
      type: "object",
      properties: {
        estimatedPriceCents: { type: "integer", minimum: 0 },
      },
      required: ["estimatedPriceCents"],
      additionalProperties: false,
    },
    strict: false,
    invoke: async (_runContext, input) => {
      const args = JSON.parse(input) as { estimatedPriceCents: number };
      return JSON.stringify({
        status: "completed",
        cost_cents: args.estimatedPriceCents,
      });
    },
    needsApproval: async () => false,
    isEnabled: async () => true,
  };
}

/**
 * No-LLM OpenAI Agents SDK sandbox demo: input guardrail pre-check + guarded
 * `invoke` + auto-evidence.
 */
export async function runOpenAIAgentsSandboxDemo(
  input: RunOpenAIAgentsSandboxDemoInput,
): Promise<RunOpenAIAgentsSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "openai-demo-1").trim();

  const registry = createPaybondToolRegistry({
    defaultDeny: true,
    sideEffecting: {
      [operation]: {
        operation,
        evidencePreset,
        spendCents: (args: unknown) =>
          typeof args === "object" &&
          args !== null &&
          "estimatedPriceCents" in args &&
          typeof (args as { estimatedPriceCents: unknown }).estimatedPriceCents === "number"
            ? (args as { estimatedPriceCents: number }).estimatedPriceCents
            : requestedSpendCents,
        evidenceMapper: (result) => {
          const payload = result as { status: string; cost_cents: number };
          return {
            status: payload.status,
            cost_cents: payload.cost_cents,
          };
        },
      },
    },
  });

  const run = await input.paybond.agentRun.bind({
    bootstrap: {
      kind: "sandbox",
      operation,
      requestedSpendCents,
      completionPreset: evidencePreset,
    },
    registry,
  });

  const paidTool = makePaidFunctionTool(operation);
  const config = createPaybondOpenAIAgentsConfig(run, [paidTool]);
  const guarded = config.tools[0];
  if (!guarded) {
    throw new Error("openai-agents sandbox demo missing guarded tool");
  }

  const toolCall = {
    type: "function_call" as const,
    name: operation,
    callId: toolCallId,
    arguments: JSON.stringify({ estimatedPriceCents: requestedSpendCents }),
  };

  const guardrail = guarded.inputGuardrails?.[0];
  const guardrailResult = guardrail
    ? await guardrail.run({
        agent: {} as never,
        context: {} as never,
        toolCall,
      })
    : undefined;

  const output = (await guarded.invoke(
    {} as never,
    JSON.stringify({ estimatedPriceCents: requestedSpendCents }),
    { toolCall },
  )) as string;

  let toolResult: unknown;
  try {
    toolResult = JSON.parse(output) as unknown;
  } catch {
    toolResult = output;
  }

  const sandboxStatus = run.binding.sandbox?.sandboxLifecycleStatus;

  return {
    bind: {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation,
      sandbox_lifecycle_status: sandboxStatus,
    },
    guardrail: {
      behavior: guardrailResult?.behavior.type ?? "not-applicable",
    },
    execute: {
      tool_result: toolResult,
      evidence: {
        submitted: true,
        sandbox_lifecycle_status: sandboxStatus,
        predicate_passed: true,
      },
    },
  };
}
