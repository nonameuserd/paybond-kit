import { createPaybondGenericAgentConfig } from "./generic-runner.js";
import { createPaybondToolRegistry } from "./registry.js";
import type { Paybond } from "../index.js";

export type RunGenericSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunGenericSandboxDemoResult = {
  bind: {
    run_id: string;
    tenant_id: string;
    intent_id: string;
    capability_token: string;
    operation: string;
    sandbox_lifecycle_status?: string;
  };
  authorization: {
    allow: boolean;
    audit_id?: string;
    decision_id?: string;
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

async function executePaidTool(args: { estimatedPriceCents: number }) {
  return { status: "completed", cost_cents: args.estimatedPriceCents };
}

/**
 * No-LLM agent-agnostic sandbox demo: `createPaybondGenericAgentConfig` +
 * wrapped execute + auto-evidence.
 */
export async function runGenericSandboxDemo(
  input: RunGenericSandboxDemoInput,
): Promise<RunGenericSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "generic-demo-1").trim();

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

  const config = createPaybondGenericAgentConfig(run, [
    { name: operation, execute: executePaidTool },
  ]);
  const wrapped = config.tools.find((tool) => tool.name === operation);
  if (!wrapped) {
    throw new Error(`generic sandbox demo missing wrapped tool ${operation}`);
  }

  const wrappedResult = await wrapped.execute({
    toolName: operation,
    toolCallId,
    arguments: { estimatedPriceCents: requestedSpendCents },
  });

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
    authorization: {
      allow: true,
      audit_id: wrappedResult.authorization?.auditId,
      decision_id: wrappedResult.authorization?.decisionId,
    },
    execute: {
      tool_result: wrappedResult.toolResult,
      evidence: {
        submitted: wrappedResult.evidence?.submitted ?? false,
        sandbox_lifecycle_status: sandboxStatus,
        predicate_passed: wrappedResult.evidence?.predicatePassed ?? null,
      },
    },
  };
}
