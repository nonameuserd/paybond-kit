import { z } from "zod";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { createPaybondMastraConfig, type MastraToolLike } from "./config.js";
import { loadMastraCreateTool } from "./peer.js";

export type RunMastraSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunMastraSandboxDemoResult = {
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
 * No-LLM Mastra sandbox demo: wrapped `createTool` execute + auto-evidence.
 * Requires optional peer `@mastra/core`.
 */
export async function runMastraSandboxDemo(
  input: RunMastraSandboxDemoInput,
): Promise<RunMastraSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "mastra-demo-1").trim();

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

  const createTool = loadMastraCreateTool();
  const rawTools = [
    createTool({
      id: operation,
      description: `Paid operation ${operation}`,
      inputSchema: z.object({
        estimatedPriceCents: z.number().int().nonnegative(),
      }),
      execute: async (inputData) => executePaidTool(inputData),
    }),
  ];

  const { tools } = createPaybondMastraConfig(run, rawTools as MastraToolLike[]);
  const guardedTool = tools[0];
  if (!guardedTool?.execute) {
    throw new Error("Mastra sandbox demo missing guarded tool execute handler");
  }

  const toolResult = await guardedTool.execute(
    { estimatedPriceCents: requestedSpendCents },
    { toolCallId },
  );

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
