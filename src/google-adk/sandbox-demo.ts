import { createRequire } from "node:module";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { createPaybondGoogleAdkConfig } from "./config.js";

export type RunGoogleAdkSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunGoogleAdkSandboxDemoResult = {
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
  };
  tool_result?: unknown;
  evidence?: {
    submitted: boolean;
    sandbox_lifecycle_status?: string;
    predicate_passed?: boolean | null;
  };
  tool_call_id: string;
};

function loadFunctionTool(): new (options: {
  name?: string;
  description: string;
  parameters?: unknown;
  execute: (input: unknown) => unknown | Promise<unknown>;
}) => { name: string; execute: (input: unknown) => unknown | Promise<unknown> } {
  try {
    const require = createRequire(import.meta.url);
    const mod = require("@google/adk") as {
      FunctionTool: new (options: {
        name?: string;
        description: string;
        parameters?: unknown;
        execute: (input: unknown) => unknown | Promise<unknown>;
      }) => { name: string; execute: (input: unknown) => unknown | Promise<unknown> };
    };
    return mod.FunctionTool;
  } catch (err) {
    throw new Error(
      'The Google ADK sandbox demo requires the optional peer dependency "@google/adk"; install it with: npm install @google/adk',
      { cause: err },
    );
  }
}

/**
 * No-LLM Google ADK sandbox demo: guarded FunctionTool execution + auto-evidence.
 */
export async function runGoogleAdkSandboxDemo(
  input: RunGoogleAdkSandboxDemoInput,
): Promise<RunGoogleAdkSandboxDemoResult> {
  const FunctionTool = loadFunctionTool();
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "google-adk-demo-1").trim();

  const registry = createPaybondToolRegistry({
    defaultDeny: true,
    sideEffecting: {
      [operation]: {
        operation,
        evidencePreset,
        spendCents: requestedSpendCents,
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

  const paidTool = new FunctionTool({
    name: operation,
    description: `Paid operation ${operation}`,
    execute: (args: unknown) => {
      const estimated =
        typeof args === "object" &&
        args !== null &&
        "estimatedPriceCents" in args &&
        typeof (args as { estimatedPriceCents: unknown }).estimatedPriceCents ===
          "number"
          ? (args as { estimatedPriceCents: number }).estimatedPriceCents
          : requestedSpendCents;
      return { status: "completed", cost_cents: estimated };
    },
  });

  const config = createPaybondGoogleAdkConfig(run, [paidTool]);
  const guarded = config.tools[0];
  if (!guarded || typeof guarded.execute !== "function") {
    throw new Error("google-adk sandbox demo missing guarded tool");
  }

  const sandboxStatus = run.binding.sandbox?.sandboxLifecycleStatus;
  let allow = true;
  let toolResult: unknown;

  try {
    toolResult = await guarded.execute({
      estimatedPriceCents: requestedSpendCents,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.startsWith("Paybond")) {
      allow = false;
      toolResult = { error: message };
    } else {
      throw err;
    }
  }

  return {
    bind: {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation,
      sandbox_lifecycle_status: sandboxStatus,
    },
    authorization: { allow },
    tool_result: toolResult,
    evidence: {
      submitted: allow,
      sandbox_lifecycle_status: sandboxStatus,
      predicate_passed: allow ? true : null,
    },
    tool_call_id: toolCallId,
  };
}
