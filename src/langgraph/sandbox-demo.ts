import { AIMessage } from "@langchain/core/messages";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { paybondToolNode } from "./tool-node.js";

export type RunLangGraphSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunLangGraphSandboxDemoResult = {
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
  tool_message: {
    content: string;
    status: string;
    name: string;
    tool_call_id: string;
  };
  evidence: {
    submitted: boolean;
    sandbox_lifecycle_status?: string;
    predicate_passed?: boolean | null;
    intent_state?: string;
  };
  intent_state?: string;
};

async function executePaidTool(args: { estimatedPriceCents: number }) {
  return { status: "completed", cost_cents: args.estimatedPriceCents };
}

/**
 * No-LLM LangGraph sandbox demo: `ToolNode` + Paybond interceptor + auto-evidence.
 */
export async function runLangGraphSandboxDemo(
  input: RunLangGraphSandboxDemoInput,
): Promise<RunLangGraphSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "langgraph-demo-1").trim();

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

  const paidTool = tool(executePaidTool, {
    name: operation,
    description: `Paid operation ${operation}`,
    schema: z.object({
      estimatedPriceCents: z.number().int().nonnegative(),
    }),
  });

  const node = paybondToolNode([paidTool], run);
  const fakeAi = new AIMessage({
    content: "",
    tool_calls: [
      {
        name: operation,
        args: { estimatedPriceCents: requestedSpendCents },
        id: toolCallId,
        type: "tool_call",
      },
    ],
  });

  const out = await node.invoke([fakeAi]);
  const messages = Array.isArray(out) ? out : out.messages;
  const toolMessage = messages[messages.length - 1];

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
      allow: toolMessage.status !== "error",
    },
    tool_message: {
      content: String(toolMessage.content),
      status: String(toolMessage.status ?? "success"),
      name: String(toolMessage.name ?? operation),
      tool_call_id: String(toolMessage.tool_call_id ?? toolCallId),
    },
    evidence: {
      submitted: toolMessage.status !== "error",
      sandbox_lifecycle_status: sandboxStatus,
      predicate_passed: toolMessage.status !== "error" ? true : null,
    },
    intent_state: sandboxStatus,
  };
}
