import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { createPaybondClaudeAgentsConfig } from "./config.js";

export type RunClaudeAgentsSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunClaudeAgentsSandboxDemoResult = {
  bind: {
    run_id: string;
    tenant_id: string;
    intent_id: string;
    capability_token: string;
    operation: string;
    sandbox_lifecycle_status?: string;
  };
  allowed_tools: string[];
  tool_result?: unknown;
  evidence: {
    submitted: boolean;
    sandbox_lifecycle_status?: string;
    predicate_passed?: boolean | null;
  };
};

/**
 * No-LLM Claude Agent SDK sandbox demo: wrapped in-process MCP tool handlers +
 * auto-evidence.
 */
export async function runClaudeAgentsSandboxDemo(
  input: RunClaudeAgentsSandboxDemoInput,
): Promise<RunClaudeAgentsSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "claude-demo-1").trim();

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

  const sdkTools = [
    tool(
      operation,
      `Paid operation ${operation}`,
      { estimatedPriceCents: z.number().int().nonnegative() },
      async (args) => ({
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({
              status: "completed",
              cost_cents: args.estimatedPriceCents,
            }),
          },
        ],
        structuredContent: {
          status: "completed",
          cost_cents: args.estimatedPriceCents,
        },
      }),
    ),
  ];

  const config = createPaybondClaudeAgentsConfig(
    run,
    sdkTools as unknown as Parameters<typeof createPaybondClaudeAgentsConfig>[1],
  );
  const paidTool = config.agentTools[0] as {
    handler: (args: unknown, extra: unknown) => Promise<unknown>;
  };
  if (!paidTool) {
    throw new Error("claude-agents sandbox demo missing paid tool");
  }

  const mcpResult = await paidTool.handler(
    { estimatedPriceCents: requestedSpendCents },
    { toolUseID: toolCallId },
  );

  const sandboxStatus = run.binding.sandbox?.sandboxLifecycleStatus;
  const structured =
    typeof mcpResult === "object" &&
    mcpResult !== null &&
    "structuredContent" in mcpResult &&
    typeof (mcpResult as { structuredContent: unknown }).structuredContent === "object"
      ? (mcpResult as { structuredContent: unknown }).structuredContent
      : undefined;
  const isError =
    typeof mcpResult === "object" &&
    mcpResult !== null &&
    "isError" in mcpResult &&
    Boolean((mcpResult as { isError?: boolean }).isError);

  return {
    bind: {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation,
      sandbox_lifecycle_status: sandboxStatus,
    },
    allowed_tools: config.allowedTools,
    tool_result: structured,
    evidence: {
      submitted: !isError,
      sandbox_lifecycle_status: sandboxStatus,
      predicate_passed: !isError ? true : null,
    },
  };
}
