import { generateText, jsonSchema, stepCountIs, tool } from "ai";
import { MockLanguageModelV4 } from "ai/test";

import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { paybondVercelToolApproval } from "./tool-approval.js";
import { paybondVercelWrapTools } from "./wrap-tools.js";

export type RunVercelAiSandboxDemoInput = {
  paybond: Paybond;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
  toolCallId?: string;
};

export type RunVercelAiSandboxDemoResult = {
  bind: {
    run_id: string;
    tenant_id: string;
    intent_id: string;
    capability_token: string;
    operation: string;
    sandbox_lifecycle_status?: string;
  };
  tool_approval: string | { type: string; reason?: string };
  generate_text: {
    text: string;
    step_count: number;
    tool_calls: number;
  };
  execute: {
    tool_result?: unknown;
    authorization?: {
      audit_id?: string;
      decision_id?: string;
    };
    evidence?: {
      submitted: boolean;
      sandbox_lifecycle_status?: string;
      predicate_passed?: boolean | null;
    };
  };
};

function mockUsage() {
  return {
    inputTokens: { total: 3, noCache: 3, cacheRead: undefined, cacheWrite: undefined },
    outputTokens: { total: 10, text: 10, reasoning: undefined },
  };
}

async function executePaidTool(args: { estimatedPriceCents: number }) {
  return { status: "completed", cost_cents: args.estimatedPriceCents };
}

async function searchWeb(args: { query: string }) {
  return { hits: [{ title: args.query, url: "https://example.com" }] };
}

/**
 * No-LLM Vercel AI SDK sandbox demo: `toolApproval` + wrapped `execute` + auto-evidence.
 * Uses `MockLanguageModelV4` — no provider API key required.
 */
export async function runVercelAiSandboxDemo(
  input: RunVercelAiSandboxDemoInput,
): Promise<RunVercelAiSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();
  const toolCallId = (input.toolCallId ?? "vercel-demo-1").trim();

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

  const rawTools = {
    [operation]: tool({
      description: `Paid operation ${operation}`,
      inputSchema: jsonSchema<{ estimatedPriceCents: number }>({
        type: "object",
        properties: {
          estimatedPriceCents: { type: "integer", minimum: 0 },
        },
        required: ["estimatedPriceCents"],
        additionalProperties: false,
      }),
      execute: async (args) => executePaidTool(args),
    }),
    "search.web": tool({
      description: "Read-only web search",
      inputSchema: jsonSchema<{ query: string }>({
        type: "object",
        properties: { query: { type: "string" } },
        required: ["query"],
        additionalProperties: false,
      }),
      execute: async (args) => searchWeb(args),
    }),
  };

  const tools = paybondVercelWrapTools(run, rawTools);
  const toolApproval = paybondVercelToolApproval(run);
  const toolInput = { estimatedPriceCents: requestedSpendCents };

  const approvalStatus = await toolApproval({
    toolCall: {
      type: "tool-call",
      toolName: operation,
      toolCallId,
      input: toolInput,
    },
    tools,
    toolsContext: {} as never,
    runtimeContext: undefined as never,
    messages: [],
  });

  let stepCount = 0;
  const generated = await generateText({
    model: new MockLanguageModelV4({
      doGenerate: [
        {
          content: [
            {
              type: "tool-call",
              toolCallId,
              toolName: operation,
              input: JSON.stringify(toolInput),
            },
          ],
          finishReason: { unified: "tool-calls", raw: "tool_calls" },
          usage: mockUsage(),
          warnings: [],
        },
        {
          content: [{ type: "text", text: "paid tool completed" }],
          finishReason: { unified: "stop", raw: "stop" },
          usage: mockUsage(),
          warnings: [],
        },
      ],
    }),
    tools,
    toolApproval: toolApproval as Parameters<typeof generateText>[0]["toolApproval"],
    stopWhen: stepCountIs(5),
    prompt: "run the paid tool",
  });
  stepCount = generated.steps.length;

  const paidToolResult = generated.toolResults.find((entry) => entry.toolName === operation);

  return {
    bind: {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation,
      sandbox_lifecycle_status: run.binding.sandbox?.sandboxLifecycleStatus,
    },
    tool_approval:
      approvalStatus === undefined
        ? "not-applicable"
        : typeof approvalStatus === "string"
          ? approvalStatus
          : { type: approvalStatus.type },
    generate_text: {
      text: generated.text,
      step_count: stepCount,
      tool_calls: generated.toolCalls.length,
    },
    execute: {
      tool_result: paidToolResult?.output,
      evidence: paidToolResult
        ? {
            submitted: true,
            sandbox_lifecycle_status: run.binding.sandbox?.sandboxLifecycleStatus,
          }
        : undefined,
    },
  };
}
