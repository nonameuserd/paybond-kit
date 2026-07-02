import { describe, expect, it, vi } from "vitest";
import {
  ToolGuardrailFunctionOutputFactory,
  type FunctionTool,
} from "@openai/agents";
import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import {
  createOpenAIAgentsAdapter,
  createPaybondOpenAIAgentsConfig,
  mapPaybondDecisionToOpenAIToolGuardrail,
  paybondOpenAIAgentsRunConfig,
} from "../../src/openai-agents/index.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
        evidencePreset: "cost_and_completion",
        evidenceMapper: (result: { reservation: { status: string; price_cents: number } }) => ({
          status: "completed",
          cost_cents: result.reservation.price_cents,
        }),
      },
    },
    defaultDeny: true,
  });
}

function makeGuard(): PaybondRunGuard {
  return {
    assertSpendAuthorized: vi.fn(async () => ({
      allow: true,
      auditId: "audit-1",
      decisionId: "decision-1",
    })),
    completeSpendAuthorization: vi.fn(async () => {}),
  };
}

function makeHost(guard: PaybondRunGuard): PaybondAgentRunHost {
  return {
    harbor: { tenantId: "tenant-a", getIntent: async () => ({ allowed_tools: ["travel.book_hotel"] }) },
    guardrails: {
      bootstrapSandbox: async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "travel.book_hotel",
        requested_spend_cents: 20_000,
        sandbox_lifecycle_status: "funded",
      }),
      submitSandboxEvidence: vi.fn(async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        sandbox_lifecycle_status: "completed",
        predicate_passed: true,
      })),
    },
    spendGuard: () => guard,
  };
}

function makeFunctionTool(name: string, handler: () => Promise<string>): FunctionTool {
  return {
    type: "function",
    name,
    description: `${name} tool`,
    parameters: { type: "object", properties: {}, additionalProperties: true },
    strict: false,
    invoke: async () => handler(),
    needsApproval: async () => false,
    isEnabled: async () => true,
  };
}

describe("mapPaybondDecisionToOpenAIToolGuardrail", () => {
  it("maps allow and deny decisions to OpenAI guardrail output", () => {
    const allow = mapPaybondDecisionToOpenAIToolGuardrail({
      kind: "allow",
      auditId: "audit-1",
      operation: "travel.book_hotel",
    });
    expect(allow.behavior).toEqual({ type: "allow" });

    const deny = mapPaybondDecisionToOpenAIToolGuardrail({
      kind: "deny",
      message: "budget exceeded",
    });
    expect(deny.behavior).toEqual({
      type: "rejectContent",
      message: "budget exceeded",
    });
    expect(ToolGuardrailFunctionOutputFactory.rejectContent("x").behavior.type).toBe("rejectContent");
  });
});

describe("createOpenAIAgentsAdapter", () => {
  it("exposes pre-approval run config and guards side-effecting function tools", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const adapter = createOpenAIAgentsAdapter(run);
    expect(adapter.runConfig).toEqual(paybondOpenAIAgentsRunConfig);

    const bookHotel = makeFunctionTool("travel.book_hotel", async () =>
      JSON.stringify({ reservation: { status: "confirmed", price_cents: 18_700 } }),
    );
    const searchWeb = makeFunctionTool("search.web", async () => "ok");

    const [guardedHotel, guardedSearch] = adapter.guardFunctionTools([bookHotel, searchWeb]);
    expect(guardedSearch).toBe(searchWeb);
    expect(guardedHotel.inputGuardrails?.length).toBe(1);

    const guardrail = guardedHotel.inputGuardrails![0]!;
    const preCheck = await guardrail.run({
      agent: {} as never,
      context: {} as never,
      toolCall: {
        type: "function_call",
        name: "travel.book_hotel",
        callId: "call-1",
        arguments: JSON.stringify({ estimatedPriceCents: 18_700 }),
      },
    });
    expect(preCheck.behavior.type).toBe("allow");

    const output = await guardedHotel.invoke({} as never, JSON.stringify({ estimatedPriceCents: 18_700 }), {
      toolCall: {
        type: "function_call",
        name: "travel.book_hotel",
        callId: "call-1",
        arguments: JSON.stringify({ estimatedPriceCents: 18_700 }),
      },
    });
    expect(output).toContain("confirmed");
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
  });
});

describe("createPaybondOpenAIAgentsConfig", () => {
  it("returns guarded tools and runConfig", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const bookHotel = makeFunctionTool("travel.book_hotel", async () => "ok");
    const config = createPaybondOpenAIAgentsConfig(run, [bookHotel]);

    expect(config.runConfig).toEqual(paybondOpenAIAgentsRunConfig);
    expect(config.tools).toHaveLength(1);
    expect(config.tools[0]?.inputGuardrails?.length).toBe(1);
  });
});
