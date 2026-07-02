import { tool } from "@anthropic-ai/claude-agent-sdk";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { createGuardedAgent, createGuardedAgentRunner } from "../../src/agent/guarded-agent.js";
import {
  PaybondAgentRun,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { PaybondPolicy } from "../../src/policy/index.js";

const TRAVEL_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: 20000,
      evidence_preset: "cost_and_completion",
    },
    "search.web": {
      side_effecting: false,
    },
  },
  intent: {
    allowed_tools: ["travel.book_hotel"],
    budget: { currency: "usd", max_spend_usd: 200 },
  },
} as const;

function makeProductionEvidence() {
  return {
    payeeDid: "did:web:vendor.example",
    payeeSigningSeed: new Uint8Array(32).fill(1),
    agentRecognitionKeyId: "kid-1",
    agentRecognitionSigningSeed: new Uint8Array(32).fill(2),
  };
}

function makeHost(overrides?: Partial<PaybondAgentRunHost>): PaybondAgentRunHost {
  return {
    harbor: {
      tenantId: "tenant-a",
      getIntent: async () => ({
        tenant_id: "tenant-a",
        allowed_tools: ["travel.book_hotel"],
      }),
      submitEvidence: vi.fn(async () => ({
        intentId: "40000000-0000-4000-8000-000000000010",
        tenant: "tenant-a",
        state: "completed",
      })),
    },
    guardrails: {
      bootstrapSandbox: vi.fn(async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "travel.book_hotel",
        requested_spend_cents: 20_000,
        sandbox_lifecycle_status: "funded",
      })),
      submitSandboxEvidence: vi.fn(async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        sandbox_lifecycle_status: "completed",
        predicate_passed: true,
      })),
    },
    spendGuard: () => ({
      assertSpendAuthorized: async () => ({
        allow: true,
        auditId: "audit-stub",
      }),
      completeSpendAuthorization: async () => {},
    }),
    ...overrides,
  };
}

describe("createGuardedAgent", () => {
  it("loads policy, binds sandbox run, and wraps generic tools from a record", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));
    const searchWeb = vi.fn(async () => ({ hits: [] }));

    const result = await createGuardedAgent(host, {
      policy: TRAVEL_POLICY,
      framework: "generic",
      tools: {
        "travel.book_hotel": bookHotel,
        "search.web": searchWeb,
      },
    });

    expect(result.framework).toBe("generic");
    expect(result.policy.name).toBe("travel-agent-v1");
    expect(result.registry.defaultDeny).toBe(true);
    expect(result.run.intentId).toBe("intent-sandbox");
    expect(result.agentTools).toHaveLength(2);
    expect(host.guardrails.bootstrapSandbox).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
        completionPreset: "cost_and_completion",
      }),
    );

    const paidTool = result.agentTools.find((tool) => tool.name === "travel.book_hotel");
    expect(paidTool).toBeDefined();
    const wrapped = await paidTool!.execute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 20_000 },
    });
    expect(wrapped.toolResult).toEqual({ status: "completed", cost_cents: 20_000 });
    expect(bookHotel).toHaveBeenCalledWith({ estimatedPriceCents: 20_000 });
  });

  it("accepts a pre-loaded PaybondPolicy instance", async () => {
    const policy = await PaybondPolicy.load(TRAVEL_POLICY);
    const result = await createGuardedAgent(makeHost(), {
      policy,
      framework: "generic",
      tools: [{ name: "search.web", execute: async () => ({ ok: true }) }],
    });

    expect(result.policy).toBe(policy);
    expect(result.agentTools).toHaveLength(1);
  });

  it("binds attach mode without sandbox bootstrap", async () => {
    const host = makeHost();
    const result = await createGuardedAgent(host, {
      policy: TRAVEL_POLICY,
      framework: "generic",
      tools: [{ name: "travel.book_hotel", execute: async () => ({ ok: true }) }],
      attach: {
        intentId: "40000000-0000-4000-8000-000000000010",
        capabilityToken: "cap-prod",
        allowedTools: ["travel.book_hotel"],
        productionEvidence: makeProductionEvidence(),
      },
    });

    expect(host.guardrails.bootstrapSandbox).not.toHaveBeenCalled();
    expect(result.run.intentId).toBe("40000000-0000-4000-8000-000000000010");
  });

  it("re-uses PaybondAgentRun.bind for sandbox bootstrap", async () => {
    const host = makeHost();
    const bindSpy = vi.spyOn(PaybondAgentRun, "bind");
    await createGuardedAgent(host, {
      policy: TRAVEL_POLICY,
      framework: "generic",
      tools: [{ name: "search.web", execute: async () => ({ ok: true }) }],
    });
    expect(bindSpy).toHaveBeenCalledOnce();
    bindSpy.mockRestore();
  });

  it("wires langgraph hooks without wrapping raw tools", async () => {
    const rawTools = [{ name: "search.web" }];
    const result = await createGuardedAgent(makeHost(), {
      policy: TRAVEL_POLICY,
      framework: "langgraph",
      tools: rawTools,
    });

    expect(result.framework).toBe("langgraph");
    expect(result.agentTools).toBe(rawTools);
    expect(result.awrapToolCall).toBeTypeOf("function");
    expect(result.createToolNode).toBeTypeOf("function");
  });

  it("wraps claude-agents SDK tools and returns MCP server config", async () => {
    const host = makeHost();
    const bookHotelHandler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: JSON.stringify({ status: "completed", cost_cents: 20_000 }) }],
      structuredContent: { status: "completed", cost_cents: 20_000 },
    }));
    const searchWebHandler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: "[]" }],
    }));

    const tools = [
      tool(
        "travel.book_hotel",
        "Book a hotel",
        { estimatedPriceCents: z.number() },
        bookHotelHandler,
      ),
      tool("search.web", "Search the web", { query: z.string() }, searchWebHandler),
    ];

    const result = await createGuardedAgent(host, {
      policy: TRAVEL_POLICY,
      framework: "claude-agents",
      tools,
    });

    expect(result.framework).toBe("claude-agents");
    expect(result.claudeAgentsConfig?.allowedTools).toEqual([
      "mcp__paybond__travel.book_hotel",
      "mcp__paybond__search.web",
    ]);
    expect(result.claudeAgentsConfig?.mcpServer).toBeDefined();
    expect(result.agentTools).toBe(tools);

    await tools[0]!.handler({ estimatedPriceCents: 20_000 }, { toolUseID: "call-claude-1" });
    expect(bookHotelHandler).toHaveBeenCalledWith(
      { estimatedPriceCents: 20_000 },
      { toolUseID: "call-claude-1" },
    );
    expect(host.guardrails.bootstrapSandbox).toHaveBeenCalled();
  });

  it("exposes createGuardedAgentRunner as an alias", async () => {
    expect(createGuardedAgentRunner).toBe(createGuardedAgent);
  });
});
