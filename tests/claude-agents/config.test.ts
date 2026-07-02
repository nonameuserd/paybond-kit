import { tool } from "@anthropic-ai/claude-agent-sdk";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import { createPaybondClaudeAgentsConfig } from "../../src/claude-agents/index.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
        evidencePreset: "cost_and_completion",
        evidenceMapper: (result: { status: string; cost_cents: number }) => ({
          status: result.status,
          cost_cents: result.cost_cents,
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
  const submitSandboxEvidence = vi.fn(async () => ({
    tenant_id: "tenant-a",
    intent_id: "intent-sandbox",
    sandbox_lifecycle_status: "completed",
    predicate_passed: true,
  }));

  return {
    harbor: {
      tenantId: "tenant-a",
      getIntent: async () => ({ allowed_tools: ["travel.book_hotel"] }),
    },
    guardrails: {
      bootstrapSandbox: async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "travel.book_hotel",
        requested_spend_cents: 20_000,
        sandbox_lifecycle_status: "funded",
      }),
      submitSandboxEvidence,
    },
    spendGuard: () => guard,
  };
}

describe("createPaybondClaudeAgentsConfig", () => {
  it("wraps only side-effecting SDK tools and builds MCP server config", async () => {
    const guard = makeGuard();
    const host = makeHost(guard);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const bookHotelHandler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: JSON.stringify({ status: "completed", cost_cents: 18_700 }) }],
      structuredContent: { status: "completed", cost_cents: 18_700 },
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

    const config = createPaybondClaudeAgentsConfig(run, tools, { serverName: "paybond" });

    expect(config.allowedTools).toEqual([
      "mcp__paybond__travel.book_hotel",
      "mcp__paybond__search.web",
    ]);
    expect(config.mcpServer).toBeDefined();
    expect(config.agentTools).toBe(tools);

    const hotelResult = await tools[0]!.handler(
      { estimatedPriceCents: 18_700 },
      { toolUseID: "call-claude-1" },
    );
    expect(hotelResult.structuredContent).toEqual({ status: "completed", cost_cents: 18_700 });
    expect(bookHotelHandler).toHaveBeenCalledOnce();
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalledOnce();

    await tools[1]!.handler({ query: "paris hotels" }, { toolUseID: "call-claude-2" });
    expect(searchWebHandler).toHaveBeenCalledOnce();
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
  });

  it("passes stored approval tokens into wrapped handlers", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    run.storeApprovalToken("call-token", "operator-token-456");

    const handler = vi.fn(async () => ({
      content: [{ type: "text" as const, text: JSON.stringify({ status: "completed", cost_cents: 100 }) }],
      structuredContent: { status: "completed", cost_cents: 100 },
    }));

    const tools = [
      tool(
        "travel.book_hotel",
        "Book a hotel",
        { estimatedPriceCents: z.number() },
        handler,
      ),
    ];

    createPaybondClaudeAgentsConfig(run, tools);
    await tools[0]!.handler({ estimatedPriceCents: 100 }, { toolUseID: "call-token" });

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({ approvalToken: "operator-token-456" }),
    );
  });

  it("rejects non-SDK tool definitions", async () => {
    const run = await PaybondAgentRun.bind(makeHost(makeGuard()), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    expect(() => createPaybondClaudeAgentsConfig(run, [{ name: "x" }] as never)).toThrow(
      /handler function/,
    );
    expect(() => createPaybondClaudeAgentsConfig(run, "not-an-array" as never)).toThrow(
      /SDK tool\(\) definitions/,
    );
  });
});
