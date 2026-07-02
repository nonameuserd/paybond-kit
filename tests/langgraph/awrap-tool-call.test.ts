import { describe, expect, it, vi } from "vitest";
import { ToolMessage } from "@langchain/core/messages";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../../src/index.js";
import {
  paybondAwrapToolCall,
  paybondToolNode,
} from "../../src/langgraph/index.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: unknown) =>
          typeof args === "object" &&
          args !== null &&
          "estimatedPriceCents" in args &&
          typeof (args as { estimatedPriceCents: unknown }).estimatedPriceCents === "number"
            ? (args as { estimatedPriceCents: number }).estimatedPriceCents
            : 0,
        evidencePreset: "cost_and_completion",
      },
    },
    defaultDeny: true,
  });
}

function makeGuard(overrides?: Partial<PaybondRunGuard>): PaybondRunGuard {
  return {
    assertSpendAuthorized: vi.fn(async () => ({
      allow: true,
      auditId: "audit-1",
      decisionId: "decision-1",
    })),
    completeSpendAuthorization: vi.fn(async () => {}),
    ...overrides,
  };
}

function makeHost(guard: PaybondRunGuard): PaybondAgentRunHost {
  return {
    harbor: {
      tenantId: "tenant-a",
      getIntent: async () => ({
        tenant_id: "tenant-a",
        allowed_tools: ["travel.book_hotel"],
      }),
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

describe("paybondAwrapToolCall", () => {
  it("allows registered tools, executes, and submits evidence", async () => {
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

    const awrap = paybondAwrapToolCall(run);
    const executed = vi.fn(async () => ({ status: "confirmed", cost_cents: 18_700 }));
    const request = {
      tool_call: {
        name: "travel.book_hotel",
        id: "call-lg-1",
        args: { estimatedPriceCents: 18_700 },
      },
    };

    const out = await awrap(request, async () => executed());

    expect(out).toEqual({ status: "confirmed", cost_cents: 18_700 });
    expect(executed).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalled();
  });

  it("resolves spend from registry tool args on verify", async () => {
    const assertSpendAuthorized = vi.fn(async (input) => {
      expect(input.requestedSpendCents).toBe(15_500);
      return {
        allow: true,
        auditId: "audit-1",
        decisionId: "decision-1",
      };
    });
    const guard = makeGuard({ assertSpendAuthorized });
    const host = makeHost(guard);
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": {
          spendCents: (args: unknown) =>
            typeof args === "object" && args !== null && "priceCents" in args
              ? (args as { priceCents: number }).priceCents
              : 0,
          evidencePreset: "cost_and_completion",
        },
      },
      defaultDeny: true,
    });
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry,
    });

    const awrap = paybondAwrapToolCall(run);
    await awrap(
      {
        tool_call: {
          name: "travel.book_hotel",
          id: "call-spend-registry",
          args: { priceCents: 15_500 },
        },
      },
      async () => ({ status: "confirmed" }),
    );

    expect(assertSpendAuthorized).toHaveBeenCalledOnce();
  });

  it("returns error ToolMessage on deny without executing", async () => {
    const guard = makeGuard({
      assertSpendAuthorized: vi.fn(async () => {
        throw new PaybondSpendDeniedError({
          allow: false,
          auditId: "audit-deny",
          message: "blocked",
        });
      }),
    });
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const awrap = paybondAwrapToolCall(run);
    const executed = vi.fn();
    const out = await awrap(
      {
        tool_call: {
          name: "travel.book_hotel",
          id: "call-deny",
          args: { estimatedPriceCents: 18_700 },
        },
      },
      executed,
    );

    expect(out).toBeInstanceOf(ToolMessage);
    const message = out as ToolMessage;
    expect(message.status).toBe("error");
    expect(String(message.content)).toContain("blocked");
    expect(executed).not.toHaveBeenCalled();
  });

  it("returns approval hold ToolMessage with decision id", async () => {
    const guard = makeGuard({
      assertSpendAuthorized: vi.fn(async () => {
        throw new PaybondSpendApprovalRequiredError({
          allow: false,
          approvalRequired: true,
          auditId: "audit-hold",
          decisionId: "decision-hold",
          message: "needs approval",
        });
      }),
    });
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const awrap = paybondAwrapToolCall(run);
    const out = await awrap(
      {
        tool_call: {
          name: "travel.book_hotel",
          id: "call-hold",
          args: { estimatedPriceCents: 18_700 },
        },
      },
      vi.fn(),
    );

    expect(out).toBeInstanceOf(ToolMessage);
    const message = out as ToolMessage;
    expect(message.status).toBe("error");
    expect(String(message.content)).toContain("decision-hold");
    expect(String(message.content)).toContain("needs approval");
  });
});

describe("paybondToolNode", () => {
  it("wraps ToolNode execution with the Paybond interceptor", async () => {
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

    const { AIMessage } = await import("@langchain/core/messages");
    const { tool } = await import("@langchain/core/tools");
    const { z } = await import("zod");

    const bookHotel = tool(
      async (args: { estimatedPriceCents: number }) => ({
        status: "confirmed",
        cost_cents: args.estimatedPriceCents,
      }),
      {
        name: "travel.book_hotel",
        description: "Book hotel",
        schema: z.object({ estimatedPriceCents: z.number().int().nonnegative() }),
      },
    );

    const node = paybondToolNode([bookHotel], run);
    const out = await node.invoke([
      new AIMessage({
        content: "",
        tool_calls: [
          {
            name: "travel.book_hotel",
            args: { estimatedPriceCents: 18_700 },
            id: "call-node-1",
            type: "tool_call",
          },
        ],
      }),
    ]);

    const messages = Array.isArray(out) ? out : out.messages;
    const toolMessage = messages[messages.length - 1];
    expect(toolMessage.status).toBe("success");
    expect(String(toolMessage.content)).toContain("confirmed");
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalled();
  });
});
