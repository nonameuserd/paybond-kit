import { tool, jsonSchema } from "ai";
import { describe, expect, it, vi } from "vitest";
import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import { paybondVercelWrapTools } from "../../src/vercel-ai/wrap-tools.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
        evidencePreset: "cost_and_completion",
        evidenceMapper: (result: { reservation: { status: string; price_cents: number } }) => ({
          status: result.reservation.status === "confirmed" ? "completed" : result.reservation.status,
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

describe("paybondVercelWrapTools", () => {
  it("wraps only side-effecting client-executed tools", async () => {
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

    const bookHotelExecute = vi.fn(async (args: { estimatedPriceCents: number }) => ({
      reservation: { status: "confirmed", price_cents: args.estimatedPriceCents },
    }));
    const searchWebExecute = vi.fn(async (args: { query: string }) => ({ hits: [args.query] }));

    const rawTools = {
      "travel.book_hotel": tool({
        description: "Book hotel",
        inputSchema: jsonSchema<{ estimatedPriceCents: number }>({
          type: "object",
          properties: { estimatedPriceCents: { type: "integer" } },
          required: ["estimatedPriceCents"],
        }),
        execute: bookHotelExecute,
      }),
      "search.web": tool({
        description: "Search web",
        inputSchema: jsonSchema<{ query: string }>({
          type: "object",
          properties: { query: { type: "string" } },
          required: ["query"],
        }),
        execute: searchWebExecute,
      }),
    };

    const wrapped = paybondVercelWrapTools(run, rawTools);
    expect(wrapped["search.web"].execute).toBe(rawTools["search.web"].execute);

    const output = await wrapped["travel.book_hotel"].execute!(
      { estimatedPriceCents: 18_700 },
      { toolCallId: "call-wrap-1", messages: [] },
    );

    expect(output).toEqual({
      reservation: { status: "confirmed", price_cents: 18_700 },
    });
    expect(bookHotelExecute).toHaveBeenCalledOnce();
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalledOnce();
    expect(searchWebExecute).not.toHaveBeenCalled();
  });

  it("passes approval tokens into wrapped execute verify", async () => {
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

    const wrapped = paybondVercelWrapTools(run, {
      "travel.book_hotel": tool({
        description: "Book hotel",
        inputSchema: jsonSchema<{ estimatedPriceCents: number }>({
          type: "object",
          properties: { estimatedPriceCents: { type: "integer" } },
          required: ["estimatedPriceCents"],
        }),
        execute: async () => ({
          reservation: { status: "confirmed", price_cents: 100 },
        }),
      }),
    });

    await wrapped["travel.book_hotel"].execute!(
      { estimatedPriceCents: 100 },
      { toolCallId: "call-token", messages: [] },
    );

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({ approvalToken: "operator-token-456" }),
    );
  });
});
