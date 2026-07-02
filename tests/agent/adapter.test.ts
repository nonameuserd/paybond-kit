import { describe, expect, it, vi } from "vitest";
import {
  PaybondAgentRun,
  createGenericToolExecutor,
  createPaybondToolRegistry,
  paybondGenericToolExecutorAdapter,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";

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

describe("PaybondFrameworkAdapter / createGenericToolExecutor", () => {
  it("exposes a stable generic adapter name", () => {
    const adapter = createGenericToolExecutor();
    expect(adapter.name).toBe("generic");
    expect(paybondGenericToolExecutorAdapter).toBe(adapter);
  });

  it("wraps tool execute handlers through run.interceptor.wrapExecute", async () => {
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

    const adapter = createGenericToolExecutor();
    const [wrapped] = adapter.wrapTools(run, [
      {
        name: "travel.book_hotel",
        description: "Book a hotel room",
        execute: async (args: { city: string; estimatedPriceCents: number }) => ({
          reservation: { status: "confirmed", price_cents: args.estimatedPriceCents },
        }),
      },
    ]) as Array<{
      name: string;
      description: string;
      execute: (call: {
        toolName: string;
        toolCallId: string;
        arguments: { city: string; estimatedPriceCents: number };
      }) => Promise<{ toolResult: unknown; evidence?: { submitted: true } }>;
    }>;

    expect(wrapped.name).toBe("travel.book_hotel");
    expect(wrapped.description).toBe("Book a hotel room");

    const result = await wrapped.execute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { city: "Lisbon", estimatedPriceCents: 18_700 },
    });

    expect(result.toolResult).toEqual({
      reservation: { status: "confirmed", price_cents: 18_700 },
    });
    expect(result.evidence?.submitted).toBe(true);
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalledOnce();
  });

  it("passes read-only tools through without verify", async () => {
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

    const [wrapped] = createGenericToolExecutor().wrapTools(run, [
      {
        name: "lookup.weather",
        execute: async () => ({ tempC: 21 }),
      },
    ]) as Array<{
      execute: (call: {
        toolName: string;
        toolCallId: string;
        arguments: Record<string, never>;
      }) => Promise<{ toolResult: unknown }>;
    }>;

    const result = await wrapped.execute({
      toolName: "lookup.weather",
      toolCallId: "call-readonly",
      arguments: {},
    });

    expect(result).toEqual({ toolResult: { tempC: 21 } });
    expect(guard.assertSpendAuthorized).not.toHaveBeenCalled();
  });

  it("rejects invalid tool definitions", () => {
    const adapter = createGenericToolExecutor();
    expect(() => adapter.wrapTools({} as PaybondAgentRun, "not-an-array")).toThrow(TypeError);
    expect(() => adapter.wrapTools({} as PaybondAgentRun, [{ name: "x" }])).toThrow(TypeError);
  });
});
