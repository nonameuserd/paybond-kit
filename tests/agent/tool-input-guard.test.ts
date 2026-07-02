import { describe, expect, it, vi } from "vitest";
import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  createToolInputGuardAdapter,
  paybondToolInputGuardAdapter,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../../src/index.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
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

describe("createToolInputGuardAdapter", () => {
  it("exposes evaluate and wrapExecutors on a stable adapter name", () => {
    const adapter = createToolInputGuardAdapter({} as PaybondAgentRun);
    expect(adapter.name).toBe("tool-input-guard");
    expect(paybondToolInputGuardAdapter({} as PaybondAgentRun).name).toBe("tool-input-guard");
  });

  it("evaluate allows read-only tools without Harbor verify", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const decision = await createToolInputGuardAdapter(run).evaluate({
      toolName: "lookup.weather",
      toolCallId: "call-readonly",
      arguments: { city: "Lisbon" },
    });

    expect(decision).toEqual({
      kind: "allow",
      passthrough: true,
      operation: "lookup.weather",
    });
    expect(guard.assertSpendAuthorized).not.toHaveBeenCalled();
  });

  it("evaluate authorizes side-effecting tools and caches for wrapExecute", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const adapter = createToolInputGuardAdapter(run);
    const decision = await adapter.evaluate({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 18_700 },
    });

    expect(decision).toMatchObject({
      kind: "allow",
      operation: "travel.book_hotel",
      auditId: "audit-1",
      decisionId: "decision-1",
    });
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();

    const [wrapped] = adapter.wrapExecutors([
      {
        name: "travel.book_hotel",
        execute: async () => ({ reservation: { status: "confirmed", price_cents: 18_700 } }),
      },
    ]);

    const result = await wrapped.execute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 18_700 },
    });

    expect(result.evidence?.submitted).toBe(true);
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
  });

  it("maps approval holds and denials to structured decisions", async () => {
    const host = makeHost(makeGuard());
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    run.binding.guard.assertSpendAuthorized = vi.fn(async () => {
      throw new PaybondSpendApprovalRequiredError({
        allow: false,
        auditId: "audit-hold",
        approvalRequired: true,
        message: "needs operator approval",
      });
    });

    const approval = await createToolInputGuardAdapter(run).evaluate({
      toolName: "travel.book_hotel",
      toolCallId: "call-hold",
      arguments: { estimatedPriceCents: 100 },
    });
    expect(approval.kind).toBe("approval_required");

    run.binding.guard.assertSpendAuthorized = vi.fn(async () => {
      throw new PaybondSpendDeniedError({
        allow: false,
        auditId: "audit-deny",
        message: "budget exceeded",
      });
    });

    const deny = await createToolInputGuardAdapter(run).evaluate({
      toolName: "travel.book_hotel",
      toolCallId: "call-deny",
      arguments: { estimatedPriceCents: 100 },
    });
    expect(deny).toMatchObject({ kind: "deny", message: expect.stringContaining("budget exceeded") });
  });
});
