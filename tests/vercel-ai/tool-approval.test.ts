import { describe, expect, it, vi } from "vitest";
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
  mapPaybondDecisionToVercelToolApproval,
  paybondVercelToolApproval,
} from "../../src/vercel-ai/index.js";

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

function makeToolCall(
  toolName: string,
  toolCallId: string,
  input: unknown,
): {
  type: "tool-call";
  toolName: string;
  toolCallId: string;
  input: unknown;
} {
  return { type: "tool-call", toolName, toolCallId, input };
}

describe("mapPaybondDecisionToVercelToolApproval", () => {
  it("maps allow, approval hold, and deny decisions", () => {
    expect(
      mapPaybondDecisionToVercelToolApproval({
        kind: "allow",
        operation: "travel.book_hotel",
      }),
    ).toBe("approved");

    expect(
      mapPaybondDecisionToVercelToolApproval({
        kind: "approval_required",
        message: "needs operator approval",
      }),
    ).toBe("user-approval");

    expect(
      mapPaybondDecisionToVercelToolApproval({
        kind: "deny",
        message: "budget exceeded",
      }),
    ).toEqual({ type: "denied", reason: "budget exceeded" });
  });
});

describe("paybondVercelToolApproval", () => {
  it("approves read-only tools without Harbor verify", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const toolApproval = paybondVercelToolApproval(run);
    const status = await toolApproval({
      toolCall: makeToolCall("search.web", "call-readonly", { query: "hotels" }),
      tools: undefined,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(status).toBe("approved");
    expect(guard.assertSpendAuthorized).not.toHaveBeenCalled();
  });

  it("authorizes side-effecting tools via Harbor verify", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const toolApproval = paybondVercelToolApproval(run);
    const status = await toolApproval({
      toolCall: makeToolCall("travel.book_hotel", "call-1", {
        city: "Lisbon",
        estimatedPriceCents: 18_700,
      }),
      tools: undefined,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(status).toBe("approved");
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
  });

  it("returns user-approval on Harbor approval holds", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
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

    const status = await paybondVercelToolApproval(run)({
      toolCall: makeToolCall("travel.book_hotel", "call-hold", {
        estimatedPriceCents: 100,
      }),
      tools: undefined,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(status).toBe("user-approval");
  });

  it("returns denied with reason on hard Harbor denials", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    run.binding.guard.assertSpendAuthorized = vi.fn(async () => {
      throw new PaybondSpendDeniedError({
        allow: false,
        auditId: "audit-deny",
        message: "budget exceeded",
      });
    });

    const status = await paybondVercelToolApproval(run)({
      toolCall: makeToolCall("travel.book_hotel", "call-deny", {
        estimatedPriceCents: 100,
      }),
      tools: undefined,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(status).toEqual({ type: "denied", reason: "budget exceeded" });
  });

  it("passes stored approval tokens on retry", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    run.storeApprovalToken("call-retry", "operator-token-123");

    const toolApproval = paybondVercelToolApproval(run);
    await toolApproval({
      toolCall: makeToolCall("travel.book_hotel", "call-retry", {
        estimatedPriceCents: 18_700,
      }),
      tools: undefined,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({ approvalToken: "operator-token-123" }),
    );
  });

  it("denies provider-executed tools when denyProviderExecutedTools is enabled", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const tools = {
      provider_search: {
        description: "Provider web search",
        inputSchema: {},
        execute: async () => ({ hits: [] }),
        isProviderExecuted: true,
      },
    } as never;

    const toolApproval = paybondVercelToolApproval(run, {
      denyProviderExecutedTools: true,
    });
    const status = await toolApproval({
      toolCall: makeToolCall("provider_search", "call-provider", { query: "hotels" }),
      tools,
      toolsContext: {},
      runtimeContext: undefined,
      messages: [],
    });

    expect(status).toEqual({
      type: "denied",
      reason: expect.stringContaining("Paybond governs only locally executed registry tools"),
    });
    expect(guard.assertSpendAuthorized).not.toHaveBeenCalled();
  });
});
