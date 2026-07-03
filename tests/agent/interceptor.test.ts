import { describe, expect, it, vi } from "vitest";
import {
  AUTHORIZATION_CACHE_TTL_SEC,
} from "../../src/agent/authorization-cache.js";
import {
  PaybondAgentRun,
  PaybondEvidenceSubmitError,
  PaybondUnregisteredSideEffectingToolError,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../../src/index.js";
import {
  productionEvidenceFromAttachBundle,
  type PaybondAttachBundlePayloadV1,
} from "../../src/agent/attach-bundle.js";

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
      "search.web": {
        evidencePreset: "api_response_ok",
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

function makeHost(guard: PaybondRunGuard, submitSandboxEvidence = vi.fn()): PaybondAgentRunHost {
  return {
    harbor: {
      tenantId: "tenant-a",
      getIntent: async () => ({
        tenant_id: "tenant-a",
        allowed_tools: ["travel.book_hotel", "search.web"],
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
      submitSandboxEvidence,
    },
    spendGuard: () => guard,
  };
}

describe("PaybondToolInterceptor.wrapExecute", () => {
  it("passes through read-only tools without verify or evidence", async () => {
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

    const execute = vi.fn(async () => ({ hits: 3 }));
    const result = await run.interceptor.wrapExecute({
      toolName: "lookup.weather",
      toolCallId: "call-readonly",
      arguments: { city: "Lisbon" },
      execute,
    });

    expect(result).toEqual({ toolResult: { hits: 3 } });
    expect(execute).toHaveBeenCalledOnce();
    expect(guard.assertSpendAuthorized).not.toHaveBeenCalled();
  });

  it("authorizes, executes, consumes spend, and submits auto-evidence", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host = makeHost(guard, submitSandboxEvidence);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const result = await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { city: "Lisbon", estimatedPriceCents: 18_700 },
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 18_700 },
      }),
    });

    expect(result.toolResult).toEqual({
      reservation: { status: "confirmed", price_cents: 18_700 },
    });
    expect(result.authorization).toEqual({
      allow: true,
      auditId: "audit-1",
      decisionId: "decision-1",
    });
    expect(result.evidence).toMatchObject({
      submitted: true,
      intentId: "intent-sandbox",
      predicatePassed: true,
      sandboxLifecycleStatus: "completed",
    });
    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "travel.book_hotel",
        requestedSpendCents: 18_700,
        toolCallId: "call-1",
        toolName: "travel.book_hotel",
      }),
    );
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
    expect(submitSandboxEvidence).toHaveBeenCalledWith(
      expect.objectContaining({
        intentId: "intent-sandbox",
        payload: { status: "completed", cost_cents: 18_700 },
        idempotencyKey: "evidence:intent-sandbox:call-1",
      }),
    );
  });

  it("prefers sandbox bind spend over policy max_spend_cents when args are empty", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host: PaybondAgentRunHost = {
      harbor: {
        tenantId: "tenant-a",
        getIntent: async () => ({
          tenant_id: "tenant-a",
          allowed_tools: ["saas.provision_seat"],
        }),
      },
      guardrails: {
        bootstrapSandbox: async (input) => ({
          tenant_id: "tenant-a",
          intent_id: "intent-sandbox",
          capability_token: "cap-sandbox",
          operation: input.operation,
          requested_spend_cents: input.requestedSpendCents,
          sandbox_lifecycle_status: "funded",
        }),
        submitSandboxEvidence,
      },
      spendGuard: () => guard,
    };
    const registry = createPaybondToolRegistry({
      defaultDeny: true,
      sideEffecting: {
        "saas.provision_seat": {
          spendCents: 5_000,
          evidencePreset: "cost_and_completion",
        },
      },
    });
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "saas.provision_seat",
        requestedSpendCents: 2_900,
      },
      registry,
    });

    await run.interceptor.wrapExecute({
      toolName: "saas.provision_seat",
      toolCallId: "smoke-1",
      arguments: {},
      execute: async () => ({ status: "completed", cost_cents: 2_900 }),
    });

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: "saas.provision_seat",
        requestedSpendCents: 2_900,
      }),
    );
  });

  it("denies unregistered side-effecting tools when defaultDeny is enabled", async () => {
    const guard = makeGuard();
    const host = makeHost(guard);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: createPaybondToolRegistry({
        sideEffecting: {
          book_hotel_alias: {
            operation: "travel.book_hotel",
            spendCents: 100,
            evidencePreset: "cost_and_completion",
          },
        },
        defaultDeny: true,
      }),
    });

    await expect(
      run.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-deny",
        arguments: {},
        execute: async () => ({ ok: true }),
      }),
    ).rejects.toBeInstanceOf(PaybondUnregisteredSideEffectingToolError);
  });

  it("releases spend when execute fails", async () => {
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

    await expect(
      run.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-fail",
        arguments: { estimatedPriceCents: 100 },
        execute: async () => {
          throw new Error("vendor down");
        },
      }),
    ).rejects.toThrow("vendor down");

    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "released");
  });

  it("surfaces evidence submit failures with tool result preserved", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => {
      throw new Error("gateway evidence rejected");
    });
    const host = makeHost(guard, submitSandboxEvidence);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const toolResult = { reservation: { status: "confirmed", price_cents: 100 } };

    try {
      await run.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-evidence-fail",
        arguments: { estimatedPriceCents: 100 },
        execute: async () => toolResult,
      });
      throw new Error("expected wrapExecute to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PaybondEvidenceSubmitError);
      const evidenceErr = err as PaybondEvidenceSubmitError;
      expect(evidenceErr.toolResult).toEqual(toolResult);
      expect(evidenceErr.message).toContain("gateway evidence rejected");
    }

    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
  });

  it("re-authorizes when cached authorization is stale", async () => {
    vi.useFakeTimers();
    try {
      const guard = makeGuard();
      const submitSandboxEvidence = vi.fn(async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        sandbox_lifecycle_status: "completed",
        predicate_passed: true,
      }));
      const host = makeHost(guard, submitSandboxEvidence);
      const run = await PaybondAgentRun.bind(host, {
        bootstrap: {
          kind: "sandbox",
          operation: "travel.book_hotel",
          requestedSpendCents: 20_000,
        },
        registry: makeRegistry(),
      });

      await run.interceptor.authorizeToolCall({
        toolName: "travel.book_hotel",
        toolCallId: "call-stale",
        arguments: { estimatedPriceCents: 100 },
      });

      vi.advanceTimersByTime((AUTHORIZATION_CACHE_TTL_SEC + 1) * 1000);

      await run.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-stale",
        arguments: { estimatedPriceCents: 100 },
        execute: async () => ({ reservation: { status: "confirmed", price_cents: 100 } }),
      });

      expect(guard.assertSpendAuthorized).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it("re-authorizes when a later authorize overwrites the cache for the same tool call", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host = makeHost(guard, submitSandboxEvidence);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    await run.interceptor.authorizeToolCall({
      toolName: "travel.book_hotel",
      toolCallId: "call-overwrite",
      arguments: { estimatedPriceCents: 100 },
    });
    await run.interceptor.authorizeToolCall({
      toolName: "travel.book_hotel",
      toolCallId: "call-overwrite",
      arguments: { estimatedPriceCents: 5_000 },
    });

    await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-overwrite",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({ reservation: { status: "confirmed", price_cents: 100 } }),
    });

    expect(guard.assertSpendAuthorized).toHaveBeenCalledTimes(3);
  });

  it("propagates approval holds and hard denials from assertSpendAuthorized", async () => {
    const host = makeHost(makeGuard());

    const approvalRun = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    approvalRun.binding.guard.assertSpendAuthorized = vi.fn(async () => {
      throw new PaybondSpendApprovalRequiredError({
        allow: false,
        auditId: "audit-hold",
        approvalRequired: true,
      });
    });

    await expect(
      approvalRun.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-hold",
        arguments: { estimatedPriceCents: 100 },
        execute: async () => ({ ok: true }),
      }),
    ).rejects.toThrow(PaybondSpendApprovalRequiredError);

    const denyRun = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    denyRun.binding.guard.assertSpendAuthorized = vi.fn(async () => {
      throw new PaybondSpendDeniedError({
        allow: false,
        auditId: "audit-deny",
      });
    });

    await expect(
      denyRun.interceptor.wrapExecute({
        toolName: "travel.book_hotel",
        toolCallId: "call-deny-auth",
        arguments: { estimatedPriceCents: 100 },
        execute: async () => ({ ok: true }),
      }),
    ).rejects.toThrow(PaybondSpendDeniedError);
  });

  it("submits production auto-evidence with signed payee binding and recognition proof", async () => {
    const guard = makeGuard();
    const submitEvidence = vi.fn(async () => ({
      intentId,
      tenant: "tenant-a",
      state: "completed",
      predicatePassed: true,
    }));
    const host: PaybondAgentRunHost = {
      harbor: {
        tenantId: "tenant-a",
        getIntent: async () => ({
          tenant_id: "tenant-a",
          allowed_tools: ["travel.book_hotel"],
        }),
        submitEvidence,
      },
      guardrails: {
        bootstrapSandbox: async () => {
          throw new Error("unexpected sandbox bootstrap");
        },
        submitSandboxEvidence: async () => {
          throw new Error("unexpected sandbox evidence");
        },
      },
      spendGuard: () => guard,
    };

    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const run = await PaybondAgentRun.bind(host, {
      attach: {
        intentId,
        capabilityToken: "cap-prod",
        productionEvidence: {
          payeeDid: "did:web:vendor.example",
          payeeSigningSeed: new Uint8Array(32).fill(1),
          agentRecognitionKeyId: "kid-1",
          agentRecognitionSigningSeed: new Uint8Array(32).fill(2),
        },
      },
      registry: makeRegistry(),
    });

    const result = await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-prod-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 100 },
      }),
    });

    expect(result.evidence).toMatchObject({
      submitted: true,
      intentId,
      intentState: "completed",
      predicatePassed: true,
    });
    expect(submitEvidence).toHaveBeenCalledOnce();
    const [, wire, options] = submitEvidence.mock.calls[0]!;
    expect(wire).toMatchObject({
      payload: { status: "completed", cost_cents: 100 },
      payee_did: "did:web:vendor.example",
    });
    expect(options.recognitionProof).toMatchObject({
      purpose: "harbor.intent.evidence.submit",
      key_id: "kid-1",
      verifier_context: { tenant_id: "tenant-a", verifier_id: "paybond-gateway" },
      request_envelope: {
        method: "POST",
        path: `/harbor/intents/${intentId}/evidence`,
      },
    });
    expect(options.idempotencyKey).toBe(`evidence:${intentId}:call-prod-1`);
  });

  it("signs recognition proof from console attach bundle credentials", async () => {
    const bundlePayload: PaybondAttachBundlePayloadV1 = {
      v: 1,
      payee_did: "did:paybond:middleware:acme:amk_demo:payee",
      payee_signing_seed_hex: "a".repeat(64),
      agent_recognition_key_id: "amk_demo",
      agent_recognition_signing_seed_hex: "b".repeat(64),
    };
    const productionEvidence = productionEvidenceFromAttachBundle(bundlePayload);
    const intentId = "550e8400-e29b-41d4-a716-446655440001";
    const guard = makeGuard();
    const submitEvidence = vi.fn(async () => ({
      intentId,
      tenant: "tenant-a",
      state: "completed",
      predicatePassed: true,
    }));
    const host: PaybondAgentRunHost = {
      harbor: {
        tenantId: "tenant-a",
        getIntent: async () => ({
          tenant_id: "tenant-a",
          allowed_tools: ["travel.book_hotel"],
        }),
        submitEvidence,
      },
      guardrails: {
        bootstrapSandbox: async () => {
          throw new Error("unexpected sandbox bootstrap");
        },
        submitSandboxEvidence: async () => {
          throw new Error("unexpected sandbox evidence");
        },
      },
      spendGuard: () => guard,
    };

    const run = await PaybondAgentRun.bind(host, {
      attach: {
        intentId,
        capabilityToken: "cap-bundle",
        productionEvidence,
      },
      registry: makeRegistry(),
    });

    await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-bundle-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 100 },
      }),
    });

    expect(submitEvidence).toHaveBeenCalledOnce();
    const [, , options] = submitEvidence.mock.calls[0]!;
    expect(options.recognitionProof).toMatchObject({
      purpose: "harbor.intent.evidence.submit",
      key_id: "amk_demo",
      verifier_context: { tenant_id: "tenant-a", verifier_id: "paybond-gateway" },
    });
  });
});

describe("PaybondToolInterceptor.traceSink", () => {
  it("emits structured trace events through an optional sink", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "released",
      predicate_passed: true,
    }));
    const host = makeHost(guard, submitSandboxEvidence);
    const traceEvents: Array<{ type: string; evidenceId?: string; presetId?: string }> = [];
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      traceSink: (event) => {
        traceEvents.push(event);
      },
    });

    await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-trace-1",
      arguments: { city: "Lisbon", estimatedPriceCents: 18_700 },
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 18_700 },
      }),
    });

    expect(traceEvents.map((event) => event.type)).toEqual([
      "tool_selected",
      "spend_authorized",
      "tool_executed",
      "spend_finalized",
      "evidence_submitted",
    ]);
    const evidenceEvent = traceEvents.find((event) => event.type === "evidence_submitted");
    expect(evidenceEvent?.evidenceId).toBe("evidence:intent-sandbox:call-trace-1");
    expect(evidenceEvent?.presetId).toBeTruthy();
  });
});
