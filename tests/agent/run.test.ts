import { describe, expect, it } from "vitest";
import {
  PaybondAgentRun,
  PaybondAgentRunBindError,
  PaybondToolRegistryValidationError,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";

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
      submitEvidence: async () => ({
        intentId: "intent-prod",
        tenant: "tenant-a",
        state: "completed",
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
      submitSandboxEvidence: async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        sandbox_lifecycle_status: "completed",
      }),
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

describe("PaybondAgentRun.bind", () => {
  it("bootstraps a sandbox run and stores tenant-scoped binding", async () => {
    const host = makeHost();
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      runId: "run-test-1",
    });

    expect(run.runId).toBe("run-test-1");
    expect(run.tenantId).toBe("tenant-a");
    expect(run.intentId).toBe("intent-sandbox");
    expect(run.capabilityToken).toBe("cap-sandbox");
    expect(run.allowedTools).toEqual(["travel.book_hotel"]);
    expect(run.binding.sandbox).toEqual({
      operation: "travel.book_hotel",
      requestedSpendCents: 20_000,
      sandboxLifecycleStatus: "funded",
    });
  });

  it("attaches an existing intent using explicit allowedTools", async () => {
    const host = makeHost();
    const run = await PaybondAgentRun.bind(host, {
      attach: {
        intentId: "40000000-0000-4000-8000-000000000001",
        capabilityToken: "cap-prod",
        allowedTools: ["travel.book_hotel"],
        productionEvidence: makeProductionEvidence(),
      },
      registry: makeRegistry(),
    });

    expect(run.intentId).toBe("40000000-0000-4000-8000-000000000001");
    expect(run.capabilityToken).toBe("cap-prod");
    expect(run.allowedTools).toEqual(["travel.book_hotel"]);
    expect(run.binding.sandbox).toBeUndefined();
  });

  it("loads allowedTools from Harbor when attach omits them", async () => {
    let fetchedIntentId = "";
    const host = makeHost({
      harbor: {
        tenantId: "tenant-a",
        getIntent: async (intentId) => {
          fetchedIntentId = intentId;
          return {
            tenant_id: "tenant-a",
            allowed_tools: ["travel.book_hotel"],
          };
        },
      },
    });

    const run = await PaybondAgentRun.bind(host, {
      attach: {
        intentId: "40000000-0000-4000-8000-000000000002",
        capabilityToken: "cap-prod",
        productionEvidence: makeProductionEvidence(),
      },
      registry: makeRegistry(),
    });

    expect(fetchedIntentId).toBe("40000000-0000-4000-8000-000000000002");
    expect(run.allowedTools).toEqual(["travel.book_hotel"]);
  });

  it("rejects bind when both bootstrap and attach are provided", async () => {
    await expect(
      PaybondAgentRun.bind(makeHost(), {
        bootstrap: {
          kind: "sandbox",
          operation: "travel.book_hotel",
          requestedSpendCents: 100,
        },
        attach: {
          intentId: "intent-1",
          capabilityToken: "cap-1",
          allowedTools: ["travel.book_hotel"],
        },
        registry: makeRegistry(),
      }),
    ).rejects.toThrow(PaybondAgentRunBindError);
  });

  it("validates registry against intent allowedTools at bind time", async () => {
    await expect(
      PaybondAgentRun.bind(makeHost(), {
        attach: {
          intentId: "40000000-0000-4000-8000-000000000003",
          capabilityToken: "cap-1",
          allowedTools: ["travel.book_hotel", "travel.book_flight"],
          productionEvidence: makeProductionEvidence(),
        },
        registry: makeRegistry(),
      }),
    ).rejects.toThrow(PaybondToolRegistryValidationError);
  });

  it("requires productionEvidence for production attach binds", async () => {
    await expect(
      PaybondAgentRun.bind(makeHost(), {
        attach: {
          intentId: "40000000-0000-4000-8000-000000000004",
          capabilityToken: "cap-prod",
          allowedTools: ["travel.book_hotel"],
        },
        registry: makeRegistry(),
      }),
    ).rejects.toThrow(PaybondAgentRunBindError);
  });
});
