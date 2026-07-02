import { describe, expect, it, vi } from "vitest";

import {
  createPaybondGenericAgentConfig,
  createPaybondGenericInputGuard,
  PaybondAgentRun,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondToolRegistry } from "../../src/agent/registry.js";

function makeHost(): PaybondAgentRunHost {
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
      assertSpendAuthorized: vi.fn(async () => ({
        allow: true,
        auditId: "audit-stub",
        decisionId: "decision-1",
      })),
      completeSpendAuthorization: vi.fn(async () => {}),
    }),
  };
}

describe("createPaybondGenericAgentConfig", () => {
  it("wraps tools from a record and exposes an input guard", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: createPaybondToolRegistry({
        defaultDeny: true,
        sideEffecting: {
          "travel.book_hotel": {
            spendCents: (args) => args.estimated_price_cents as number,
            evidencePreset: "cost_and_completion",
            evidenceMapper: (result) => ({
              status: result.status,
              cost_cents: result.cost_cents,
            }),
          },
        },
      }),
    });

    const config = createPaybondGenericAgentConfig(run, {
      "travel.book_hotel": bookHotel,
    });

    expect(config.tools).toHaveLength(1);
    expect(config.tools[0]?.name).toBe("travel.book_hotel");
    expect(config.inputGuard.name).toBe("tool-input-guard");
    expect(createPaybondGenericInputGuard(run).name).toBe("tool-input-guard");

    const wrapped = config.tools[0]!;
    await wrapped.execute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimated_price_cents: 18_700 },
    });

    expect(bookHotel).toHaveBeenCalledWith({ estimated_price_cents: 18_700 });
  });
});
