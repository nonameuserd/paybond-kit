import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondLangGraphHooks } from "../../src/langgraph/config.js";
import { paybondToolNode } from "../../src/langgraph/index.js";

function makeHost(): PaybondAgentRunHost {
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
        auditId: "audit-1",
        decisionId: "decision-1",
      })),
      completeSpendAuthorization: vi.fn(async () => {}),
    }),
  };
}

describe("createPaybondLangGraphHooks", () => {
  it("returns awrapToolCall and createToolNode wired to the run", async () => {
    const host = makeHost();
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
            spendCents: () => 100,
            evidencePreset: "cost_and_completion",
          },
        },
      }),
    });

    const hooks = createPaybondLangGraphHooks(run);

    expect(typeof hooks.awrapToolCall).toBe("function");
    expect(typeof hooks.createToolNode).toBe("function");
    expect(hooks.createToolNode([]).constructor.name).toBe(paybondToolNode([], run).constructor.name);
  });
});
