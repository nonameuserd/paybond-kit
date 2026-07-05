import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondMastraConfig } from "../../src/mastra/config.js";

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

describe("createPaybondMastraConfig", () => {
  it("returns guarded tools with wrapped execute", async () => {
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
            spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
            evidencePreset: "cost_and_completion",
          },
        },
      }),
    });

    const execute = vi.fn(async () => ({ ok: true }));
    const tools = [
      {
        id: "travel.book_hotel",
        description: "book",
        execute,
      },
      {
        id: "search.web",
        description: "read-only",
        execute: vi.fn(async () => ({ hits: [] })),
      },
    ];

    const config = createPaybondMastraConfig(run, tools);

    expect(config.tools).toHaveLength(2);
    expect(config.tools[0]?.execute).not.toBe(execute);
    expect(config.tools[1]?.execute).toBe(tools[1]?.execute);
  });
});
