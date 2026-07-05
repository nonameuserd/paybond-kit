import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondCloudflareAgentsConfig } from "../../src/cloudflare-agents/config.js";

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

describe("createPaybondCloudflareAgentsConfig", () => {
  it("returns guarded tools with wrapped execute and toolApproval", async () => {
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
    const tools = {
      "travel.book_hotel": {
        description: "book",
        inputSchema: {},
        execute,
      },
      searchWeb: {
        description: "read-only",
        inputSchema: {},
        execute: vi.fn(async () => ({ hits: [] })),
      },
    };

    const config = createPaybondCloudflareAgentsConfig(run, tools);

    expect(config.tools["travel.book_hotel"]?.execute).not.toBe(execute);
    expect(config.tools.searchWeb?.execute).toBe(tools.searchWeb.execute);
    expect(typeof config.toolApproval).toBe("function");
  });
});
