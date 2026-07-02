import { describe, expect, it, vi } from "vitest";
import { tool, jsonSchema } from "ai";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondVercelAgentConfig } from "../../src/vercel-ai/config.js";

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

describe("createPaybondVercelAgentConfig", () => {
  it("returns guarded tools and toolApproval", async () => {
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

    const bookHotel = vi.fn(async () => ({ ok: true }));
    const tools = {
      "travel.book_hotel": tool({
        description: "book",
        inputSchema: jsonSchema({
          type: "object",
          properties: { estimatedPriceCents: { type: "number" } },
          required: ["estimatedPriceCents"],
        }),
        execute: bookHotel,
      }),
    };

    const config = createPaybondVercelAgentConfig(run, tools);

    expect(config.tools).toBeDefined();
    expect(typeof config.toolApproval).toBe("function");
    expect(config.tools["travel.book_hotel"]).not.toBe(tools["travel.book_hotel"]);
  });
});
