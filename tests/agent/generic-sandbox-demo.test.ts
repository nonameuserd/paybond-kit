import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import { runGenericSandboxDemo } from "../../src/agent/generic-sandbox-demo.js";

function makeGuard(): PaybondRunGuard {
  return {
    assertSpendAuthorized: vi.fn(async () => ({
      allow: true,
      auditId: "audit-1",
      decisionId: "decision-1",
    })),
    completeSpendAuthorization: vi.fn(async () => {}),
  };
}

function makeHost(guard: PaybondRunGuard): PaybondAgentRunHost {
  return {
    harbor: { tenantId: "tenant-a", getIntent: async () => ({ allowed_tools: ["paid-tool"] }) },
    guardrails: {
      bootstrapSandbox: async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "paid-tool",
        requested_spend_cents: 100,
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

describe("runGenericSandboxDemo", () => {
  it("binds sandbox run and executes wrapped generic tool", async () => {
    const guard = makeGuard();
    const host = makeHost(guard);
    const paybond = {
      agentRun: {
        bind: (input: unknown) => PaybondAgentRun.bind(host, input as never),
      },
    };

    const demo = await runGenericSandboxDemo({
      paybond: paybond as never,
      operation: "paid-tool",
      requestedSpendCents: 100,
      evidencePreset: "cost_and_completion",
    });

    expect(demo.authorization.allow).toBe(true);
    expect(demo.execute.tool_result).toEqual({ status: "completed", cost_cents: 100 });
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(host.guardrails.submitSandboxEvidence).toHaveBeenCalledOnce();
  });
});
