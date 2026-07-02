import { describe, expect, it } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPolicySnapshot } from "../../src/policy/snapshot.js";
import { parsePaybondPolicyDocumentV1 } from "../../src/policy/schema.js";

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
        requested_spend_cents: 100,
        sandbox_lifecycle_status: "funded",
      }),
    },
    spendGuard: () => ({
      assertSpendAuthorized: async () => ({ allow: true, auditId: "audit-1" }),
      completeSpendAuthorization: async () => {},
    }),
  };
}

describe("PaybondAgentRun policy snapshot tracking", () => {
  it("exposes currentSnapshot and policyDigest when bind includes a snapshot", async () => {
    const document = parsePaybondPolicyDocumentV1({
      version: 1,
      name: "travel-agent-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          evidence_preset: "cost_and_completion",
        },
      },
    });
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": { evidencePreset: "cost_and_completion" },
      },
    });
    const snapshot = createPolicySnapshot({
      document,
      registry,
      source: "file",
      loadedAt: "2030-01-01T00:00:00.000Z",
    });

    const run = await PaybondAgentRun.bind(makeHost(), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry,
      policySnapshot: snapshot,
    });

    expect(run.currentSnapshot).toBe(snapshot);
    expect(run.policyDigest).toBe(snapshot.digest);
    expect(run.policyVersion).toBe(snapshot.version);
    expect(run.policyLoadedAt).toBe("2030-01-01T00:00:00.000Z");
    expect(run.binding.policySnapshot).toBe(snapshot);
  });
});
