import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { createPaybondMcpToolSurface } from "../../src/mcp/tool-surface.js";

function makeHost(): PaybondAgentRunHost {
  return {
    harbor: { tenantId: "tenant-a" },
    guardrails: {
      bootstrapSandbox: async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "travel.book_hotel",
        requested_spend_cents: 20_000,
        sandbox_lifecycle_status: "funded",
      }),
    },
    spendGuard: () => ({
      assertSpendAuthorized: vi.fn(async () => ({
        allow: true,
        auditId: "audit-1",
      })),
      completeSpendAuthorization: vi.fn(async () => {}),
    }),
  };
}

describe("createPaybondMcpToolSurface", () => {
  it("returns stdio server config and install payloads", async () => {
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

    const surface = createPaybondMcpToolSurface(run, { envFile: ".env.local" });

    expect(surface.serverConfig.env.PAYBOND_ENV_FILE).toBe(".env.local");
    expect(surface.serverConfig.command).toBeTruthy();
    expect(surface.installPayload("json")).toContain("mcpServers");
    expect(surface.installPayload("toml")).toContain("[mcp_servers.paybond]");
  });
});
