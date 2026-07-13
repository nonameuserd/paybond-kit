import { createRequire } from "node:module";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
} from "../../src/index.js";

vi.mock("node:module", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:module")>();
  return {
    ...actual,
    createRequire: vi.fn((url: string) => {
      const require = actual.createRequire(url);
      return ((id: string) => {
        if (id === "@google/adk") {
          return {
            FunctionTool: class FakeFunctionTool {
              name: string;
              description: string;
              parameters?: unknown;
              isLongRunning?: boolean;
              execute: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;

              constructor(options: {
                name?: string;
                description: string;
                parameters?: unknown;
                execute: (
                  input: unknown,
                  toolContext?: unknown,
                ) => unknown | Promise<unknown>;
                isLongRunning?: boolean;
              }) {
                this.name = options.name ?? options.execute.name ?? "tool";
                this.description = options.description;
                this.parameters = options.parameters;
                this.isLongRunning = options.isLongRunning;
                this.execute = options.execute;
              }
            },
            isFunctionTool: (value: unknown) =>
              typeof value === "object" &&
              value !== null &&
              typeof (value as { execute?: unknown }).execute === "function",
          };
        }
        return require(id);
      }) as NodeRequire;
    }),
  };
});

const { createPaybondGoogleAdkConfig } = await import("../../src/google-adk/index.js");

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
        evidencePreset: "cost_and_completion",
        evidenceMapper: (result: { reservation: { status: string; price_cents: number } }) => ({
          status: "completed",
          cost_cents: result.reservation.price_cents,
        }),
      },
    },
    defaultDeny: true,
  });
}

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
    spendGuard: () => guard,
  };
}

function loadFunctionTool() {
  const require = createRequire(import.meta.url);
  return (
    require("@google/adk") as {
      FunctionTool: new (options: {
        name: string;
        description: string;
        execute: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;
        isLongRunning?: boolean;
      }) => {
        name: string;
        execute: (input: unknown, toolContext?: unknown) => unknown | Promise<unknown>;
        isLongRunning?: boolean;
      };
    }
  ).FunctionTool;
}

describe("createPaybondGoogleAdkConfig", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("wraps side-effecting FunctionTool execute and passes through read-only tools", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const FunctionTool = loadFunctionTool();

    const bookHotel = new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel",
      execute: async (args) => ({
        reservation: {
          status: "confirmed",
          price_cents: (args as { estimatedPriceCents: number }).estimatedPriceCents,
        },
      }),
    });
    const searchWeb = new FunctionTool({
      name: "search.web",
      description: "Search",
      execute: async () => ({ ok: true }),
    });

    const config = createPaybondGoogleAdkConfig(run, [bookHotel, searchWeb]);
    expect(config.tools).toHaveLength(2);
    expect(typeof config.wrapTool).toBe("function");
    expect(config.tools[1]).toBe(searchWeb);

    const result = await config.tools[0]!.execute!({ estimatedPriceCents: 18_700 });
    expect(result).toEqual({
      reservation: { status: "confirmed", price_cents: 18_700 },
    });
    expect(guard.assertSpendAuthorized).toHaveBeenCalledOnce();
    expect(guard.completeSpendAuthorization).toHaveBeenCalledWith("decision-1", "consumed");
  });

  it("uses ADK functionCallId and stored approval tokens", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });
    run.storeApprovalToken("adk-call-9", "operator-token-456");

    const FunctionTool = loadFunctionTool();
    const bookHotel = new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel",
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 100 },
      }),
    });

    const config = createPaybondGoogleAdkConfig(run, [bookHotel]);
    await config.tools[0]!.execute!(
      { estimatedPriceCents: 100 },
      { functionCallId: "adk-call-9" },
    );

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({
        toolCallId: "adk-call-9",
        approvalToken: "operator-token-456",
      }),
    );
  });

  it("maps deny and approval-hold errors to clear Paybond messages", async () => {
    const denyGuard: PaybondRunGuard = {
      assertSpendAuthorized: vi.fn(async () => {
        throw new PaybondSpendDeniedError({
          allow: false,
          auditId: "audit-deny",
          tenant: "tenant-a",
          intentId: "intent-sandbox",
          code: "denied",
          message: "capability denied",
        });
      }),
      completeSpendAuthorization: vi.fn(async () => {}),
    };
    const denyRun = await PaybondAgentRun.bind(makeHost(denyGuard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const FunctionTool = loadFunctionTool();
    const denyTool = new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel",
      execute: async () => ({ ok: true }),
    });
    const denyConfig = createPaybondGoogleAdkConfig(denyRun, [denyTool]);
    await expect(denyConfig.tools[0]!.execute!({ estimatedPriceCents: 100 })).rejects.toThrow(
      /Paybond capability denied/,
    );

    const holdGuard: PaybondRunGuard = {
      assertSpendAuthorized: vi.fn(async () => {
        throw new PaybondSpendApprovalRequiredError({
          allow: false,
          auditId: "audit-hold",
          tenant: "tenant-a",
          intentId: "intent-sandbox",
          code: "approval_required",
          message: "approval required",
          decisionId: "decision-hold-1",
          approvalRequired: true,
        });
      }),
      completeSpendAuthorization: vi.fn(async () => {}),
    };
    const holdRun = await PaybondAgentRun.bind(makeHost(holdGuard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });
    const holdTool = new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel",
      execute: async () => ({ ok: true }),
    });
    const holdConfig = createPaybondGoogleAdkConfig(holdRun, [holdTool]);
    await expect(holdConfig.tools[0]!.execute!({ estimatedPriceCents: 100 })).rejects.toThrow(
      /Paybond capability approval required.*decision-hold-1/,
    );
  });

  it("preserves isLongRunning when rebuilding", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const FunctionTool = loadFunctionTool();
    const bookHotel = new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel",
      isLongRunning: true,
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 100 },
      }),
    });

    const config = createPaybondGoogleAdkConfig(run, [bookHotel]);
    expect(config.tools[0]!.isLongRunning).toBe(true);
  });

  it("rejects non-sequence tools", async () => {
    const guard = makeGuard();
    const run = await PaybondAgentRun.bind(makeHost(guard), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    expect(() => createPaybondGoogleAdkConfig(run, "not-an-array" as never)).toThrow(
      /sequence/,
    );
  });
});
