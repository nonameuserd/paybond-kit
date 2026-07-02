import { describe, expect, it, vi } from "vitest";

import {
  PaybondInstrumented,
  PaybondInstrumentRuntime,
  PaybondUnboundContextError,
  discoverToolNames,
  discoverToolsFromAgent,
  inlinePolicyToDocument,
  instrumentPaybondAgent,
  isInlinePolicy,
  readPaybondAgentInstrumentation,
} from "../../src/agent/instrument.js";
import type { PaybondAgentRunHost } from "../../src/agent/run.js";
import { Paybond } from "../../src/index.js";

const TRAVEL_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: 20000,
      evidence_preset: "cost_and_completion",
    },
  },
  intent: {
    allowed_tools: ["travel.book_hotel"],
  },
} as const;

const BIND_CONTEXT = {
  intentId: "intent-prod",
  capabilityToken: "cap-prod",
  userId: "user-42",
  allowedTools: ["travel.book_hotel"],
  sandbox: {
    operation: "travel.book_hotel",
    requestedSpendCents: 20_000,
    sandboxLifecycleStatus: "funded" as const,
  },
};

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
      assertSpendAuthorized: async () => ({
        allow: true,
        auditId: "audit-stub",
      }),
      completeSpendAuthorization: async () => {},
    }),
  };
}

describe("inline policy", () => {
  it("detects simplified policy objects", () => {
    expect(isInlinePolicy({ budget: "$500/day", approve: ["travel.*"] })).toBe(true);
    expect(isInlinePolicy(TRAVEL_POLICY)).toBe(false);
  });

  it("converts inline policy to a full document", () => {
    const doc = inlinePolicyToDocument(
      { budget: "$500/day", approve: ["travel.*"], deny: ["crypto.*"] },
      {
        "travel.book_hotel": vi.fn(),
        "crypto.swap": vi.fn(),
      },
    );
    expect(doc.tools).toHaveProperty("travel.book_hotel");
    expect(doc.tools).not.toHaveProperty("crypto.swap");
    expect(doc.intent?.budget?.max_spend_usd).toBe(500);
  });

  it("discovers tool names from maps and arrays", () => {
    expect(discoverToolNames({ "travel.book": vi.fn() })).toEqual(["travel.book"]);
    expect(discoverToolNames([{ name: "search.web", execute: vi.fn() }])).toEqual(["search.web"]);
  });
});

describe("PaybondInstrumented", () => {
  it("defaults to deferred binding with registerable tool shells", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));

    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": bookHotel },
    });

    expect(instrumented).toBeInstanceOf(PaybondInstrumented);
    expect(instrumented.binding).toEqual({ phase: "deferred" });
    expect(instrumented.status).toEqual({ phase: "deferred" });
    expect(discoverToolNames(instrumented.tools)).toEqual(["travel.book_hotel"]);
    expect(instrumented.policy.name).toBe("travel-agent-v1");
    expect("run" in instrumented).toBe(false);
  });

  it("throws PaybondUnboundContextError only when a deferred tool executes", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });

    const tools = instrumented.tools as Record<string, () => Promise<unknown>>;
    await expect(tools["travel.book_hotel"]()).rejects.toBeInstanceOf(PaybondUnboundContextError);
  });

  it("supports inline policy in instrument()", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: { budget: "$200/day", approve: ["travel.*"] },
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });
    expect(instrumented.policy.name).toBe("inline-policy");
  });

  it("exposes sandbox binding when sandbox: true", async () => {
    const host = makeHost();
    const runtime = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
      sandbox: true,
    });
    expect(runtime).toBeInstanceOf(PaybondInstrumentRuntime);
    expect(runtime.binding.phase).toBe("bound");
    expect(runtime.binding.mode).toBe("sandbox");
    expect(runtime.binding.intentId).toBe("intent-sandbox");
    expect(runtime.binding.tenantId).toBe("tenant-a");
    expect(Array.isArray(runtime.tools)).toBe(true);
    expect(runtime.run).toBeDefined();
    expect(runtime.hooks.inputGuard).toBeDefined();
  });

  it("binds intent per session via bind()", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });

    const runtime = await instrumented.bind(BIND_CONTEXT);
    expect(runtime).toBeInstanceOf(PaybondInstrumentRuntime);
    expect(runtime.binding.phase).toBe("bound");
    expect(runtime.binding.mode).toBe("attach");
    expect(runtime.binding.intentId).toBe("intent-prod");
    expect(runtime.binding.userId).toBe("user-42");
    expect(Array.isArray(runtime.tools)).toBe(true);
    expect(runtime.tools).toHaveLength(1);
    expect(instrumented.binding).toEqual({ phase: "deferred" });
  });

  it("supports withContext as a deprecated alias for bind()", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });

    const runtime = await instrumented.withContext(BIND_CONTEXT);
    expect(runtime.binding.intentId).toBe("intent-prod");
  });

  it("returns an immutable runtime per bind() call", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });

    const runtimeA = await instrumented.bind({
      ...BIND_CONTEXT,
      intentId: "intent-a",
      capabilityToken: "cap-a",
    });
    const runtimeB = await instrumented.bind({
      ...BIND_CONTEXT,
      intentId: "intent-b",
      capabilityToken: "cap-b",
    });

    expect(runtimeA.binding.intentId).toBe("intent-a");
    expect(runtimeB.binding.intentId).toBe("intent-b");
    expect(runtimeA).not.toBe(runtimeB);
  });

  it("returns a bound runtime immediately when context is passed to instrument()", async () => {
    const host = makeHost();
    const runtime = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
      context: BIND_CONTEXT,
    });

    expect(runtime).toBeInstanceOf(PaybondInstrumentRuntime);
    expect(runtime.binding.intentId).toBe("intent-prod");
    expect(runtime.run.binding.capabilityToken).toBe("cap-prod");
  });

  it("supports lazy context providers for request-local binding", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));

    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": bookHotel },
      context: () => BIND_CONTEXT,
    });

    expect(instrumented).toBeInstanceOf(PaybondInstrumented);
    expect(instrumented.binding).toEqual({ phase: "lazy" });
    expect("run" in instrumented).toBe(false);

    const tools = instrumented.tools as Array<{
      name: string;
      execute: (call: {
        toolName: string;
        toolCallId: string;
        arguments: unknown;
      }) => Promise<unknown>;
    }>;
    expect(Array.isArray(tools)).toBe(false);
    const wrapped = instrumented.tools as Record<
      string,
      (call?: {
        toolName: string;
        toolCallId: string;
        arguments: unknown;
      }) => Promise<unknown>
    >;
    await wrapped["travel.book_hotel"]({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { hotel: "ritz" },
    });
    expect(bookHotel).toHaveBeenCalled();
  });

  it("throws PaybondLazyContextError when the context provider is empty", async () => {
    const host = makeHost();
    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
      context: () => ({ intentId: "", capabilityToken: "" }),
    });

    const wrapped = instrumented.tools as Record<string, () => Promise<unknown>>;
    await expect(wrapped["travel.book_hotel"]()).rejects.toMatchObject({
      name: "PaybondLazyContextError",
    });
  });
});

describe("Paybond fluent builder", () => {
  it("chains policy().instrument(tools)", async () => {
    const paybond = new Paybond(
      makeHost().harbor as never,
      makeHost().guardrails as never,
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );

    const instrumented = await paybond.policy(TRAVEL_POLICY).instrument({
      "travel.book_hotel": vi.fn(async () => ({ ok: true })),
    });

    expect(instrumented).toBeInstanceOf(PaybondInstrumented);
    expect(discoverToolNames(instrumented.tools)).toEqual(["travel.book_hotel"]);
  });
});

describe("automatic tool discovery", () => {
  class Agent {
    tools: Record<string, ReturnType<typeof vi.fn>>;
    policy?: typeof TRAVEL_POLICY | string;
    constructor(tools: Record<string, ReturnType<typeof vi.fn>>) {
      this.tools = tools;
    }
  }

  it("discovers tools from agent.tools", () => {
    const agent = { tools: { "travel.book_hotel": vi.fn() } };
    expect(discoverToolsFromAgent(agent)).toEqual(agent.tools);
  });

  it("instruments agent in place with deferred binding by default", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));
    const agent = new Agent({ "travel.book_hotel": bookHotel });
    agent.policy = TRAVEL_POLICY;

    const result = await instrumentPaybondAgent(host, agent);
    expect(result).toBe(agent);
    expect(readPaybondAgentInstrumentation(agent)?.binding).toEqual({ phase: "deferred" });
    expect(readPaybondAgentInstrumentation(agent)?.policy.name).toBe("travel-agent-v1");
    expect(readPaybondAgentInstrumentation(agent)?.bind).toBeDefined();
  });

  it("patches guarded tools after agent.paybond.bind()", async () => {
    const host = makeHost();
    const agent = new Agent({
      "travel.book_hotel": vi.fn(async () => ({ ok: true })),
    });
    agent.policy = TRAVEL_POLICY;
    await instrumentPaybondAgent(host, agent);

    const bound = await readPaybondAgentInstrumentation(agent)!.bind!(BIND_CONTEXT);
    expect(bound.binding.intentId).toBe("intent-prod");
    expect(readPaybondAgentInstrumentation(agent)?.run).toBeDefined();
    expect(Array.isArray(agent.tools)).toBe(true);
  });

  it("supports paybond.instrument(agent) via Paybond facade", async () => {
    const paybond = new Paybond(
      makeHost().harbor as never,
      makeHost().guardrails as never,
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );
    const agent = new Agent({
      "travel.book_hotel": vi.fn(async () => ({ ok: true })),
    });
    agent.policy = TRAVEL_POLICY;
    const result = await paybond.instrument(agent);
    expect(result).toBe(agent);
    expect(readPaybondAgentInstrumentation(agent)?.tools).toBeDefined();
    expect(readPaybondAgentInstrumentation(agent)?.binding.phase).toBe("deferred");
  });
});
