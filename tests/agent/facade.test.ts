import { describe, expect, it, vi } from "vitest";

import {
  createPaybondAgent,
  resolveAgentPolicySource,
  wrapPaybondTools,
} from "../../src/agent/facade.js";
import { instrumentPaybondAgent } from "../../src/agent/instrument.js";
import { createGuardedAgentRunner } from "../../src/agent/guarded-agent.js";
import {
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import { Paybond } from "../../src/index.js";
import { PaybondPolicy } from "../../src/policy/index.js";
import { paybondPolicyPresets } from "../../src/policy/policy-api.js";
import { isKnownPolicyPresetId, resolveComposedPresetDocument, resolvePolicyPresetPath } from "../../src/policy/presets.js";

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

describe("policy presets", () => {
  it("recognizes bundled travel preset", () => {
    expect(isKnownPolicyPresetId("travel")).toBe(true);
    expect(resolvePolicyPresetPath("travel")).toMatch(/travel\.yaml$/);
  });

  it("resolves preset ids and preserves file paths", () => {
    expect(resolveAgentPolicySource("travel")).toMatch(/travel\.yaml$/);
    expect(resolveAgentPolicySource("./paybond.policy.yaml")).toBe("./paybond.policy.yaml");
  });

  it("policyPresets.travel matches composed flat travel preset", () => {
    const preset = paybondPolicyPresets.travel();
    expect(preset.name).toBe("travel-agent-v1");
    expect(preset.document).toEqual(resolveComposedPresetDocument("travel"));
  });

  it("policyPresets.travel({ maxSpendUsd: 100 }) tightens budget", () => {
    const preset = paybondPolicyPresets.travel({ maxSpendUsd: 100 });
    expect(preset.document.intent?.budget?.max_spend_usd).toBe(100);
  });
});

describe("instrumentPaybondAgent", () => {
  it("defaults to deferred tool shells without framework", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));

    const instrumented = await instrumentPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: { "travel.book_hotel": bookHotel },
    });

    expect(instrumented.binding).toEqual({ phase: "deferred" });
    expect(Object.keys(instrumented.tools as Record<string, unknown>)).toEqual(["travel.book_hotel"]);
  });
});

describe("createPaybondAgent", () => {
  it("resolves travel preset before instrumenting", async () => {
    const host = makeHost();
    const bookHotel = vi.fn(async () => ({ status: "completed", cost_cents: 20_000 }));

    const result = await createPaybondAgent(host, {
      policy: "travel",
      framework: "generic",
      tools: { "travel.book_hotel": bookHotel },
    });

    expect(result.policy.name).toBe("travel-agent-v1");
    expect(result.tools).toHaveLength(1);
    expect(result.hooks.inputGuard).toBeDefined();
    expect(result.run).toBeDefined();
  });
});

describe("wrapPaybondTools", () => {
  it("wraps generic tools for an existing run", async () => {
    const host = makeHost();
    const guarded = await createPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      framework: "generic",
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });
    const searchWeb = vi.fn(async () => ({ hits: [] }));

    const wrapped = wrapPaybondTools(guarded.run, { "search.web": searchWeb }) as Array<{
      name: string;
      execute: (call: {
        toolName: string;
        toolCallId: string;
        arguments: unknown;
      }) => Promise<unknown>;
    }>;

    expect(wrapped).toHaveLength(1);
    await wrapped[0]!.execute({
      toolName: "search.web",
      toolCallId: "call-search",
      arguments: { q: "paris" },
    });
    expect(searchWeb).toHaveBeenCalled();
  });

  it("rejects langgraph in-place wrapping", async () => {
    const host = makeHost();
    const guarded = await createPaybondAgent(host, {
      policy: TRAVEL_POLICY,
      tools: {},
    });

    expect(() => wrapPaybondTools(guarded.run, [], { framework: "langgraph" })).toThrow(
      /langgraph/,
    );
  });
});

describe("Paybond.wrapTools", () => {
  it("delegates to wrapPaybondTools for an existing bound run", async () => {
    const host = makeHost();
    const paybond = new Paybond(
      host.harbor as never,
      host.guardrails as never,
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );
    const guarded = await paybond.agent({
      policy: TRAVEL_POLICY,
      framework: "generic",
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });
    const searchWeb = vi.fn(async () => ({ hits: [] }));

    const wrapped = paybond.wrapTools(guarded.run, { "search.web": searchWeb }) as Array<{
      name: string;
      execute: (call: {
        toolName: string;
        toolCallId: string;
        arguments: unknown;
      }) => Promise<unknown>;
    }>;

    expect(wrapped).toHaveLength(1);
    await wrapped[0]!.execute({
      toolName: "search.web",
      toolCallId: "call-search",
      arguments: { q: "paris" },
    });
    expect(searchWeb).toHaveBeenCalled();
  });
});

describe("Paybond facade methods", () => {
  it("exposes runner alias and instrument/agent helpers", async () => {
    const harbor = {
      tenantId: "tenant-a",
      getIntent: vi.fn(),
      submitEvidence: vi.fn(),
      authorizeSpend: vi.fn(),
      verifyCapability: vi.fn(),
      createIntent: vi.fn(),
      fundIntent: vi.fn(),
    };
    const guardrails = {
      bootstrapSandbox: vi.fn(async () => ({
        tenant_id: "tenant-a",
        intent_id: "intent-sandbox",
        capability_token: "cap-sandbox",
        operation: "travel.book_hotel",
        requested_spend_cents: 20_000,
        sandbox_lifecycle_status: "funded",
      })),
      submitSandboxEvidence: vi.fn(),
    };
    const paybond = new Paybond(
      harbor as never,
      guardrails as never,
      {} as never,
      {} as never,
      {} as never,
      {} as never,
    );

    expect(paybond.createGuardedAgentRunner).toBeDefined();
    expect(createGuardedAgentRunner).toBeDefined();

    const policy = PaybondPolicy.fromDocument(TRAVEL_POLICY);
    const instrumented = await paybond.instrument({
      policy,
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });
    expect(instrumented.binding).toEqual({ phase: "deferred" });

    const agent = await paybond.agent({
      policy: "travel",
      framework: "generic",
      tools: { "travel.book_hotel": vi.fn(async () => ({ ok: true })) },
    });
    expect(agent.policy.name).toBe("travel-agent-v1");
    expect(agent.tools).toHaveLength(1);
    expect(agent.hooks.inputGuard).toBeDefined();
  });
});
