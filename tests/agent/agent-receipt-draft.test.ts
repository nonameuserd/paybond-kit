import { describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
  type PaybondRunGuard,
} from "../../src/agent/index.js";
import { createPolicySnapshot } from "../../src/policy/snapshot.js";
import { parsePaybondPolicyDocumentV1 } from "../../src/policy/schema.js";
import {
  agentReceiptMessageDigestSha256Hex,
  configHashSha256Hex,
  promptHashSha256Hex,
} from "../../src/agent-receipt.js";

function makeRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
        evidencePreset: "cost_and_completion",
      },
    },
    defaultDeny: true,
  });
}

function makeSnapshot() {
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
  return createPolicySnapshot({
    document,
    registry: makeRegistry(),
    source: "file",
    loadedAt: "2030-01-01T00:00:00.000Z",
  });
}

function makeGuard(overrides?: Partial<PaybondRunGuard>): PaybondRunGuard {
  return {
    assertSpendAuthorized: vi.fn(async () => ({
      allow: true,
      auditId: "9f1c2b3a-4d5e-6f70-8192-a3b4c5d6e7f8",
      decisionId: "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809",
    })),
    completeSpendAuthorization: vi.fn(async () => {}),
    ...overrides,
  };
}

describe("Agent Receipt Standard: bind-time agentContext resolution", () => {
  it("auto-computes config_hash from materials and prompt_hash from normalizedUserPrompt", async () => {
    const snapshot = makeSnapshot();
    const host: PaybondAgentRunHost = {
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
      },
      spendGuard: () => makeGuard(),
    };

    const toolsManifest = [{ name: "travel.book_hotel" }];
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      policySnapshot: snapshot,
      agentContext: {
        modelFamily: "gpt-5",
        modelInstanceId: "run-abc",
        configHashMaterials: {
          systemPrompt: "You are a travel booking agent.",
          toolsManifest,
        },
        normalizedUserPrompt: "book a hotel in lisbon",
        principalDid: "did:web:acme.example",
        operatorDid: "did:web:acme.example:operator",
        policyTemplateId: "travel-agent-v1",
      },
    });

    const expectedConfigHash = configHashSha256Hex({
      system_prompt: "You are a travel booking agent.",
      tools_manifest: toolsManifest,
      policy_snapshot_id: snapshot.digest.replace(/^sha256:/, ""),
    });
    const expectedPromptHash = promptHashSha256Hex("book a hotel in lisbon");

    expect(run.binding.agentContext).toMatchObject({
      modelFamily: "gpt-5",
      modelInstanceId: "run-abc",
      configHashHex: expectedConfigHash,
      promptHashHex: expectedPromptHash,
      principalDid: "did:web:acme.example",
      operatorDid: "did:web:acme.example:operator",
      policyTemplateId: "travel-agent-v1",
    });
  });

  it("prefers precomputed configHashHex/promptHashHex over materials", async () => {
    const host: PaybondAgentRunHost = {
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
      },
      spendGuard: () => makeGuard(),
    };

    const precomputedConfigHash = "a".repeat(64);
    const precomputedPromptHash = "b".repeat(64);
    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      agentContext: {
        modelFamily: "claude-4",
        configHashHex: precomputedConfigHash,
        promptHashHex: precomputedPromptHash,
      },
    });

    expect(run.binding.agentContext?.configHashHex).toBe(precomputedConfigHash);
    expect(run.binding.agentContext?.promptHashHex).toBe(precomputedPromptHash);
  });
});

describe("Agent Receipt Standard: verify call context propagation", () => {
  it("forwards model_family/config_hash/prompt_hash and defaults agent_subject to operatorDid", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host: PaybondAgentRunHost = {
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
        submitSandboxEvidence,
      },
      spendGuard: () => guard,
    };

    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      agentContext: {
        modelFamily: "gpt-5",
        configHashHex: "c".repeat(64),
        promptHashHex: "d".repeat(64),
        operatorDid: "did:web:acme.example:operator",
      },
    });

    await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({ reservation: { status: "confirmed", price_cents: 100 } }),
    });

    expect(guard.assertSpendAuthorized).toHaveBeenCalledWith(
      expect.objectContaining({
        modelFamily: "gpt-5",
        configHashHex: "c".repeat(64),
        promptHashHex: "d".repeat(64),
        agentSubject: "did:web:acme.example:operator",
      }),
    );
  });
});

describe("Agent Receipt Standard: unsigned receipt draft composition", () => {
  it("omits receiptDraft when bind has no agentContext", async () => {
    const guard = makeGuard();
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host: PaybondAgentRunHost = {
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
        submitSandboxEvidence,
      },
      spendGuard: () => guard,
    };

    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
    });

    const result = await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({ reservation: { status: "confirmed", price_cents: 100 } }),
    });

    expect(result.receiptDraft).toBeUndefined();
  });

  it("composes an unsigned draft with a verifiable message digest for a production auto-evidence run", async () => {
    const guard = makeGuard();
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const submitEvidence = vi.fn(async () => ({
      intentId,
      tenant: "tenant-a",
      state: "released",
      predicatePassed: true,
      payload_digest: "e".repeat(64),
      artifacts_digest: "f".repeat(64),
    }));
    const host: PaybondAgentRunHost = {
      harbor: {
        tenantId: "tenant-a",
        getIntent: async () => ({
          tenant_id: "tenant-a",
          allowed_tools: ["travel.book_hotel"],
        }),
        submitEvidence,
      },
      guardrails: {
        bootstrapSandbox: async () => {
          throw new Error("unexpected sandbox bootstrap");
        },
        submitSandboxEvidence: async () => {
          throw new Error("unexpected sandbox evidence");
        },
      },
      spendGuard: () => guard,
    };

    const snapshot = makeSnapshot();
    const run = await PaybondAgentRun.bind(host, {
      attach: {
        intentId,
        capabilityToken: "cap-prod",
        productionEvidence: {
          payeeDid: "did:web:vendor.example",
          payeeSigningSeed: new Uint8Array(32).fill(1),
          agentRecognitionKeyId: "kid-1",
          agentRecognitionSigningSeed: new Uint8Array(32).fill(2),
        },
      },
      registry: makeRegistry(),
      policySnapshot: snapshot,
      agentContext: {
        modelFamily: "gpt-5",
        modelInstanceId: "run-abc",
        configHashHex: "c".repeat(64),
        promptHashHex: "d".repeat(64),
        principalDid: "did:web:acme.example",
        operatorDid: "did:web:acme.example:operator",
        policyTemplateId: "travel-agent-v1",
      },
    });

    const result = await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-prod-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({
        reservation: { status: "confirmed", price_cents: 100 },
      }),
    });

    expect(result.receiptDraft).toBeDefined();
    const draft = result.receiptDraft!;
    expect(draft.tenant_id).toBe("tenant-a");
    expect(draft.scope).toBe("action");
    expect(draft.authorization).toMatchObject({
      principal_did: "did:web:acme.example",
      actor_subject: "did:web:acme.example:operator",
      decision_id: "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809",
      audit_id: "9f1c2b3a-4d5e-6f70-8192-a3b4c5d6e7f8",
      agent: {
        operator_did: "did:web:acme.example:operator",
        model_family: "gpt-5",
        model_instance_id: "run-abc",
        config_hash_sha256_hex: "c".repeat(64),
        prompt_hash_sha256_hex: "d".repeat(64),
      },
      policy: {
        template_id: "travel-agent-v1",
        content_digest_sha256_hex: snapshot.digest.replace(/^sha256:/, ""),
      },
      requested_spend_cents: 100,
      currency: "usd",
    });
    expect(draft.execution).toMatchObject({
      run_id: run.runId,
      tool_call_id: "call-prod-1",
      tool_name: "travel.book_hotel",
      operation: "travel.book_hotel",
      outcome: "executed",
    });
    expect(draft.merchant).toMatchObject({ payee_did: "did:web:vendor.example" });
    expect(draft.evidence).toMatchObject({
      completion_preset_id: "cost_and_completion",
      payload_digest_sha256_hex: "e".repeat(64),
      artifacts_digest_sha256_hex: "f".repeat(64),
      predicate_passed: true,
      payee_did: "did:web:vendor.example",
    });
    expect(draft.outcome.harbor_state).toBe("released");
    expect(draft.references.intent_id).toBe(intentId);
    expect(draft.receipt_id).toHaveLength(64);
    expect(draft.message_digest_sha256_hex).toBe(agentReceiptMessageDigestSha256Hex(draft));
  });

  it("omits receiptDraft when a decision id is unavailable", async () => {
    const guard = makeGuard({
      assertSpendAuthorized: vi.fn(async () => ({
        allow: true,
        auditId: "audit-only",
      })),
    });
    const submitSandboxEvidence = vi.fn(async () => ({
      tenant_id: "tenant-a",
      intent_id: "intent-sandbox",
      sandbox_lifecycle_status: "completed",
      predicate_passed: true,
    }));
    const host: PaybondAgentRunHost = {
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
        submitSandboxEvidence,
      },
      spendGuard: () => guard,
    };

    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 20_000,
      },
      registry: makeRegistry(),
      policySnapshot: makeSnapshot(),
      agentContext: {
        modelFamily: "gpt-5",
        configHashHex: "c".repeat(64),
        promptHashHex: "d".repeat(64),
        principalDid: "did:web:acme.example",
        operatorDid: "did:web:acme.example:operator",
        policyTemplateId: "travel-agent-v1",
      },
    });

    const result = await run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: { estimatedPriceCents: 100 },
      execute: async () => ({ reservation: { status: "confirmed", price_cents: 100 } }),
    });

    expect(result.receiptDraft).toBeUndefined();
  });
});
