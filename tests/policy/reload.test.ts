import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PaybondAgentRun,
  createPaybondToolRegistry,
  type PaybondAgentRunHost,
} from "../../src/agent/index.js";
import {
  PaybondPolicyReloadError,
  detectPolicyLoosening,
  reloadPolicyOnRun,
  requiresIntentRebind,
} from "../../src/policy/reload.js";
import { createPolicySnapshot } from "../../src/policy/snapshot.js";
import { parsePaybondPolicyDocumentV1 } from "../../src/policy/schema.js";
import { policyDocumentToDict } from "../../src/policy/digest.js";

function documentToJson(document: ReturnType<typeof travelDocument>): string {
  return `${JSON.stringify(policyDocumentToDict(document), null, 2)}\n`;
}

function makeHost(overrides?: Partial<PaybondAgentRunHost>): PaybondAgentRunHost {
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
    ...overrides,
  };
}

function travelDocument(maxSpendCents = 20_000) {
  return parsePaybondPolicyDocumentV1({
    version: 1,
    name: "travel-agent-v1",
    default_deny: true,
    tools: {
      "travel.book_hotel": {
        side_effecting: true,
        max_spend_cents: maxSpendCents,
        evidence_preset: "cost_and_completion",
      },
    },
    intent: {
      allowed_tools: ["travel.book_hotel"],
    },
  });
}

function snapshotFromDocument(document: ReturnType<typeof travelDocument>) {
  const registry = createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        evidencePreset: "cost_and_completion",
        spendCents: document.tools["travel.book_hotel"].max_spend_cents,
      },
    },
    defaultDeny: document.default_deny,
  });
  return createPolicySnapshot({ document, registry, source: "file" });
}

describe("policy reload", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    vi.restoreAllMocks();
  });

  async function makeTempPolicy(document: ReturnType<typeof travelDocument>): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-reload-"));
    tempDirs.push(dir);
    const path = join(dir, "paybond.policy.json");
    await writeFile(path, documentToJson(document), "utf8");
    return path;
  }

  it("applies stricter cap on reload for subsequent tool calls", async () => {
    const initialDoc = travelDocument(20_000);
    const stricterDoc = travelDocument(5_000);
    const policyPath = await makeTempPolicy(initialDoc);

    const run = await PaybondAgentRun.bind(makeHost(), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry: snapshotFromDocument(initialDoc).registry,
      policySnapshot: snapshotFromDocument(initialDoc),
      policyFile: policyPath,
    });

    await writeFile(policyPath, documentToJson(stricterDoc), "utf8");
    const result = await run.reloadPolicy({ file: policyPath });
    expect(result.applied).toBe(true);
    expect(run.registry.resolveSpendCents("travel.book_hotel", {})).toBe(5_000);
  });

  it("retains previous registry when reload validation fails", async () => {
    const initialDoc = travelDocument(20_000);
    const policyPath = await makeTempPolicy(initialDoc);
    const snapshot = snapshotFromDocument(initialDoc);
    const previousDigest = snapshot.digest;

    const run = await PaybondAgentRun.bind(makeHost(), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry: snapshot.registry,
      policySnapshot: snapshot,
      policyFile: policyPath,
    });

    await writeFile(policyPath, "not: valid: yaml: [", "utf8");
    await expect(run.reloadPolicy({ file: policyPath })).rejects.toThrow();
    expect(run.policyDigest).toBe(previousDigest);
    expect(run.registry.resolveSpendCents("travel.book_hotel", {})).toBe(20_000);
  });

  it("denies loosening by default", async () => {
    const initialDoc = travelDocument(5_000);
    const looserDoc = travelDocument(50_000);
    const policyPath = await makeTempPolicy(initialDoc);

    const run = await PaybondAgentRun.bind(makeHost(), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry: snapshotFromDocument(initialDoc).registry,
      policySnapshot: snapshotFromDocument(initialDoc),
      policyFile: policyPath,
    });

    await writeFile(policyPath, documentToJson(looserDoc), "utf8");
    await expect(run.reloadPolicy({ file: policyPath })).rejects.toSatisfy((err: unknown) => {
      return err instanceof PaybondPolicyReloadError && err.code === "loosening_denied";
    });
  });

  it("pins policy digest for in-flight wrapExecute across reload", async () => {
    const initialDoc = travelDocument(20_000);
    const policyPath = await makeTempPolicy(initialDoc);
    const snapshot = snapshotFromDocument(initialDoc);

    let releaseExecute: (() => void) | undefined;
    const executeGate = new Promise<void>((resolve) => {
      releaseExecute = resolve;
    });

    const host = makeHost({
      guardrails: {
        bootstrapSandbox: async () => ({
          tenant_id: "tenant-a",
          intent_id: "intent-sandbox",
          capability_token: "cap-sandbox",
          operation: "travel.book_hotel",
          requested_spend_cents: 100,
          sandbox_lifecycle_status: "funded",
        }),
        submitSandboxEvidence: async () => ({
          intent_id: "intent-sandbox",
          sandbox_lifecycle_status: "funded",
          predicate_passed: true,
        }),
      },
      spendGuard: () => ({
        assertSpendAuthorized: async () => ({ allow: true, auditId: "audit-1", decisionId: "dec-1" }),
        completeSpendAuthorization: async () => {},
      }),
    });

    const run = await PaybondAgentRun.bind(host, {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry: snapshot.registry,
      policySnapshot: snapshot,
      policyFile: policyPath,
    });

    const pinnedDigest = run.policyDigest;
    const executePromise = run.interceptor.wrapExecute({
      toolName: "travel.book_hotel",
      toolCallId: "call-1",
      arguments: {},
      execute: async () => {
        await executeGate;
        return { status: "completed", cost_cents: 100 };
      },
    });

    const stricterDoc = travelDocument(5_000);
    await writeFile(policyPath, documentToJson(stricterDoc), "utf8");
    const reloadPromise = run.reloadPolicy({ file: policyPath });
    await new Promise((resolve) => setTimeout(resolve, 50));
    releaseExecute?.();
    const wrapped = await executePromise;
    const reloadResult = await reloadPromise;

    expect(wrapped.authorization?.policyDigest).toBe(pinnedDigest);
    expect(reloadResult.applied).toBe(true);
  });

  it("detectPolicyLoosening flags higher caps and new side-effecting tools", () => {
    const prev = travelDocument(5_000);
    const next = travelDocument(50_000);
    const reasons = detectPolicyLoosening(prev, next);
    expect(reasons.some((r) => r.includes("max_spend_cents increased"))).toBe(true);
  });

  it("requiresIntentRebind when allowed_tools drift from bound intent", () => {
    const doc = parsePaybondPolicyDocumentV1({
      version: 1,
      name: "travel-agent-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": { side_effecting: true, evidence_preset: "cost_and_completion" },
        "travel.book_flight": { side_effecting: true, evidence_preset: "cost_and_completion" },
      },
      intent: { allowed_tools: ["travel.book_hotel", "travel.book_flight"] },
    });
    expect(requiresIntentRebind(doc, ["travel.book_hotel"])).toBe(true);
  });

  it("skips reload when Gateway effective digest is unchanged", async () => {
    const dir = await mkdtemp(join(tmpdir(), "paybond-policy-reload-"));
    tempDirs.push(dir);
    const policyPath = join(dir, "tenant-overlay.policy.json");
    await writeFile(
      policyPath,
      JSON.stringify({
        version: 2,
        name: "tenant-overlay",
        default_deny: true,
        extends: { org_policy_id: "org-pol-1", org_id: "org_acme" },
        tools: {},
        overrides: {
          tools: {
            "travel.book_hotel": { max_spend_cents: 20_000 },
          },
        },
      }),
      "utf8",
    );
    const snapshot = snapshotFromDocument(travelDocument());

    const run = await PaybondAgentRun.bind(makeHost(), {
      bootstrap: {
        kind: "sandbox",
        operation: "travel.book_hotel",
        requestedSpendCents: 100,
      },
      registry: snapshot.registry,
      policySnapshot: snapshot,
      policyFile: policyPath,
    });

    const gateway = {
      resolvePolicyEffective: vi.fn().mockResolvedValue({
        effective_policy: {},
        effective_policy_digest: snapshot.digest,
        effective_policy_version: snapshot.version,
        merge_report: {
          org_policy_id: null,
          org_id: null,
          base_policy_name: "",
          overlay_policy_name: null,
          overrides_applied: [],
          denied_widenings: [],
        },
        org_base_version_seq: 1,
        org_base_content_digest: "sha256:abc",
        unchanged: true,
      }),
    };

    const result = await reloadPolicyOnRun(run, {
      file: policyPath,
      resolveInheritance: true,
      gateway,
    });
    expect(result.unchanged).toBe(true);
    expect(result.applied).toBe(false);
  });
});
