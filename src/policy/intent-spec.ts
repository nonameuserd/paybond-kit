import type { PaybondToolRegistry } from "../agent/registry.js";
import { PaybondToolRegistryValidationError } from "../agent/types.js";
import { resolveCompletionPreset, contractSnapshotForPreset } from "../completion-resolve.js";
import type {
  CompletionContractSnapshot,
  PolicyBindingRef,
  PublishedPolicyHead,
  SettlementRail,
} from "../principal-intent.js";
import { validateUsdDenominatedSettlement } from "../mpp-commercial.js";
import { policyToToolRegistry } from "./registry.js";
import { type PaybondPolicyDocumentV1 } from "./schema.js";

/** Raised when policy intent fields cannot be aligned to a Harbor create payload. */
export class PaybondPolicyIntentSpecError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondPolicyIntentSpecError";
  }
}

/** Runtime fields required to build a production intent create payload from policy. */
export type PaybondPolicyIntentCreateOverrides = {
  principalDid: string;
  principalSigningSeed: Uint8Array;
  payeeDid: string;
  payeeSigningSeed: Uint8Array;
  deadlineRfc3339: string;
  settlementRail: SettlementRail;
  recognitionProof: Record<string, unknown>;
  publishedPolicyHead: PublishedPolicyHead;
  intentId?: string;
  predicateRef?: string;
  amountCents?: number;
  currency?: string;
  budget?: Record<string, unknown>;
  allowedTools?: string[];
  completionPresetId?: string;
  evidenceSchema?: Record<string, unknown>;
  policyBinding?: PolicyBindingRef;
};

/** Params for {@link PaybondIntents.createWithPolicyBinding} derived from policy + runtime signing context. */
export type PaybondPolicyIntentCreateInput = {
  principalDid: string;
  principalSigningSeed: Uint8Array;
  payeeDid: string;
  payeeSigningSeed: Uint8Array;
  budget: Record<string, unknown>;
  currency: string;
  amountCents: number;
  evidenceSchema: Record<string, unknown>;
  deadlineRfc3339: string;
  allowedTools: string[];
  settlementRail: SettlementRail;
  policyBinding: PolicyBindingRef;
  publishedPolicyHead: PublishedPolicyHead;
  recognitionProof: Record<string, unknown>;
  intentId?: string;
  predicateRef?: string;
  completionPresetId?: string;
  completionContract?: CompletionContractSnapshot;
};

function normalizeDigestHex(digest: string): string {
  const trimmed = digest.trim().toLowerCase();
  if (trimmed.startsWith("sha256:")) {
    return trimmed.slice("sha256:".length);
  }
  return trimmed.replace(/^0x/, "");
}

function resolveAllowedHarborOperations(
  document: PaybondPolicyDocumentV1,
  registry: PaybondToolRegistry,
  override?: string[],
): string[] {
  const raw = override ?? document.intent?.allowed_tools;
  if (!raw || raw.length === 0) {
    throw new PaybondPolicyIntentSpecError(
      "policy intent.allowed_tools is required for toIntentCreateInput",
    );
  }

  const operations = registry.sideEffectingOperations();
  const seen = new Set<string>();
  const resolved: string[] = [];

  for (const name of raw) {
    let operation: string;
    if (registry.isSideEffecting(name)) {
      operation = registry.resolveOperation(name);
    } else if (operations.includes(name)) {
      operation = name;
    } else {
      throw new PaybondPolicyIntentSpecError(
        `allowed_tools entry "${name}" is not a registered side-effecting tool or Harbor operation`,
      );
    }
    if (!seen.has(operation)) {
      seen.add(operation);
      resolved.push(operation);
    }
  }

  if (resolved.length === 0) {
    throw new PaybondPolicyIntentSpecError(
      "allowed_tools must resolve to at least one Harbor operation",
    );
  }

  try {
    registry.validateForBind(resolved);
  } catch (err) {
    if (err instanceof PaybondToolRegistryValidationError) {
      throw new PaybondPolicyIntentSpecError(err.message);
    }
    throw err;
  }

  return resolved;
}

function resolveEvidencePresetForOperations(
  registry: PaybondToolRegistry,
  allowedOperations: string[],
): string {
  const presets = new Set<string>();

  for (const operation of allowedOperations) {
    for (const toolName of registry.sideEffectingToolNames()) {
      if (registry.resolveOperation(toolName) !== operation) {
        continue;
      }
      const preset = registry.getSideEffectingEntry(toolName)?.evidencePreset;
      if (preset) {
        presets.add(preset);
      }
    }
  }

  if (presets.size === 0) {
    throw new PaybondPolicyIntentSpecError(
      "could not resolve evidence_preset from policy allowed_tools",
    );
  }
  if (presets.size > 1) {
    throw new PaybondPolicyIntentSpecError(
      `allowed_tools reference multiple evidence_preset values: ${[...presets].join(", ")}`,
    );
  }
  return [...presets][0]!;
}

function resolvePolicyBindingRef(
  document: PaybondPolicyDocumentV1,
  publishedHead: PublishedPolicyHead,
  override?: PolicyBindingRef,
): PolicyBindingRef {
  const policyBinding = document.intent?.policy_binding;
  if (!override && !policyBinding) {
    throw new PaybondPolicyIntentSpecError(
      "policy intent.policy_binding is required for toIntentCreateInput",
    );
  }

  const binding: PolicyBindingRef = override ?? {
    templateId: policyBinding!.template_id,
    versionSeq: policyBinding!.version_seq ?? publishedHead.versionSeq,
  };

  if (binding.templateId !== publishedHead.templateId) {
    throw new PaybondPolicyIntentSpecError(
      "publishedPolicyHead.templateId must match policy intent.policy_binding.template_id",
    );
  }
  if (binding.versionSeq !== publishedHead.versionSeq) {
    throw new PaybondPolicyIntentSpecError(
      "publishedPolicyHead.versionSeq must match policy intent.policy_binding.version_seq",
    );
  }
  if (
    policyBinding?.version_seq !== undefined &&
    policyBinding.version_seq !== publishedHead.versionSeq
  ) {
    throw new PaybondPolicyIntentSpecError(
      "policy intent.policy_binding.version_seq does not match publishedPolicyHead.versionSeq",
    );
  }

  const headDigest = policyBinding?.head_digest;
  if (headDigest) {
    const expected = normalizeDigestHex(headDigest);
    const actual = normalizeDigestHex(publishedHead.policyContentDigestHex);
    if (expected !== actual) {
      throw new PaybondPolicyIntentSpecError(
        "policy intent.policy_binding.head_digest does not match publishedPolicyHead.policyContentDigestHex",
      );
    }
  }

  return binding;
}

function resolveBudgetFields(
  document: PaybondPolicyDocumentV1,
  overrides: Pick<
    PaybondPolicyIntentCreateOverrides,
    "budget" | "currency" | "amountCents"
  >,
): { budget: Record<string, unknown>; currency: string; amountCents: number } {
  if (
    overrides.budget !== undefined &&
    overrides.currency !== undefined &&
    overrides.amountCents !== undefined
  ) {
    return {
      budget: overrides.budget,
      currency: overrides.currency,
      amountCents: overrides.amountCents,
    };
  }

  const intentBudget = document.intent?.budget;
  const currency =
    overrides.currency ??
    (typeof intentBudget?.currency === "string" ? intentBudget.currency : undefined) ??
    "usd";

  let amountCents = overrides.amountCents;
  if (amountCents === undefined && intentBudget && typeof intentBudget.max_spend_usd === "number") {
    amountCents = Math.round(intentBudget.max_spend_usd * 100);
  }
  if (amountCents === undefined) {
    throw new PaybondPolicyIntentSpecError(
      "amountCents is required when policy intent.budget.max_spend_usd is not set",
    );
  }

  const budget: Record<string, unknown> = overrides.budget ?? {
    ...(intentBudget ?? {}),
    max: amountCents,
  };
  if (!("max" in budget)) {
    budget.max = amountCents;
  }

  return { budget, currency, amountCents };
}

/**
 * Build {@link PaybondIntents.createWithPolicyBinding} input from a validated policy document.
 * Merges policy intent alignment (`allowed_tools`, `budget`, `policy_binding`) with caller signing context.
 */
export function policyToIntentCreateInput(
  document: PaybondPolicyDocumentV1,
  overrides: PaybondPolicyIntentCreateOverrides,
): PaybondPolicyIntentCreateInput {
  const registry = policyToToolRegistry(document);
  const allowedTools = resolveAllowedHarborOperations(
    document,
    registry,
    overrides.allowedTools,
  );
  const policyBinding = resolvePolicyBindingRef(
    document,
    overrides.publishedPolicyHead,
    overrides.policyBinding,
  );
  const { budget, currency, amountCents } = resolveBudgetFields(document, overrides);
  validateUsdDenominatedSettlement(overrides.settlementRail, currency);

  const completionPresetId =
    overrides.completionPresetId ??
    resolveEvidencePresetForOperations(registry, allowedTools);
  const resolvedPreset = resolveCompletionPreset(completionPresetId);
  const evidenceSchema = overrides.evidenceSchema ?? resolvedPreset.evidenceSchema;

  let completionContract: CompletionContractSnapshot | undefined;
  try {
    completionContract = contractSnapshotForPreset(completionPresetId);
  } catch (err) {
    throw new PaybondPolicyIntentSpecError(
      err instanceof Error ? err.message : "failed to build completion contract snapshot",
    );
  }

  return {
    principalDid: overrides.principalDid,
    principalSigningSeed: overrides.principalSigningSeed,
    payeeDid: overrides.payeeDid,
    payeeSigningSeed: overrides.payeeSigningSeed,
    budget,
    currency,
    amountCents,
    evidenceSchema,
    deadlineRfc3339: overrides.deadlineRfc3339,
    allowedTools,
    settlementRail: overrides.settlementRail,
    policyBinding,
    publishedPolicyHead: overrides.publishedPolicyHead,
    recognitionProof: overrides.recognitionProof,
    intentId: overrides.intentId,
    predicateRef: overrides.predicateRef,
    completionPresetId,
    completionContract,
  };
}
