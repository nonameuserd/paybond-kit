import type {
  PaybondPolicyIntentSection,
  PaybondPolicyToolEntry,
} from "./schema.js";

/** Partial policy patch applied on top of a domain document during compose. */
export type PolicyGuardrailLayer = {
  default_deny?: boolean;
  tools?: Record<string, Partial<PaybondPolicyToolEntry>>;
  intent?: Partial<PaybondPolicyIntentSection>;
  filters?: {
    readOnly?: boolean;
    readOnlySearch?: boolean;
  };
  caps?: {
    sideEffectingMaxSpendCents?: number;
    budgetMaxSpendUsd?: number;
  };
  requireEvidence?: boolean;
};

/** Require `default_deny: true` (stricter wins when stacked). */
export function defaultDeny(): PolicyGuardrailLayer {
  return { default_deny: true };
}

/** Cap every side-effecting tool at `cents` (stricter min wins when stacked). */
export function maxSpend(cents: number): PolicyGuardrailLayer {
  if (!Number.isInteger(cents) || cents < 0) {
    throw new Error("maxSpend requires a non-negative integer cents value");
  }
  return { caps: { sideEffectingMaxSpendCents: cents } };
}

/** Cap intent budget at `usd` dollars (stricter min wins when stacked). */
export function maxSpendUsd(usd: number): PolicyGuardrailLayer {
  if (typeof usd !== "number" || usd < 0 || !Number.isFinite(usd)) {
    throw new Error("maxSpendUsd requires a non-negative finite USD value");
  }
  return { caps: { budgetMaxSpendUsd: usd } };
}

/** Keep only non-side-effecting tools and intersect allowed_tools. */
export function readOnly(): PolicyGuardrailLayer {
  return { filters: { readOnly: true } };
}

/** Keep only non-side-effecting search.* tools. */
export function readOnlySearch(): PolicyGuardrailLayer {
  return { filters: { readOnlySearch: true } };
}

/** Tight caps, default deny, and evidence required on side-effecting tools. */
export function strict(): PolicyGuardrailLayer {
  return {
    default_deny: true,
    caps: { sideEffectingMaxSpendCents: 1000, budgetMaxSpendUsd: 10 },
    requireEvidence: true,
  };
}

/** Governance hook: validate evidence presets at compose time (no extra fields). */
export function requireEvidence(): PolicyGuardrailLayer {
  return { requireEvidence: true };
}

/** Governance hook reserved for audit-only execution modes (no-op layer today). */
export function auditOnly(): PolicyGuardrailLayer {
  return {};
}

/** Governance hook reserved for dry-run modes (no-op layer today). */
export function allowDryRun(): PolicyGuardrailLayer {
  return {};
}

/** Convert a bundled guardrails YAML object into a compose layer. */
export function guardrailLayerFromDocument(document: Record<string, unknown>): PolicyGuardrailLayer {
  const layer: PolicyGuardrailLayer = {};
  if (document.default_deny === true) {
    layer.default_deny = true;
  }
  if (document.tools && typeof document.tools === "object" && !Array.isArray(document.tools)) {
    layer.tools = document.tools as Record<string, Partial<PaybondPolicyToolEntry>>;
  }
  if (document.intent && typeof document.intent === "object" && !Array.isArray(document.intent)) {
    layer.intent = document.intent as Partial<PaybondPolicyIntentSection>;
  }
  return layer;
}

export const guardrails = {
  defaultDeny,
  maxSpend,
  maxSpendUsd,
  readOnly,
  readOnlySearch,
  strict,
  requireEvidence,
  auditOnly,
  allowDryRun,
  fromDocument: guardrailLayerFromDocument,
} as const;
