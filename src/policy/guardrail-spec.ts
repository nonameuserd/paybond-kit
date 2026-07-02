import {
  auditOnly,
  allowDryRun,
  defaultDeny,
  guardrails,
  maxSpend,
  maxSpendUsd,
  readOnly,
  readOnlySearch,
  requireEvidence,
  strict,
  type PolicyGuardrailLayer,
} from "./guardrails.js";

export type GuardrailCatalogEntry = {
  id: string;
  title: string;
  description: string;
  parameterized?: boolean;
};

/** Built-in guardrail ids accepted by `policy init --guardrails` and solution manifests. */
export const GUARDRAIL_CATALOG_ENTRIES: GuardrailCatalogEntry[] = [
  {
    id: "default-deny",
    title: "Default deny",
    description: "Require explicit tool registration (default_deny: true)",
  },
  {
    id: "read-only",
    title: "Read only",
    description: "Keep only non-side-effecting tools",
  },
  {
    id: "read-only-search",
    title: "Read-only search",
    description: "Keep only non-side-effecting search.* tools",
  },
  {
    id: "strict",
    title: "Strict",
    description: "Tight caps, default deny, and evidence required on side-effecting tools",
  },
  {
    id: "require-evidence",
    title: "Require evidence",
    description: "Validate evidence_preset on side-effecting tools at compose time",
  },
  {
    id: "audit-only",
    title: "Audit only",
    description: "Reserved governance hook (no-op layer today)",
  },
  {
    id: "allow-dry-run",
    title: "Allow dry run",
    description: "Reserved governance hook (no-op layer today)",
  },
  {
    id: "max-spend:<usd>",
    title: "Max spend (USD)",
    description: "Cap intent budget and side-effecting tool spend (USD parameter)",
    parameterized: true,
  },
  {
    id: "max-spend-cents:<cents>",
    title: "Max spend (cents)",
    description: "Cap side-effecting tool spend in cents",
    parameterized: true,
  },
  {
    id: "max-spend-usd:<usd>",
    title: "Max spend budget (USD)",
    description: "Cap intent budget max_spend_usd only",
    parameterized: true,
  },
];

function normalizeGuardrailToken(token: string): string {
  return token.trim().toLowerCase().replace(/_/g, "-");
}

function parsePositiveNumber(raw: string, label: string): number {
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${label} requires a non-negative number`);
  }
  return value;
}

/** Resolve a solution-manifest guardrail token (for example `max_spend_usd_200`). */
export function resolveGuardrailManifestToken(token: string): PolicyGuardrailLayer {
  const trimmed = token.trim();
  const manifestUsd = /^max_spend_usd_(\d+(?:\.\d+)?)$/i.exec(trimmed);
  if (manifestUsd) {
    return maxSpendUsd(parsePositiveNumber(manifestUsd[1]!, "max_spend_usd"));
  }
  return parseGuardrailSpec(trimmed);
}

/** Parse one guardrail token from CLI `--guardrails` or solution manifests. */
export function parseGuardrailSpec(spec: string): PolicyGuardrailLayer {
  const normalized = normalizeGuardrailToken(spec);
  if (!normalized) {
    throw new Error("guardrail spec must not be empty");
  }

  const maxSpendMatch = /^max-spend:(\d+(?:\.\d+)?)$/.exec(normalized);
  if (maxSpendMatch) {
    const usd = parsePositiveNumber(maxSpendMatch[1]!, "max-spend");
    return {
      caps: {
        budgetMaxSpendUsd: usd,
        sideEffectingMaxSpendCents: Math.round(usd * 100),
      },
    };
  }

  const maxSpendUsdMatch = /^max-spend-usd:(\d+(?:\.\d+)?)$/.exec(normalized);
  if (maxSpendUsdMatch) {
    return maxSpendUsd(parsePositiveNumber(maxSpendUsdMatch[1]!, "max-spend-usd"));
  }

  const maxSpendCentsMatch = /^max-spend-cents:(\d+)$/.exec(normalized);
  if (maxSpendCentsMatch) {
    return maxSpend(parsePositiveNumber(maxSpendCentsMatch[1]!, "max-spend-cents"));
  }

  switch (normalized) {
    case "default-deny":
    case "defaultdeny":
      return defaultDeny();
    case "read-only":
    case "readonly":
      return readOnly();
    case "read-only-search":
    case "readonlysearch":
      return readOnlySearch();
    case "strict":
      return strict();
    case "require-evidence":
    case "requireevidence":
      return requireEvidence();
    case "audit-only":
    case "auditonly":
      return auditOnly();
    case "allow-dry-run":
    case "allowdryrun":
      return allowDryRun();
    default:
      throw new Error(`unknown guardrail: ${spec}`);
  }
}

/** Parse a comma-separated guardrail spec list from CLI flags. */
export function parseGuardrailSpecs(csv: string): PolicyGuardrailLayer[] {
  const tokens = csv
    .split(",")
    .map((token) => token.trim())
    .filter((token) => token.length > 0);
  if (tokens.length === 0) {
    throw new Error("guardrails list must include at least one entry");
  }
  return tokens.map((token) => parseGuardrailSpec(token));
}

export function listGuardrailCatalogEntries(): GuardrailCatalogEntry[] {
  return [...GUARDRAIL_CATALOG_ENTRIES];
}

export { guardrails };
