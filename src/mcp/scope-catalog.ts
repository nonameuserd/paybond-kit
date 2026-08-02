/**
 * Canonical Paybond MCP scope catalog (TypeScript mirror).
 *
 * Mirrors `kit/mcp-scopes/catalog.json`, which is also mirrored by
 * `kit/python/src/paybond_kit/mcp_scope_catalog.py` and the Go gateway catalog.
 * Parity is enforced by tests in every runtime — do not edit one mirror without
 * the others.
 *
 * Restricted `paybond_rk_*` keys carry an explicit scope grant; the credential is
 * the permission model. Standard `paybond_sk_*` keys carry no MCP scopes and keep
 * the pre-existing env tool-policy behavior.
 */

/** Grant level within one scope group. `write` implies `read`. */
export type McpScopeLevel = "read" | "write";

/** One granted or required MCP scope entry. */
export type McpScope = {
  scope: string;
  level: McpScopeLevel;
};

/** Catalog metadata for one scope group. */
export type McpScopeDefinition = {
  id: string;
  title: string;
  maxLevel: McpScopeLevel;
  description: string;
};

/** Gateway route covered by a scope, used for defense-in-depth documentation. */
export type McpScopeRoute = {
  method: "GET" | "POST";
  pattern: string;
  scope: string;
  level: McpScopeLevel;
};

/** Console/CLI starting template for a restricted key scope grant. */
export type McpScopePreset = {
  id: string;
  title: string;
  description: string;
  scopes: readonly McpScope[];
};

/** Prefix classification of a Paybond API key string. */
export type PaybondApiKeyKind = "standard" | "restricted" | "unknown";

export const MCP_SCOPE_CATALOG_VERSION = 1;

export const MCP_SCOPE_LEVELS: readonly McpScopeLevel[] = ["read", "write"];

export const STANDARD_API_KEY_PREFIX = "paybond_sk_";
export const RESTRICTED_API_KEY_PREFIX = "paybond_rk_";
/** User-scoped MCP OAuth access tokens issued by `/v1/oauth/token`. */
export const MCP_OAUTH_ACCESS_TOKEN_PREFIX = "paybond_oat_";

export const MCP_SCOPE_DEFINITIONS: readonly McpScopeDefinition[] = [
  {
    id: "mcp.discovery",
    title: "Discovery",
    maxLevel: "read",
    description:
      "Principal identity, Harbor intent reads, and side-effect-free spend policy dry-runs.",
  },
  {
    id: "mcp.signal",
    title: "Signal standing",
    maxLevel: "read",
    description: "Reputation receipts, portfolio artifacts, and fraud review reads.",
  },
  {
    id: "mcp.compliance",
    title: "Compliance exports",
    maxLevel: "read",
    description: "Audit export listing and retrieval.",
  },
  {
    id: "mcp.a2a",
    title: "A2A and mandates",
    maxLevel: "write",
    description:
      "Agent card, task contracts, and mandate verification (read); mandate import (write).",
  },
  {
    id: "mcp.receipts",
    title: "Receipts",
    maxLevel: "read",
    description: "Settlement, protocol, and agent receipt retrieval plus verification.",
  },
  {
    id: "mcp.evidence",
    title: "Completion evidence",
    maxLevel: "write",
    description:
      "Local evidence validation (read); Harbor completion evidence submission (write).",
  },
  {
    id: "mcp.spend",
    title: "Spend authorization",
    maxLevel: "write",
    description:
      "Intent creation, capability verification, and agent spend authorization.",
  },
  {
    id: "mcp.settlement",
    title: "Settlement (live money)",
    maxLevel: "write",
    description:
      "Funding intents and confirming settlement. Never included in a preset; must be chosen explicitly.",
  },
  {
    id: "mcp.sandbox",
    title: "Sandbox guardrails",
    maxLevel: "write",
    description: "Sandbox guardrail bootstrap and sandbox guardrail evidence.",
  },
];

export const MCP_TOOL_SCOPES: Readonly<Record<string, McpScope>> = {
  paybond_get_principal: { scope: "mcp.discovery", level: "read" },
  paybond_list_intents: { scope: "mcp.discovery", level: "read" },
  paybond_get_intent: { scope: "mcp.discovery", level: "read" },
  paybond_explain_policy: { scope: "mcp.discovery", level: "read" },
  paybond_get_budget_remaining: { scope: "mcp.discovery", level: "read" },

  paybond_get_reputation_receipt: { scope: "mcp.signal", level: "read" },
  paybond_get_portfolio_summary: { scope: "mcp.signal", level: "read" },
  paybond_get_signed_portfolio_artifact: { scope: "mcp.signal", level: "read" },
  paybond_get_fraud_assessment: { scope: "mcp.signal", level: "read" },
  paybond_get_fraud_metrics: { scope: "mcp.signal", level: "read" },

  paybond_list_audit_exports: { scope: "mcp.compliance", level: "read" },
  paybond_get_audit_export: { scope: "mcp.compliance", level: "read" },

  paybond_get_a2a_agent_card: { scope: "mcp.a2a", level: "read" },
  paybond_list_a2a_task_contracts: { scope: "mcp.a2a", level: "read" },
  paybond_get_a2a_task_contract: { scope: "mcp.a2a", level: "read" },
  paybond_verify_agent_mandate_v1: { scope: "mcp.a2a", level: "read" },
  paybond_verify_agent_recognition_proof_v1: { scope: "mcp.a2a", level: "read" },
  paybond_import_agent_mandate_v1: { scope: "mcp.a2a", level: "write" },

  paybond_get_settlement_receipt_v1: { scope: "mcp.receipts", level: "read" },
  paybond_get_agent_receipt_v1: { scope: "mcp.receipts", level: "read" },
  paybond_verify_agent_receipt_v1: { scope: "mcp.receipts", level: "read" },
  paybond_verify_protocol_receipt_v1: { scope: "mcp.receipts", level: "read" },

  paybond_validate_completion_evidence: { scope: "mcp.evidence", level: "read" },
  paybond_submit_evidence: { scope: "mcp.evidence", level: "write" },
  paybond_submit_spend_evidence: { scope: "mcp.evidence", level: "write" },

  paybond_create_intent: { scope: "mcp.spend", level: "write" },
  paybond_create_spend_intent: { scope: "mcp.spend", level: "write" },
  paybond_authorize_agent_spend: { scope: "mcp.spend", level: "write" },
  paybond_verify_capability: { scope: "mcp.spend", level: "write" },

  paybond_fund_intent: { scope: "mcp.settlement", level: "write" },
  paybond_confirm_settlement: { scope: "mcp.settlement", level: "write" },

  paybond_bootstrap_sandbox_guardrail: { scope: "mcp.sandbox", level: "write" },
  paybond_submit_sandbox_guardrail_evidence: { scope: "mcp.sandbox", level: "write" },
};

export const MCP_RESOURCE_SCOPES: Readonly<Record<string, McpScope>> = {
  "paybond-agent-receipt": { scope: "mcp.receipts", level: "read" },
};

export const MCP_SCOPE_ROUTES: readonly McpScopeRoute[] = [
  { method: "GET", pattern: "/v1/auth/principal", scope: "mcp.discovery", level: "read" },
  { method: "GET", pattern: "/harbor/operator/v1/intents", scope: "mcp.discovery", level: "read" },
  {
    method: "GET",
    pattern: "/harbor/operator/v1/intents/{intent_id}",
    scope: "mcp.discovery",
    level: "read",
  },
  { method: "POST", pattern: "/v1/spend/preflight", scope: "mcp.discovery", level: "read" },

  { method: "GET", pattern: "/reputation/{operator_did}", scope: "mcp.signal", level: "read" },
  { method: "GET", pattern: "/signal/v1/portfolio/summary", scope: "mcp.signal", level: "read" },
  {
    method: "GET",
    pattern: "/signal/v1/portfolio/signed-export",
    scope: "mcp.signal",
    level: "read",
  },
  {
    method: "GET",
    pattern: "/signal/v1/operators/{operator_did}/review-status",
    scope: "mcp.signal",
    level: "read",
  },
  { method: "GET", pattern: "/signal/v1/fraud/metrics", scope: "mcp.signal", level: "read" },

  {
    method: "GET",
    pattern: "/v1/compliance/audit-exports",
    scope: "mcp.compliance",
    level: "read",
  },
  {
    method: "GET",
    pattern: "/v1/compliance/audit-exports/{job_id}",
    scope: "mcp.compliance",
    level: "read",
  },

  { method: "GET", pattern: "/.well-known/agent-card.json", scope: "mcp.a2a", level: "read" },
  { method: "GET", pattern: "/protocol/v2/a2a/task-contracts", scope: "mcp.a2a", level: "read" },
  {
    method: "GET",
    pattern: "/protocol/v2/a2a/task-contracts/{contract_id}",
    scope: "mcp.a2a",
    level: "read",
  },
  { method: "POST", pattern: "/protocol/v2/mandates/verify", scope: "mcp.a2a", level: "read" },
  { method: "POST", pattern: "/protocol/v2/recognition/verify", scope: "mcp.a2a", level: "read" },
  { method: "POST", pattern: "/protocol/v2/mandates", scope: "mcp.a2a", level: "write" },

  {
    method: "GET",
    pattern: "/protocol/v2/receipts/{receipt_id}",
    scope: "mcp.receipts",
    level: "read",
  },
  { method: "POST", pattern: "/protocol/v2/receipts/verify", scope: "mcp.receipts", level: "read" },
  { method: "GET", pattern: "/protocol/v2/agent-receipts", scope: "mcp.receipts", level: "read" },
  {
    method: "GET",
    pattern: "/protocol/v2/agent-receipts/{receipt_id}",
    scope: "mcp.receipts",
    level: "read",
  },
  {
    method: "POST",
    pattern: "/protocol/v2/agent-receipts/verify",
    scope: "mcp.receipts",
    level: "read",
  },

  {
    method: "POST",
    pattern: "/harbor/intents/{intent_id}/evidence",
    scope: "mcp.evidence",
    level: "write",
  },

  { method: "POST", pattern: "/verify", scope: "mcp.spend", level: "write" },
  { method: "POST", pattern: "/harbor/intents", scope: "mcp.spend", level: "write" },

  {
    method: "POST",
    pattern: "/harbor/intents/{intent_id}/fund",
    scope: "mcp.settlement",
    level: "write",
  },
  {
    method: "POST",
    pattern: "/harbor/intents/{intent_id}/settlement/confirm",
    scope: "mcp.settlement",
    level: "write",
  },

  {
    method: "POST",
    pattern: "/v1/sandbox/guardrails/bootstrap",
    scope: "mcp.sandbox",
    level: "write",
  },
  {
    method: "POST",
    pattern: "/v1/sandbox/guardrails/{intent_id}/evidence",
    scope: "mcp.sandbox",
    level: "write",
  },
];

export const MCP_SCOPE_PRESETS: readonly McpScopePreset[] = [
  {
    id: "mcp-readonly",
    title: "MCP Readonly Discovery",
    description:
      "Identity, Harbor intent reads, Signal standing, compliance exports, and receipts. No writes.",
    scopes: [
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.signal", level: "read" },
      { scope: "mcp.compliance", level: "read" },
      { scope: "mcp.receipts", level: "read" },
    ],
  },
  {
    id: "mcp-spend-operator",
    title: "MCP Spend Operator",
    description:
      "Readonly discovery plus intent creation, spend authorization, and completion evidence. No settlement.",
    scopes: [
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.signal", level: "read" },
      { scope: "mcp.compliance", level: "read" },
      { scope: "mcp.receipts", level: "read" },
      { scope: "mcp.spend", level: "write" },
      { scope: "mcp.evidence", level: "write" },
    ],
  },
  {
    id: "mcp-sandbox-agent",
    title: "MCP Sandbox Agent",
    description:
      "Sandbox guardrail bootstrap and evidence plus the discovery and spend authorization path.",
    scopes: [
      { scope: "mcp.discovery", level: "read" },
      { scope: "mcp.sandbox", level: "write" },
      { scope: "mcp.spend", level: "write" },
    ],
  },
];

const SCOPE_DEFINITION_BY_ID: Map<string, McpScopeDefinition> = new Map(
  MCP_SCOPE_DEFINITIONS.map((definition) => [definition.id, definition]),
);

const PRESET_BY_ID: Map<string, McpScopePreset> = new Map(
  MCP_SCOPE_PRESETS.map((preset) => [preset.id, preset]),
);

function levelRank(level: McpScopeLevel): number {
  return level === "write" ? 1 : 0;
}

function normalizeLevel(raw: unknown): McpScopeLevel | null {
  if (typeof raw !== "string") {
    return null;
  }
  const value = raw.trim().toLowerCase();
  return value === "read" || value === "write" ? value : null;
}

/** Render a scope as its canonical `mcp.spend:write` wire/CLI token. */
export function formatMcpScope(scope: McpScope): string {
  return `${scope.scope}:${scope.level}`;
}

/** Catalog definition for a scope id, or `null` when the id is unknown. */
export function mcpScopeDefinition(scopeId: string): McpScopeDefinition | null {
  return SCOPE_DEFINITION_BY_ID.get(scopeId.trim()) ?? null;
}

/** Sorted tool names unlocked by one scope id (empty for unknown ids). */
export function toolsForMcpScope(scopeId: string): string[] {
  const id = scopeId.trim();
  return Object.entries(MCP_TOOL_SCOPES)
    .filter(([, required]) => required.scope === id)
    .map(([name]) => name)
    .sort();
}

/**
 * Parse the `mcp_scopes` value from a `GET /v1/auth/principal` response.
 *
 * Deliberately tolerant so a gateway that ships new scope ids ahead of Kit does
 * not break existing hosts: unknown scope ids, unknown levels, and malformed
 * entries are dropped rather than raising. Duplicate scope ids collapse to the
 * highest granted level. Accepts both the object wire form
 * (`{"scope":"mcp.spend","level":"write"}`) and the `mcp.spend:write` string form.
 */
export function parseMcpScopes(raw: unknown): McpScope[] {
  if (!Array.isArray(raw)) {
    return [];
  }
  const byScope = new Map<string, McpScopeLevel>();
  for (const entry of raw) {
    let scopeId: string | null = null;
    let level: McpScopeLevel | null = null;
    if (typeof entry === "string") {
      const [rawId, rawLevel] = entry.split(":", 2);
      scopeId = (rawId ?? "").trim();
      level = normalizeLevel(rawLevel);
    } else if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
      const record = entry as Record<string, unknown>;
      scopeId = typeof record.scope === "string" ? record.scope.trim() : null;
      level = normalizeLevel(record.level);
    }
    if (!scopeId || level === null || !SCOPE_DEFINITION_BY_ID.has(scopeId)) {
      continue;
    }
    const existing = byScope.get(scopeId);
    if (existing === undefined || levelRank(level) > levelRank(existing)) {
      byScope.set(scopeId, level);
    }
  }
  return MCP_SCOPE_DEFINITIONS.filter((definition) => byScope.has(definition.id)).map(
    (definition) => ({ scope: definition.id, level: byScope.get(definition.id)! }),
  );
}

/**
 * Parse one `mcp.spend:write` CLI/config token.
 *
 * Throws with an actionable message listing the catalog scope ids so callers can
 * fail before a gateway round-trip.
 */
export function parseMcpScopeToken(raw: string): McpScope {
  const value = (raw ?? "").trim();
  if (!value) {
    throw new Error("invalid MCP scope (expected <scope-id>:read|write)");
  }
  const separator = value.lastIndexOf(":");
  if (separator <= 0 || separator === value.length - 1) {
    throw new Error(
      `invalid MCP scope ${value} (expected <scope-id>:read|write, e.g. mcp.spend:write)`,
    );
  }
  const scopeId = value.slice(0, separator).trim();
  const level = normalizeLevel(value.slice(separator + 1));
  if (level === null) {
    throw new Error(`invalid MCP scope level in ${value} (expected read or write)`);
  }
  const definition = SCOPE_DEFINITION_BY_ID.get(scopeId);
  if (!definition) {
    throw new Error(
      `unknown MCP scope ${scopeId} (expected one of ${MCP_SCOPE_DEFINITIONS.map(
        (candidate) => candidate.id,
      ).join(", ")})`,
    );
  }
  if (levelRank(level) > levelRank(definition.maxLevel)) {
    throw new Error(
      `MCP scope ${scopeId} supports at most level ${definition.maxLevel}; got ${level}`,
    );
  }
  return { scope: definition.id, level };
}

/** Deduplicate scopes in catalog order, keeping the highest granted level. */
export function normalizeMcpScopes(scopes: readonly McpScope[]): McpScope[] {
  return parseMcpScopes(scopes.map((scope) => ({ scope: scope.scope, level: scope.level })));
}

/** True when `granted` covers `required`; `write` satisfies a `read` requirement. */
export function scopeSatisfies(granted: readonly McpScope[], required: McpScope): boolean {
  return granted.some(
    (entry) =>
      entry.scope === required.scope && levelRank(entry.level) >= levelRank(required.level),
  );
}

/** Required scope for an MCP tool name, or `null` when the tool is not in the catalog. */
export function requiredScopeForTool(name: string): McpScope | null {
  return MCP_TOOL_SCOPES[name.trim()] ?? null;
}

/** Required scope for an MCP resource name, or `null` when it is not in the catalog. */
export function requiredScopeForResource(name: string): McpScope | null {
  return MCP_RESOURCE_SCOPES[name.trim()] ?? null;
}

/**
 * Scope decision for one tool under a restricted-key grant.
 *
 * Fails closed: a tool name absent from the catalog is denied, so a newly added
 * tool cannot be exposed to a restricted key before it is mapped to a scope.
 */
export function toolAllowedByScope(name: string, granted: readonly McpScope[]): boolean {
  const required = requiredScopeForTool(name);
  if (required === null) {
    return false;
  }
  return scopeSatisfies(granted, required);
}

/** Scopes granted by a preset id, or `null` when the preset is unknown. */
export function presetScopes(presetId: string): McpScope[] | null {
  const preset = PRESET_BY_ID.get(presetId.trim());
  if (!preset) {
    return null;
  }
  return preset.scopes.map((scope) => ({ scope: scope.scope, level: scope.level }));
}

/** Preset metadata for a preset id, or `null` when the preset is unknown. */
export function mcpScopePreset(presetId: string): McpScopePreset | null {
  return PRESET_BY_ID.get(presetId.trim()) ?? null;
}

/**
 * Classify a Paybond API key by prefix only.
 *
 * Never parses, hashes, or logs secret material — only the public prefix is
 * inspected so callers can pick the right permission model.
 */
export function classifyPaybondApiKey(apiKey: string): PaybondApiKeyKind {
  const value = (apiKey ?? "").trim();
  if (value.startsWith(RESTRICTED_API_KEY_PREFIX)) {
    return "restricted";
  }
  // MCP OAuth access tokens are always scope-capped (gateway wires key_kind=restricted
  // for wire compatibility). Classify them the same so principal-resolution failures
  // fail closed instead of widening the tool surface.
  if (value.startsWith(MCP_OAUTH_ACCESS_TOKEN_PREFIX)) {
    return "restricted";
  }
  if (value.startsWith(STANDARD_API_KEY_PREFIX)) {
    return "standard";
  }
  return "unknown";
}

/** True when the key string carries the restricted `paybond_rk_` prefix. */
export function isRestrictedPaybondApiKey(apiKey: string): boolean {
  return classifyPaybondApiKey(apiKey) === "restricted";
}
