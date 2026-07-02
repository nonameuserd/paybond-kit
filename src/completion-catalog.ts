import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { verifyBundledCompletionCatalogIntegrity } from "./completion-catalog-integrity.js";

export type CompletionPreset = {
  preset_id: string;
  title: string;
  description: string;
  harbor_template_id: string;
  parameters: Record<string, unknown>;
  evidence_schema: Record<string, unknown>;
  sample_evidence: Record<string, unknown>;
  sample_failing_evidence: Record<string, unknown>;
  human_summary: string;
  recommended_amount_cents?: number;
  spend_hints?: {
    approval_threshold_cents?: number;
    per_tool_max_cents?: number;
  };
  kind?: "archetype" | "vendor_pack";
  archetype_preset_id?: string;
  evidence_field_map?: Record<string, string>;
  vendor_evidence_schema?: Record<string, unknown>;
  vendor_sample_evidence?: Record<string, unknown>;
  scope?: "tool_completion" | "sandbox_smoke";
  rail_hints?: string[];
  forbidden_evidence_fields?: string[];
  anti_patterns?: string[];
  deprecated?: boolean;
  superseded_by?: string;
  vendor_contract?: {
    provider: "stripe" | "x402" | "mcp" | "generic";
    api_version: string;
    contract_kind: "json_schema" | "openapi_fragment" | "mapper_version";
    schema_digest_hex: string;
    canonical_schema_digest_hex: string;
    quality_fields: string[];
    supersedes?: string;
    migration_notes?: string;
  };
};

export type CompletionPresetCatalog = {
  version: number;
  presets: CompletionPreset[];
};

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

function catalogCandidatePaths(): string[] {
  return [
    join(MODULE_DIR, "../completion-presets/catalog.json"),
    join(MODULE_DIR, "../../../kit/completion-presets/catalog.json"),
    join(MODULE_DIR, "../../completion-presets/catalog.json"),
  ];
}

let cachedCatalog: CompletionPresetCatalog | undefined;

export function loadCompletionCatalog(): CompletionPresetCatalog {
  if (cachedCatalog) {
    return cachedCatalog;
  }
  let lastError: unknown;
  for (const candidate of catalogCandidatePaths()) {
    try {
      const raw = readFileSync(candidate, "utf8");
      verifyBundledCompletionCatalogIntegrity(raw);
      cachedCatalog = JSON.parse(raw) as CompletionPresetCatalog;
      return cachedCatalog;
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(
    `completion preset catalog not found (${catalogCandidatePaths().join(", ")}): ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

export function listCompletionPresetIds(): string[] {
  return loadCompletionCatalog().presets.map((preset) => preset.preset_id);
}

export function getCompletionPreset(presetId: string): CompletionPreset {
  const preset = loadCompletionCatalog().presets.find((entry) => entry.preset_id === presetId);
  if (!preset) {
    throw new Error(`unknown completion preset: ${presetId}`);
  }
  return preset;
}

export function getCompletionPresetByTemplateId(templateId: string): CompletionPreset | undefined {
  const matches = loadCompletionCatalog().presets.filter(
    (entry) => entry.harbor_template_id === templateId,
  );
  if (matches.length === 0) {
    return undefined;
  }
  return (
    matches.find((entry) => entry.kind !== "vendor_pack") ??
    matches.find((entry) => entry.kind === "archetype") ??
    matches[0]
  );
}

export function listCompletionPresetsByTemplateId(templateId: string): CompletionPreset[] {
  return loadCompletionCatalog().presets.filter((entry) => entry.harbor_template_id === templateId);
}

export function jsonLiteral(value: unknown, indent = 2): string {
  return JSON.stringify(value, null, indent);
}

export function catalogPathForTests(): string {
  return join(MODULE_DIR, "../completion-presets/catalog.json");
}

export function catalogFileUrl(): string {
  return pathToFileURL(catalogPathForTests()).href;
}
