import {
  getCompletionPreset,
  loadCompletionCatalog,
  type CompletionPreset,
} from "./completion-catalog.js";
import { completionSchemaDigestHex } from "./completion-contract-digest.js";

export type CompletionPresetKind = "archetype" | "vendor_pack";

export type ResolvedCompletionPreset = {
  preset: CompletionPreset;
  archetype: CompletionPreset;
  kind: CompletionPresetKind;
  harborTemplateId: string;
  parameters: Record<string, unknown>;
  evidenceSchema: Record<string, unknown>;
};

export function presetKind(preset: CompletionPreset): CompletionPresetKind {
  return preset.kind === "vendor_pack" ? "vendor_pack" : "archetype";
}

export function isVendorPack(preset: CompletionPreset): boolean {
  return presetKind(preset) === "vendor_pack";
}

/** Resolves vendor packs to their underlying archetype for Harbor materialization. */
export function resolveCompletionPreset(presetId: string): ResolvedCompletionPreset {
  const preset = getCompletionPreset(presetId);
  if (!isVendorPack(preset)) {
    return {
      preset,
      archetype: preset,
      kind: "archetype",
      harborTemplateId: preset.harbor_template_id,
      parameters: preset.parameters,
      evidenceSchema: preset.evidence_schema,
    };
  }
  const archetypeId = preset.archetype_preset_id;
  if (!archetypeId) {
    throw new Error(`vendor pack ${presetId} missing archetype_preset_id`);
  }
  const archetype = getCompletionPreset(archetypeId);
  return {
    preset,
    archetype,
    kind: "vendor_pack",
    harborTemplateId: archetype.harbor_template_id,
    parameters: { ...archetype.parameters, ...preset.parameters },
    evidenceSchema: preset.evidence_schema,
  };
}

/** Maps vendor-facing evidence fields to catalog canonical names for Harbor submit. */
export function mapVendorEvidenceToCanonical(
  preset: CompletionPreset,
  vendorEvidence: Record<string, unknown>,
): Record<string, unknown> {
  const fieldMap = preset.evidence_field_map ?? {};
  const out: Record<string, unknown> = {};
  for (const [vendorKey, value] of Object.entries(vendorEvidence)) {
    const canonicalKey = fieldMap[vendorKey] ?? vendorKey;
    if (canonicalKey === "artifact_blake3_hex" && !Array.isArray(value)) {
      out[canonicalKey] = [value];
      continue;
    }
    out[canonicalKey] = value;
  }
  return out;
}

/** Frozen completion contract metadata for intent pinning at create time. */
export function contractSnapshotForPreset(presetId: string): import("./principal-intent.js").CompletionContractSnapshot {
  const preset = getCompletionPreset(presetId);
  const contract = preset.vendor_contract;
  if (contract) {
    return {
      completionPresetId: preset.preset_id,
      vendorContractProvider: contract.provider,
      vendorApiVersion: contract.api_version,
      vendorSchemaDigestHex: contract.schema_digest_hex,
      canonicalSchemaDigestHex: contract.canonical_schema_digest_hex,
    };
  }
  if (preset.kind === "vendor_pack") {
    throw new Error(`vendor pack ${presetId} missing vendor_contract`);
  }
  return {
    completionPresetId: preset.preset_id,
    canonicalSchemaDigestHex: completionSchemaDigestHex(preset.evidence_schema),
  };
}

export function completionPresetDeprecationWarning(presetId: string): string | undefined {
  const preset = getCompletionPreset(presetId);
  if (!preset.deprecated) {
    return undefined;
  }
  const replacement = preset.superseded_by ?? "a newer preset";
  return `completion preset ${presetId} is deprecated; use ${replacement} instead`;
}

export function vendorEvidenceSchema(preset: CompletionPreset): Record<string, unknown> | undefined {
  return preset.vendor_evidence_schema;
}

export function listArchetypePresetIds(): string[] {
  return loadCompletionCatalog()
    .presets.filter((entry) => !isVendorPack(entry))
    .map((entry) => entry.preset_id);
}
