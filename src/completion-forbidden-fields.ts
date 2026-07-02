import type { CompletionPreset } from "./completion-catalog.js";

/** Returns top-level evidence keys that intersect the preset forbidden list. */
export function forbiddenFieldsInEvidence(
  evidence: Record<string, unknown> | undefined,
  forbidden: string[] | undefined,
): string[] {
  if (!evidence || !forbidden?.length) {
    return [];
  }
  const blocked = new Set(forbidden);
  return Object.keys(evidence).filter((key) => blocked.has(key));
}

/** Checks vendor keys and their mapped canonical names against forbidden fields. */
export function forbiddenFieldsInVendorPayload(
  preset: CompletionPreset,
  vendorPayload: Record<string, unknown> | undefined,
  forbidden: string[] | undefined,
): string[] {
  if (!vendorPayload || !forbidden?.length) {
    return [];
  }
  const blocked = new Set(forbidden);
  const fieldMap = preset.evidence_field_map ?? {};
  const hits: string[] = [];
  for (const vendorKey of Object.keys(vendorPayload)) {
    const canonicalKey = fieldMap[vendorKey] ?? vendorKey;
    if (blocked.has(vendorKey) || blocked.has(canonicalKey)) {
      if (!hits.includes(vendorKey)) {
        hits.push(vendorKey);
      }
    }
  }
  return hits;
}
