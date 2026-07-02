import { Ajv2020 } from "ajv/dist/2020.js";

import { getCompletionPreset } from "./completion-catalog.js";
import {
  forbiddenFieldsInEvidence,
  forbiddenFieldsInVendorPayload,
} from "./completion-forbidden-fields.js";
import {
  isVendorPack,
  mapVendorEvidenceToCanonical,
  resolveCompletionPreset,
  vendorEvidenceSchema,
} from "./completion-resolve.js";

/** Local pre-validation report aligned with Harbor `SchemaValidationReport`. */
export type CompletionEvidenceValidationReport = {
  preset_id: string;
  vendor_schema_ok: boolean;
  canonical_schema_ok: boolean;
  quality_fields_missing: string[];
  forbidden_fields_present: string[];
  pack_stale: boolean;
  drift_kinds: string[];
  canonical_payload?: Record<string, unknown>;
};

function pushDriftKind(kinds: string[], kind: string): void {
  if (!kinds.includes(kind)) {
    kinds.push(kind);
  }
}

function classifyAjvError(error: { instancePath: string; message?: string }): string {
  const message = error.message ?? "";
  if (!error.instancePath && message.includes("required")) {
    return "missing_field";
  }
  if (message.includes("required")) {
    return "missing_field";
  }
  return "type_mismatch";
}

function validateJsonSchema(schema: Record<string, unknown>, instance: unknown): string[] {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  const validate = ajv.compile(schema);
  if (validate(instance)) {
    return [];
  }
  const kinds: string[] = [];
  for (const error of validate.errors ?? []) {
    pushDriftKind(kinds, classifyAjvError(error));
  }
  return kinds.length > 0 ? kinds : ["type_mismatch"];
}

function missingQualityFields(
  payload: Record<string, unknown>,
  qualityFields: string[] | undefined,
): string[] {
  if (!qualityFields?.length) {
    return [];
  }
  return qualityFields.filter((field) => {
    const value = payload[field];
    return value === undefined || value === null;
  });
}

/**
 * Validates vendor and canonical completion evidence against catalog JSON Schemas.
 * Signal-only: returns drift metadata without throwing on schema mismatch.
 */
export function validateCompletionEvidence(input: {
  presetId: string;
  vendorPayload?: Record<string, unknown>;
  canonicalPayload?: Record<string, unknown>;
  /** When set, compares catalog contract digests to detect pack_stale (intent pin drift). */
  frozenVendorApiVersion?: string;
  frozenVendorSchemaDigestHex?: string;
  frozenCanonicalSchemaDigestHex?: string;
}): CompletionEvidenceValidationReport {
  const preset = getCompletionPreset(input.presetId);
  const resolved = resolveCompletionPreset(input.presetId);
  const contract = preset.vendor_contract;
  const driftKinds: string[] = [];
  let vendorSchemaOk = true;
  let canonicalSchemaOk = true;

  let canonicalPayload = input.canonicalPayload;
  if (!canonicalPayload && input.vendorPayload && isVendorPack(preset)) {
    canonicalPayload = mapVendorEvidenceToCanonical(preset, input.vendorPayload);
  }
  if (!canonicalPayload && !isVendorPack(preset) && input.vendorPayload) {
    canonicalPayload = input.vendorPayload;
  }

  let packStale = false;
  if (input.frozenVendorApiVersion && contract?.api_version && input.frozenVendorApiVersion !== contract.api_version) {
    packStale = true;
    pushDriftKind(driftKinds, "pack_stale");
  }
  if (
    input.frozenVendorSchemaDigestHex &&
    contract?.schema_digest_hex &&
    input.frozenVendorSchemaDigestHex !== contract.schema_digest_hex
  ) {
    packStale = true;
    pushDriftKind(driftKinds, "pack_stale");
  }
  if (
    input.frozenCanonicalSchemaDigestHex &&
    contract?.canonical_schema_digest_hex &&
    input.frozenCanonicalSchemaDigestHex !== contract.canonical_schema_digest_hex
  ) {
    packStale = true;
    pushDriftKind(driftKinds, "pack_stale");
  }

  if (canonicalPayload) {
    const canonicalKinds = validateJsonSchema(resolved.evidenceSchema, canonicalPayload);
    if (canonicalKinds.length > 0) {
      canonicalSchemaOk = false;
      for (const kind of canonicalKinds) {
        pushDriftKind(driftKinds, kind);
      }
    }
  } else if (!isVendorPack(preset)) {
    canonicalSchemaOk = false;
    pushDriftKind(driftKinds, "missing_field");
  }

  const vendorSchema = vendorEvidenceSchema(preset);
  if (isVendorPack(preset)) {
    if (input.vendorPayload && vendorSchema && !packStale) {
      const vendorKinds = validateJsonSchema(vendorSchema, input.vendorPayload);
      if (vendorKinds.length > 0) {
        vendorSchemaOk = false;
        for (const kind of vendorKinds) {
          pushDriftKind(driftKinds, kind);
        }
      }
    } else if (!input.vendorPayload) {
      vendorSchemaOk = false;
      pushDriftKind(driftKinds, "missing_field");
    }
  }

  const qualityTarget = input.vendorPayload ?? canonicalPayload;
  const qualityMissing =
    qualityTarget && contract?.quality_fields
      ? missingQualityFields(qualityTarget, contract.quality_fields)
      : [];
  for (const _field of qualityMissing) {
    pushDriftKind(driftKinds, "quality_field_missing");
  }

  const forbidden = preset.forbidden_evidence_fields;
  const forbiddenHits: string[] = [];
  if (forbidden?.length) {
    if (input.vendorPayload) {
      forbiddenHits.push(
        ...forbiddenFieldsInVendorPayload(preset, input.vendorPayload, forbidden),
      );
    }
    if (canonicalPayload) {
      for (const field of forbiddenFieldsInEvidence(canonicalPayload, forbidden)) {
        if (!forbiddenHits.includes(field)) {
          forbiddenHits.push(field);
        }
      }
    }
  }
  for (const _field of forbiddenHits) {
    if (isVendorPack(preset) && input.vendorPayload) {
      vendorSchemaOk = false;
    }
    if (canonicalPayload) {
      canonicalSchemaOk = false;
    }
    pushDriftKind(driftKinds, "forbidden_field_present");
  }

  return {
    preset_id: input.presetId,
    vendor_schema_ok: vendorSchemaOk,
    canonical_schema_ok: canonicalSchemaOk,
    quality_fields_missing: qualityMissing,
    forbidden_fields_present: forbiddenHits,
    pack_stale: packStale,
    drift_kinds: driftKinds,
    canonical_payload: canonicalPayload,
  };
}
