/**
 * BLAKE3 digests for completion preset vendor_contract schema pinning.
 * Matches `paybond-evidence::json_value_digest` and Harbor signing digests.
 */

import type { CompletionPreset } from "./completion-catalog.js";
import { jsonValueDigest } from "./json-digest.js";

export type VendorContract = {
  provider: "stripe" | "x402" | "mcp" | "generic";
  api_version: string;
  contract_kind: "json_schema" | "openapi_fragment" | "mapper_version";
  schema_digest_hex: string;
  canonical_schema_digest_hex: string;
  quality_fields: string[];
  supersedes?: string;
  migration_notes?: string;
};

export type VendorContractDigests = {
  schema_digest_hex: string;
  canonical_schema_digest_hex: string;
};

/** Hex-encode a 32-byte BLAKE3 digest. */
export function digestToHex(digest: Uint8Array): string {
  return Buffer.from(digest).toString("hex");
}

/** BLAKE3 hex digest of JCS-canonical JSON for a completion evidence schema object. */
export function completionSchemaDigestHex(schema: Record<string, unknown>): string {
  return digestToHex(jsonValueDigest(schema));
}

/** Compute vendor and canonical schema digests for a vendor_pack preset. */
export function computeVendorContractDigests(preset: {
  vendor_evidence_schema: Record<string, unknown>;
  evidence_schema: Record<string, unknown>;
}): VendorContractDigests {
  return {
    schema_digest_hex: completionSchemaDigestHex(preset.vendor_evidence_schema),
    canonical_schema_digest_hex: completionSchemaDigestHex(preset.evidence_schema),
  };
}

function vendorSchemaFieldNames(schema: Record<string, unknown>): Set<string> {
  const props = schema.properties;
  if (!props || typeof props !== "object" || Array.isArray(props)) {
    return new Set();
  }
  return new Set(Object.keys(props as Record<string, unknown>));
}

/**
 * Assert catalog-declared vendor_contract digests and quality_fields match computed values.
 * @throws when a vendor_pack contract is missing, stale, or references unknown quality fields.
 */
export function verifyVendorContract(preset: CompletionPreset): void {
  if (preset.kind !== "vendor_pack") {
    return;
  }
  const presetId = preset.preset_id;
  const contract = preset.vendor_contract;
  if (!contract) {
    throw new Error(`${presetId}: vendor_pack missing vendor_contract`);
  }
  if (!preset.vendor_evidence_schema || !preset.evidence_schema) {
    throw new Error(`${presetId}: vendor_pack missing evidence schemas`);
  }
  const computed = computeVendorContractDigests({
    vendor_evidence_schema: preset.vendor_evidence_schema,
    evidence_schema: preset.evidence_schema,
  });
  if (contract.schema_digest_hex !== computed.schema_digest_hex) {
    throw new Error(
      `${presetId}: vendor_contract.schema_digest_hex mismatch (catalog=${contract.schema_digest_hex}, computed=${computed.schema_digest_hex})`,
    );
  }
  if (contract.canonical_schema_digest_hex !== computed.canonical_schema_digest_hex) {
    throw new Error(
      `${presetId}: vendor_contract.canonical_schema_digest_hex mismatch (catalog=${contract.canonical_schema_digest_hex}, computed=${computed.canonical_schema_digest_hex})`,
    );
  }
  if (!contract.quality_fields?.length) {
    throw new Error(`${presetId}: vendor_contract.quality_fields must be non-empty`);
  }
  const allowed = vendorSchemaFieldNames(preset.vendor_evidence_schema);
  for (const field of contract.quality_fields) {
    if (!allowed.has(field)) {
      throw new Error(
        `${presetId}: quality_fields entry ${JSON.stringify(field)} is not a vendor_evidence_schema property`,
      );
    }
  }
}

/** Verify all vendor_pack presets in a catalog document. */
export function verifyCatalogVendorContracts(catalog: { presets: CompletionPreset[] }): void {
  const vendorPacks = catalog.presets.filter((preset) => preset.kind === "vendor_pack");
  if (vendorPacks.length === 0) {
    throw new Error("catalog must contain at least one vendor_pack preset");
  }
  for (const preset of vendorPacks) {
    verifyVendorContract(preset);
  }
}
