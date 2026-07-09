import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Ajv2020 } from "ajv/dist/2020.js";

import {
  type AgentReceiptV1,
  type VerifyAgentReceiptV1Options,
  verifyAgentReceiptV1FromJSON,
} from "./agent-receipt.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const AGENT_RECEIPT_DIR = join(MODULE_DIR, "../../agent-receipt");

export const AGENT_RECEIPT_PDF_EXPORT_MANIFEST_SCHEMA_VERSION = 1;
export const AGENT_RECEIPT_PDF_EXPORT_MANIFEST_KIND =
  "paybond.agent_receipt_pdf_export_manifest_v1";
export const AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL =
  "Derived from paybond.agent_receipt_v1";

export const FORBIDDEN_PDF_EXPORT_MANIFEST_FIELDS = [
  "embedded_receipt_json",
  "receipt_json",
  "unsigned_receipt",
  "canonical_receipt",
  "user_prompt",
  "system_prompt",
  "tool_arguments",
  "tool_results",
  "evidence_payload",
  "payee_signature",
] as const;

export type AgentReceiptPDFExportSourceKind =
  | "gateway_fetch"
  | "audit_export"
  | "local_file";

export type AgentReceiptPDFExportFooterStamp = {
  label: typeof AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL;
  receipt_id: string;
  message_digest_sha256_hex: string;
  verify_endpoint?: string;
};

export type AgentReceiptPDFExportManifest = {
  schema_version: typeof AGENT_RECEIPT_PDF_EXPORT_MANIFEST_SCHEMA_VERSION;
  kind: typeof AGENT_RECEIPT_PDF_EXPORT_MANIFEST_KIND;
  receipt_id: string;
  message_digest_sha256_hex: string;
  source_kind: AgentReceiptPDFExportSourceKind;
  source_artifact?: string;
  generated_at_rfc3339: string;
  renderer_id?: string;
  pdf_sha256_hex?: string;
  pdf_page_count?: number;
  derived_view_label: typeof AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL;
  footer_stamp: AgentReceiptPDFExportFooterStamp;
};

let manifestSchemaValidator: ReturnType<Ajv2020["compile"]> | undefined;

function manifestSchemaValidate(): ReturnType<Ajv2020["compile"]> {
  if (!manifestSchemaValidator) {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(
      readFileSync(join(AGENT_RECEIPT_DIR, "pdf-export-manifest-schema.json"), "utf8"),
    );
    manifestSchemaValidator = ajv.compile(schema);
  }
  return manifestSchemaValidator;
}

function rejectForbiddenPDFExportManifestFields(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      rejectForbiddenPDFExportManifestFields(item);
    }
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  const record = value as Record<string, unknown>;
  for (const [key, child] of Object.entries(record)) {
    if ((FORBIDDEN_PDF_EXPORT_MANIFEST_FIELDS as readonly string[]).includes(key)) {
      throw new Error(`agent receipt pdf export manifest: forbidden field ${JSON.stringify(key)}`);
    }
    rejectForbiddenPDFExportManifestFields(child);
  }
}

/** Reject authority-embedding fields and validate against the published Draft 2020-12 schema. */
export function validateAgentReceiptPDFExportManifestJSON(
  value: unknown,
): AgentReceiptPDFExportManifest {
  rejectForbiddenPDFExportManifestFields(value);
  const validate = manifestSchemaValidate();
  if (!validate(value)) {
    throw new Error(
      `agent receipt pdf export manifest: schema validation failed: ${JSON.stringify(validate.errors ?? [])}`,
    );
  }
  return value as AgentReceiptPDFExportManifest;
}

export function parseAgentReceiptPDFExportManifestJSON(
  raw: string | Uint8Array,
): AgentReceiptPDFExportManifest {
  const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("agent receipt pdf export manifest: invalid JSON");
  }
  return validateAgentReceiptPDFExportManifestJSON(parsed);
}

export type GateAgentReceiptPDFExportInput = {
  receiptJSON: string | Uint8Array;
  manifestJSON: string | Uint8Array;
  pdfBytes?: Uint8Array;
  verifyOptions?: VerifyAgentReceiptV1Options;
};

function assertManifestMatchesReceipt(
  manifest: AgentReceiptPDFExportManifest,
  receipt: AgentReceiptV1,
): void {
  const receiptId = receipt.receipt_id.trim().toLowerCase();
  const digest = receipt.message_digest_sha256_hex.trim().toLowerCase();

  if (manifest.receipt_id.trim().toLowerCase() !== receiptId) {
    throw new Error(
      "agent receipt pdf export gate: manifest receipt_id does not match verified receipt",
    );
  }
  if (manifest.message_digest_sha256_hex.trim().toLowerCase() !== digest) {
    throw new Error(
      "agent receipt pdf export gate: manifest message_digest_sha256_hex does not match verified receipt",
    );
  }
  if (manifest.derived_view_label !== AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL) {
    throw new Error(
      `agent receipt pdf export gate: derived_view_label must be ${JSON.stringify(AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL)}`,
    );
  }

  const stamp = manifest.footer_stamp;
  if (stamp.receipt_id.trim().toLowerCase() !== receiptId) {
    throw new Error(
      "agent receipt pdf export gate: footer_stamp receipt_id does not match verified receipt",
    );
  }
  if (stamp.message_digest_sha256_hex.trim().toLowerCase() !== digest) {
    throw new Error(
      "agent receipt pdf export gate: footer_stamp message_digest_sha256_hex does not match verified receipt",
    );
  }
  if (stamp.label !== AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL) {
    throw new Error(
      `agent receipt pdf export gate: footer_stamp label must be ${JSON.stringify(AGENT_RECEIPT_PDF_EXPORT_DERIVED_VIEW_LABEL)}`,
    );
  }
}

/**
 * Enforces the PDF export verification gate before rendering or accepting a derived PDF.
 * Verify signed JSON first, bind manifest/footer stamps, optionally verify PDF bytes hash.
 */
export async function gateAgentReceiptPDFExport(
  input: GateAgentReceiptPDFExportInput,
): Promise<{ receipt: AgentReceiptV1; manifest: AgentReceiptPDFExportManifest }> {
  const receipt = await verifyAgentReceiptV1FromJSON(input.receiptJSON, input.verifyOptions);
  const manifest = parseAgentReceiptPDFExportManifestJSON(input.manifestJSON);
  assertManifestMatchesReceipt(manifest, receipt);

  if (input.pdfBytes && manifest.pdf_sha256_hex) {
    const actual = createHash("sha256").update(input.pdfBytes).digest("hex");
    if (actual !== manifest.pdf_sha256_hex.trim().toLowerCase()) {
      throw new Error("agent receipt pdf export gate: pdf_sha256_hex mismatch");
    }
  }

  return { receipt, manifest };
}
