import {
  type CompletionEvidenceValidationReport,
  validateCompletionEvidence,
} from "./completion-validate-evidence.js";
import { jsonValueDigest } from "./json-digest.js";

export type McpEvidencePolicy = "strict" | "off";

export const MCP_EVIDENCE_POLICY_ENV = "PAYBOND_MCP_EVIDENCE_POLICY";
export const DEFAULT_MCP_EVIDENCE_POLICY: McpEvidencePolicy = "strict";

export const EVIDENCE_SUBMIT_TOOL_NAMES = new Set([
  "paybond_submit_evidence",
  "paybond_submit_spend_evidence",
  "paybond_submit_sandbox_guardrail_evidence",
]);

export class McpEvidencePolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpEvidencePolicyError";
  }
}

export function parseMcpEvidencePolicy(raw: string | undefined): McpEvidencePolicy {
  const value = (raw ?? "").trim().toLowerCase();
  if (!value) {
    return DEFAULT_MCP_EVIDENCE_POLICY;
  }
  if (value === "strict" || value === "off") {
    return value;
  }
  throw new Error("invalid PAYBOND_MCP_EVIDENCE_POLICY (expected strict|off)");
}

export function completionEvidenceValidationOk(report: CompletionEvidenceValidationReport): boolean {
  return report.drift_kinds.length === 0;
}

export function evidenceValidationGateKey(input: {
  presetId: string;
  vendorPayload?: Record<string, unknown>;
  canonicalPayload?: Record<string, unknown>;
}): string {
  const presetId = input.presetId.trim();
  if (!presetId) {
    throw new Error("completion preset id is required for evidence validation");
  }
  const digest = jsonValueDigest({
    preset_id: presetId,
    vendor_payload: input.vendorPayload,
    canonical_payload: input.canonicalPayload,
  });
  return Buffer.from(digest).toString("hex");
}

export function extractHarborEvidenceValidationInput(
  body: Record<string, unknown>,
  completionPresetId?: string,
): {
  presetId: string;
  vendorPayload?: Record<string, unknown>;
  canonicalPayload?: Record<string, unknown>;
} {
  let presetId = (completionPresetId ?? "").trim();
  if (!presetId) {
    for (const key of ["completion_preset_id", "completion_preset"] as const) {
      const raw = body[key];
      if (typeof raw === "string" && raw.trim()) {
        presetId = raw.trim();
        break;
      }
    }
  }
  const vendorRaw = body.vendor_payload;
  const vendorPayload =
    vendorRaw !== undefined && typeof vendorRaw === "object" && vendorRaw !== null && !Array.isArray(vendorRaw)
      ? (vendorRaw as Record<string, unknown>)
      : undefined;
  const payloadRaw = body.payload;
  const canonicalPayload =
    payloadRaw !== undefined && typeof payloadRaw === "object" && payloadRaw !== null && !Array.isArray(payloadRaw)
      ? (payloadRaw as Record<string, unknown>)
      : undefined;
  return { presetId, vendorPayload, canonicalPayload };
}

export function extractSandboxGuardrailValidationInput(input: {
  payload?: Record<string, unknown>;
  completionPresetId?: string;
}): {
  presetId: string;
  vendorPayload?: Record<string, unknown>;
  canonicalPayload?: Record<string, unknown>;
} {
  const presetId = (input.completionPresetId ?? "").trim();
  return {
    presetId,
    vendorPayload: input.payload,
    canonicalPayload: input.payload,
  };
}

export class McpEvidenceValidationGate {
  private readonly passes = new Set<string>();

  constructor(readonly policy: McpEvidencePolicy = DEFAULT_MCP_EVIDENCE_POLICY) {}

  recordPass(gateKey: string): void {
    this.passes.add(gateKey);
  }

  hasPass(gateKey: string): boolean {
    return this.passes.has(gateKey);
  }

  requirePass(input: {
    presetId: string;
    vendorPayload?: Record<string, unknown>;
    canonicalPayload?: Record<string, unknown>;
  }): void {
    if (this.policy === "off") {
      return;
    }
    const presetId = input.presetId.trim();
    if (!presetId) {
      return;
    }
    const gateKey = evidenceValidationGateKey({
      presetId,
      vendorPayload: input.vendorPayload,
      canonicalPayload: input.canonicalPayload,
    });
    if (!this.hasPass(gateKey)) {
      throw new McpEvidencePolicyError(
        "completion evidence was not pre-validated; call paybond_validate_completion_evidence with the same preset and payload before submit (Harbor remains authoritative at submit time)",
      );
    }
  }

  validateAndRecord(input: {
    presetId: string;
    vendorPayload?: Record<string, unknown>;
    canonicalPayload?: Record<string, unknown>;
    frozenVendorApiVersion?: string;
    frozenVendorSchemaDigestHex?: string;
    frozenCanonicalSchemaDigestHex?: string;
  }): CompletionEvidenceValidationReport {
    const report = validateCompletionEvidence({
      presetId: input.presetId,
      vendorPayload: input.vendorPayload,
      canonicalPayload: input.canonicalPayload,
      frozenVendorApiVersion: input.frozenVendorApiVersion,
      frozenVendorSchemaDigestHex: input.frozenVendorSchemaDigestHex,
      frozenCanonicalSchemaDigestHex: input.frozenCanonicalSchemaDigestHex,
    });
    if (completionEvidenceValidationOk(report)) {
      this.recordPass(
        evidenceValidationGateKey({
          presetId: input.presetId,
          vendorPayload: input.vendorPayload,
          canonicalPayload: input.canonicalPayload,
        }),
      );
    }
    return report;
  }
}
