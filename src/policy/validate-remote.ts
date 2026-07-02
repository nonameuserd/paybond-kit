import { policyDocumentToDict } from "./digest.js";
import type { PolicyMergeReport } from "./merge.js";
import { parseMergeReport } from "./load-effective.js";
import type { PaybondPolicyDocumentV1 } from "./schema.js";

export type PolicyRemoteValidateIssue = {
  path: string;
  code: string;
  message: string;
};

export type PolicyRemoteValidateCheck = {
  name: string;
  passed: boolean;
};

export type PolicyRemoteValidateResult = {
  valid: boolean;
  local_valid: boolean;
  remote_valid: boolean;
  policy_name: string | null;
  tenant_id: string;
  errors: PolicyRemoteValidateIssue[];
  warnings: PolicyRemoteValidateIssue[];
  checks: PolicyRemoteValidateCheck[];
  effective_policy_digest?: string;
  merge_report?: PolicyMergeReport;
};

export type PolicyRemoteValidateOptions = {
  /** When true, side-effecting tools must appear in intent.allowed_tools when that list is set. */
  strict?: boolean;
  /** When true, treat the body as a v2 tenant overlay and merge org base server-side. */
  resolveInheritance?: boolean;
};

/** Gateway client surface used by {@link validatePolicyRemote}. */
export type PolicyRemoteValidateClient = {
  validatePolicy(
    document: Record<string, unknown>,
    options?: PolicyRemoteValidateOptions,
  ): Promise<PolicyRemoteValidateResult>;
};

function parseIssue(value: unknown): PolicyRemoteValidateIssue | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const row = value as Record<string, unknown>;
  const path = String(row.path ?? "");
  const code = String(row.code ?? "");
  const message = String(row.message ?? "");
  if (!path || !code || !message) {
    return null;
  }
  return { path, code, message };
}

function parseCheck(value: unknown): PolicyRemoteValidateCheck | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const row = value as Record<string, unknown>;
  const name = String(row.name ?? "");
  if (!name || typeof row.passed !== "boolean") {
    return null;
  }
  return { name, passed: row.passed };
}

/** Build query parameters for Gateway `POST /v1/policy/validate`. */
export function policyValidateQueryString(options: PolicyRemoteValidateOptions = {}): string {
  const params = new URLSearchParams();
  if (options.strict) {
    params.set("strict", "1");
  }
  if (options.resolveInheritance) {
    params.set("resolve_inheritance", "1");
  }
  const qs = params.toString();
  return qs ? `?${qs}` : "";
}

/** Parse a Gateway `POST /v1/policy/validate` JSON body. */
export function parsePolicyRemoteValidateResponse(body: unknown): PolicyRemoteValidateResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("policy validate response must be a JSON object");
  }
  const row = body as Record<string, unknown>;
  const errors = Array.isArray(row.errors)
    ? row.errors.map(parseIssue).filter((issue): issue is PolicyRemoteValidateIssue => issue !== null)
    : [];
  const warnings = Array.isArray(row.warnings)
    ? row.warnings.map(parseIssue).filter((issue): issue is PolicyRemoteValidateIssue => issue !== null)
    : [];
  const checks = Array.isArray(row.checks)
    ? row.checks.map(parseCheck).filter((check): check is PolicyRemoteValidateCheck => check !== null)
    : [];

  const result: PolicyRemoteValidateResult = {
    valid: Boolean(row.valid),
    local_valid: Boolean(row.local_valid),
    remote_valid: Boolean(row.remote_valid),
    policy_name:
      row.policy_name === null || row.policy_name === undefined
        ? null
        : String(row.policy_name),
    tenant_id: String(row.tenant_id ?? ""),
    errors,
    warnings,
    checks,
  };

  if (row.effective_policy_digest != null) {
    const digest = String(row.effective_policy_digest);
    if (digest) {
      result.effective_policy_digest = digest;
    }
  }
  if (row.merge_report != null) {
    result.merge_report = parseMergeReport(row.merge_report);
  }

  return result;
}

/** Serialize a remote validation report for CLI or logging output. */
export function policyRemoteValidateResultToDict(
  result: PolicyRemoteValidateResult,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    valid: result.valid,
    local_valid: result.local_valid,
    remote_valid: result.remote_valid,
    policy_name: result.policy_name,
    tenant_id: result.tenant_id,
    errors: result.errors,
    warnings: result.warnings,
    checks: result.checks,
  };
  if (result.effective_policy_digest) {
    payload.effective_policy_digest = result.effective_policy_digest;
  }
  if (result.merge_report) {
    payload.merge_report = result.merge_report;
  }
  return payload;
}

/** Validate a raw policy payload against the tenant-scoped Gateway registry endpoint. */
export async function validatePolicyPayloadRemote(
  document: Record<string, unknown>,
  client: PolicyRemoteValidateClient,
  options: PolicyRemoteValidateOptions = {},
): Promise<PolicyRemoteValidateResult> {
  return client.validatePolicy(document, options);
}

/** Validate a policy document against the tenant-scoped Gateway registry endpoint. */
export async function validatePolicyRemote(
  document: PaybondPolicyDocumentV1,
  client: PolicyRemoteValidateClient,
  options: PolicyRemoteValidateOptions = {},
): Promise<PolicyRemoteValidateResult> {
  return validatePolicyPayloadRemote(policyDocumentToDict(document), client, options);
}
