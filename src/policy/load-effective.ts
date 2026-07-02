import type { PaybondPolicyDocumentV2 } from "./schema.js";
import type { PolicyMergeReport } from "./merge.js";

export type PolicyEffectiveResolveResult = {
  effective_policy: Record<string, unknown>;
  effective_policy_digest: string;
  effective_policy_version: string;
  merge_report: PolicyMergeReport;
  org_base_version_seq: number;
  org_base_content_digest: string;
  unchanged?: boolean;
};

/** Gateway client surface used by {@link resolvePolicyEffectiveRemote}. */
export type PolicyEffectiveResolveClient = {
  resolvePolicyEffective(
    orgPolicyId: string,
    overlay: Record<string, unknown>,
    options?: { currentDigest?: string },
  ): Promise<PolicyEffectiveResolveResult>;
};

export function parseMergeReport(value: unknown): PolicyMergeReport {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("merge_report must be an object");
  }
  const row = value as Record<string, unknown>;
  return {
    org_policy_id: row.org_policy_id == null ? null : String(row.org_policy_id),
    org_id: row.org_id == null ? null : String(row.org_id),
    base_policy_name: String(row.base_policy_name ?? ""),
    overlay_policy_name:
      row.overlay_policy_name == null ? null : String(row.overlay_policy_name),
    overrides_applied: Array.isArray(row.overrides_applied)
      ? row.overrides_applied.map((item) => String(item))
      : [],
    denied_widenings: Array.isArray(row.denied_widenings)
      ? row.denied_widenings
          .map((item) => {
            if (!item || typeof item !== "object" || Array.isArray(item)) {
              return null;
            }
            const denied = item as Record<string, unknown>;
            const path = String(denied.path ?? "");
            const code = String(denied.code ?? "");
            const message = String(denied.message ?? "");
            if (!path || !code || !message) {
              return null;
            }
            return { path, code, message };
          })
          .filter((item): item is PolicyMergeReport["denied_widenings"][number] => item !== null)
      : [],
  };
}

/** Parse a Gateway org-policy effective resolution JSON body. */
export function parsePolicyEffectiveResolveResponse(body: unknown): PolicyEffectiveResolveResult {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("policy effective response must be a JSON object");
  }
  const row = body as Record<string, unknown>;
  const digest = String(row.effective_policy_digest ?? "");
  if (!digest) {
    throw new Error("effective_policy_digest is required");
  }
  const version = String(row.effective_policy_version ?? "");
  if (!version) {
    throw new Error("effective_policy_version is required");
  }
  if (row.unchanged === true) {
    return {
      effective_policy: {},
      effective_policy_digest: digest,
      effective_policy_version: version,
      merge_report: parseMergeReport(row.merge_report ?? {}),
      org_base_version_seq: Number(row.org_base_version_seq ?? 0),
      org_base_content_digest: String(row.org_base_content_digest ?? ""),
      unchanged: true,
    };
  }
  const effective = row.effective_policy;
  if (!effective || typeof effective !== "object" || Array.isArray(effective)) {
    throw new Error("effective_policy must be an object");
  }
  return {
    effective_policy: effective as Record<string, unknown>,
    effective_policy_digest: digest,
    effective_policy_version: version,
    merge_report: parseMergeReport(row.merge_report),
    org_base_version_seq: Number(row.org_base_version_seq ?? 0),
    org_base_content_digest: String(row.org_base_content_digest ?? ""),
  };
}

/** Resolve merged effective policy via Gateway org-policy inheritance endpoint. */
export async function resolvePolicyEffectiveRemote(
  overlay: PaybondPolicyDocumentV2,
  client: PolicyEffectiveResolveClient,
): Promise<PolicyEffectiveResolveResult> {
  if (!overlay.extends?.org_policy_id) {
    throw new Error("overlay must declare extends.org_policy_id");
  }
  return client.resolvePolicyEffective(overlay.extends.org_policy_id, overlay as unknown as Record<string, unknown>);
}
