import {
  PaybondPolicyValidationError,
  PAYBOND_POLICY_SCHEMA_VERSION,
  type PaybondPolicyBinding,
  type PaybondPolicyBindingOverride,
  type PaybondPolicyDocument,
  type PaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV2,
  type PaybondPolicyIntentSection,
  type PaybondPolicyToolEntry,
  type PaybondPolicyToolOverrideEntry,
  isPaybondPolicyDocumentV1,
  isPaybondPolicyDocumentV2,
  isPaybondPolicyOverlay,
} from "./schema.js";

export type PolicyMergeDeniedWidening = {
  path: string;
  code: string;
  message: string;
};

export type PolicyMergeReport = {
  org_policy_id: string | null;
  org_id: string | null;
  base_policy_name: string;
  overlay_policy_name: string | null;
  overrides_applied: string[];
  denied_widenings: PolicyMergeDeniedWidening[];
};

export type PolicyMergeResult = {
  effective: PaybondPolicyDocumentV1;
  report: PolicyMergeReport;
};

export type PolicyMergeOptions = {
  /** When set, tenant evidence_preset swaps must stay within this catalog subset. */
  approvedEvidencePresets?: readonly string[];
};

function cloneToolEntry(entry: PaybondPolicyToolEntry): PaybondPolicyToolEntry {
  return { ...entry };
}

function mergeStricterDefaultDeny(...values: Array<boolean | undefined>): boolean {
  return values.some((value) => value === true);
}

function mergeToolFields(
  base: PaybondPolicyToolEntry,
  patch: PaybondPolicyToolOverrideEntry,
  toolName: string,
  report: PolicyMergeReport,
  denied: PolicyMergeDeniedWidening[],
): PaybondPolicyToolEntry {
  const merged = cloneToolEntry(base);

  if (patch.side_effecting !== undefined) {
    if (base.side_effecting && patch.side_effecting === false) {
      denied.push({
        path: `tools.${toolName}.side_effecting`,
        code: "policy.cannot_disable_org_side_effecting_tool",
        message: `cannot disable org-required side-effecting tool "${toolName}"`,
      });
    } else {
      merged.side_effecting = patch.side_effecting;
      report.overrides_applied.push(`tools.${toolName}.side_effecting`);
    }
  }

  if (patch.max_spend_cents !== undefined) {
    if (
      base.max_spend_cents !== undefined &&
      patch.max_spend_cents > base.max_spend_cents
    ) {
      denied.push({
        path: `tools.${toolName}.max_spend_cents`,
        code: "policy.cannot_raise_spend_cap",
        message: `tenant max_spend_cents (${patch.max_spend_cents}) exceeds org cap (${base.max_spend_cents})`,
      });
    } else {
      merged.max_spend_cents = patch.max_spend_cents;
      report.overrides_applied.push(`tools.${toolName}.max_spend_cents`);
    }
  }

  if (patch.spend_from_args !== undefined) {
    if (base.max_spend_cents !== undefined) {
      denied.push({
        path: `tools.${toolName}.spend_from_args`,
        code: "policy.cannot_override_org_spend_mode",
        message: `cannot replace org max_spend_cents with spend_from_args on "${toolName}"`,
      });
    } else {
      merged.spend_from_args = patch.spend_from_args;
      delete merged.max_spend_cents;
      report.overrides_applied.push(`tools.${toolName}.spend_from_args`);
    }
  }

  if (patch.evidence_preset !== undefined) {
    if (
      patch.evidence_preset !== base.evidence_preset &&
      report.org_policy_id !== null
    ) {
      // Structural check only; catalog membership is validated downstream.
      report.overrides_applied.push(`tools.${toolName}.evidence_preset`);
    }
    merged.evidence_preset = patch.evidence_preset;
  }

  if (patch.vendor_pack !== undefined) {
    merged.vendor_pack = patch.vendor_pack;
    report.overrides_applied.push(`tools.${toolName}.vendor_pack`);
  }

  if (patch.operation !== undefined) {
    merged.operation = patch.operation;
    report.overrides_applied.push(`tools.${toolName}.operation`);
  }

  if (merged.side_effecting && !merged.evidence_preset) {
    denied.push({
      path: `tools.${toolName}.evidence_preset`,
      code: "policy.missing_evidence_preset",
      message: `side-effecting tool "${toolName}" must declare evidence_preset after merge`,
    });
  }

  if (
    merged.max_spend_cents !== undefined &&
    merged.spend_from_args !== undefined
  ) {
    denied.push({
      path: `tools.${toolName}`,
      code: "policy.conflicting_spend_fields",
      message: "max_spend_cents and spend_from_args are mutually exclusive",
    });
  }

  return merged;
}

function mergePolicyBinding(
  base: PaybondPolicyBinding | undefined,
  overlay: PaybondPolicyBinding | undefined,
  override: PaybondPolicyBindingOverride | undefined,
  denied: PolicyMergeDeniedWidening[],
  report: PolicyMergeReport,
): PaybondPolicyBinding | undefined {
  if (!base && !overlay && !override) {
    return undefined;
  }

  const templateId = override?.template_id ?? overlay?.template_id ?? base?.template_id;
  if (!templateId) {
    return undefined;
  }

  const merged: PaybondPolicyBinding = { template_id: templateId };

  const overlayTemplate = overlay?.template_id ?? override?.template_id;
  if (base?.template_id && overlayTemplate && overlayTemplate !== base.template_id) {
    denied.push({
      path: "intent.policy_binding.template_id",
      code: "policy.cannot_change_org_template",
      message: `tenant template_id "${overlayTemplate}" must match org template "${base.template_id}"`,
    });
  }

  const versionSeq = override?.version_seq ?? overlay?.version_seq ?? base?.version_seq;
  if (versionSeq !== undefined) {
    if (base?.version_seq !== undefined && versionSeq < base.version_seq) {
      denied.push({
        path: "intent.policy_binding.version_seq",
        code: "policy.cannot_downgrade_template_version",
        message: `tenant version_seq (${versionSeq}) is older than org version_seq (${base.version_seq})`,
      });
    } else {
      merged.version_seq = versionSeq;
      if (override?.version_seq !== undefined) {
        report.overrides_applied.push("intent.policy_binding.version_seq");
      }
    }
  }

  const headDigest = override?.head_digest ?? overlay?.head_digest ?? base?.head_digest;
  if (headDigest !== undefined) {
    if (base?.head_digest && headDigest !== base.head_digest) {
      denied.push({
        path: "intent.policy_binding.head_digest",
        code: "policy.cannot_change_org_head_digest",
        message: "tenant head_digest must match the org-pinned template head",
      });
    } else {
      merged.head_digest = headDigest;
      if (override?.head_digest !== undefined) {
        report.overrides_applied.push("intent.policy_binding.head_digest");
      }
    }
  }

  return merged;
}

function mergeBudget(
  base: PaybondPolicyIntentSection["budget"] | undefined,
  overlay: PaybondPolicyIntentSection["budget"] | undefined,
  override: PaybondPolicyIntentSection["budget"] | undefined,
  denied: PolicyMergeDeniedWidening[],
  report: PolicyMergeReport,
): PaybondPolicyIntentSection["budget"] | undefined {
  const merged = {
    ...(base ?? {}),
    ...(overlay ?? {}),
    ...(override ?? {}),
  } as PaybondPolicyIntentSection["budget"];

  if (!merged || Object.keys(merged).length === 0) {
    return undefined;
  }

  const orgMax = base?.max_spend_usd;
  const tenantMax = override?.max_spend_usd ?? overlay?.max_spend_usd;
  if (orgMax !== undefined && tenantMax !== undefined && tenantMax > orgMax) {
    denied.push({
      path: "intent.budget.max_spend_usd",
      code: "policy.cannot_raise_budget_cap",
      message: `tenant max_spend_usd (${tenantMax}) exceeds org cap (${orgMax})`,
    });
  } else if (override?.max_spend_usd !== undefined) {
    report.overrides_applied.push("intent.budget.max_spend_usd");
  }

  return merged;
}

function intersectAllowedTools(
  orgAllowed: string[] | undefined,
  tenantAllowed: string[] | undefined,
  denied: PolicyMergeDeniedWidening[],
  report: PolicyMergeReport,
): string[] | undefined {
  if (!tenantAllowed || tenantAllowed.length === 0) {
    return orgAllowed;
  }

  if (!orgAllowed || orgAllowed.length === 0) {
    return tenantAllowed;
  }

  const orgSet = new Set(orgAllowed);
  const widened = tenantAllowed.filter((tool) => !orgSet.has(tool));
  if (widened.length > 0) {
    denied.push({
      path: "intent.allowed_tools",
      code: "policy.cannot_widen_allowed_tools",
      message: `tenant allowed_tools widens org allowlist: ${widened.join(", ")}`,
    });
  }

  const intersection = tenantAllowed.filter((tool) => orgSet.has(tool));
  if (intersection.length !== tenantAllowed.length) {
    report.overrides_applied.push("intent.allowed_tools");
  }
  return intersection;
}

function baseDocumentToEffectiveV1(
  document: PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2,
): PaybondPolicyDocumentV1 {
  return {
    version: PAYBOND_POLICY_SCHEMA_VERSION,
    name: document.name,
    default_deny: document.default_deny,
    tools: Object.fromEntries(
      Object.entries(document.tools).map(([toolName, entry]) => [toolName, cloneToolEntry(entry)]),
    ),
    intent: document.intent ? structuredClone(document.intent) : undefined,
  };
}

function assertOverlay(document: PaybondPolicyDocumentV2): void {
  if (!isPaybondPolicyOverlay(document)) {
    throw new PaybondPolicyValidationError(
      "merge requires a tenant overlay document with extends",
      [{ path: "extends", code: "required", message: "extends is required for overlay merge" }],
    );
  }
}

/**
 * Deterministically merge an org base policy with a tenant overlay.
 * Returns a v1 effective document suitable for middleware and validation.
 */
export function mergePaybondPolicies(
  base: PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2,
  overlay: PaybondPolicyDocumentV2,
  options: PolicyMergeOptions = {},
): PolicyMergeResult {
  assertOverlay(overlay);

  const denied: PolicyMergeDeniedWidening[] = [];
  const report: PolicyMergeReport = {
    org_policy_id: overlay.extends!.org_policy_id,
    org_id: overlay.extends!.org_id,
    base_policy_name: base.name,
    overlay_policy_name: overlay.name,
    overrides_applied: [],
    denied_widenings: [],
  };

  const effective = baseDocumentToEffectiveV1(base);
  effective.name = overlay.name;
  effective.default_deny = mergeStricterDefaultDeny(
    base.default_deny,
    overlay.default_deny,
    overlay.overrides?.default_deny,
  );
  if (overlay.overrides?.default_deny !== undefined) {
    report.overrides_applied.push("overrides.default_deny");
  }

  for (const [toolName, patch] of Object.entries(overlay.overrides?.tools ?? {})) {
    const existing = effective.tools[toolName];
    if (!existing) {
      denied.push({
        path: `overrides.tools.${toolName}`,
        code: "policy.unknown_org_tool_override",
        message: `cannot override unknown org tool "${toolName}"`,
      });
      continue;
    }
    effective.tools[toolName] = mergeToolFields(existing, patch, toolName, report, denied);
  }

  for (const [toolName, entry] of Object.entries(overlay.tools)) {
    if (effective.tools[toolName]) {
      denied.push({
        path: `tools.${toolName}`,
        code: "policy.cannot_replace_org_tool",
        message: `tenant tools must append new entries; "${toolName}" already exists in org base`,
      });
      continue;
    }
    effective.tools[toolName] = cloneToolEntry(entry);
  }

  const orgAllowed = base.intent?.allowed_tools;
  const tenantAllowed =
    overlay.overrides?.intent?.allowed_tools ?? overlay.intent?.allowed_tools;
  const mergedAllowed = intersectAllowedTools(orgAllowed, tenantAllowed, denied, report);

  if (!overlay.intent && !overlay.overrides?.intent) {
    effective.intent = base.intent ? structuredClone(base.intent) : undefined;
    if (mergedAllowed && effective.intent) {
      effective.intent.allowed_tools = mergedAllowed;
    }
  } else {
    const mergedBinding = mergePolicyBinding(
      base.intent?.policy_binding,
      overlay.intent?.policy_binding,
      overlay.overrides?.intent?.policy_binding,
      denied,
      report,
    );

    const mergedBudget = mergeBudget(
      base.intent?.budget,
      overlay.intent?.budget,
      overlay.overrides?.intent?.budget,
      denied,
      report,
    );

    if (mergedBinding || mergedBudget || mergedAllowed) {
      effective.intent = {
        ...(mergedBinding ? { policy_binding: mergedBinding } : {}),
        ...(mergedBudget ? { budget: mergedBudget } : {}),
        ...(mergedAllowed ? { allowed_tools: mergedAllowed } : {}),
      };
    } else if (base.intent) {
      effective.intent = structuredClone(base.intent);
    }
  }

  if (options.approvedEvidencePresets) {
    const approved = new Set(options.approvedEvidencePresets);
    for (const [toolName, entry] of Object.entries(effective.tools)) {
      if (!entry.side_effecting || !entry.evidence_preset) {
        continue;
      }
      const basePreset = base.tools[toolName]?.evidence_preset;
      if (basePreset && entry.evidence_preset !== basePreset && !approved.has(entry.evidence_preset)) {
        denied.push({
          path: `tools.${toolName}.evidence_preset`,
          code: "policy.evidence_preset_not_org_approved",
          message: `evidence preset "${entry.evidence_preset}" is not in the org-approved catalog subset`,
        });
      }
    }
  }

  report.denied_widenings = denied;
  if (denied.length > 0) {
    const summary = denied.map((item) => `${item.path}: ${item.message}`).join("; ");
    throw new PaybondPolicyValidationError(summary, denied.map((item) => ({
      path: item.path,
      code: item.code,
      message: item.message,
    })));
  }

  return { effective, report };
}

/** Normalize any supported policy document to a flat v1 effective document. */
export function toEffectivePolicyDocument(
  document: PaybondPolicyDocument,
): PaybondPolicyDocumentV1 {
  if (isPaybondPolicyDocumentV1(document)) {
    return baseDocumentToEffectiveV1(document);
  }
  if (isPaybondPolicyOverlay(document)) {
    throw new PaybondPolicyValidationError(
      "tenant overlay requires merge with an org base policy before use",
      [{ path: "extends", code: "merge_required", message: "resolve inheritance before producing effective policy" }],
    );
  }
  return baseDocumentToEffectiveV1(document);
}
