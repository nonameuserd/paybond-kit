import {
  getCompletionPreset,
  listCompletionPresetIds,
  type CompletionPreset,
} from "../completion-catalog.js";
import { isVendorPack } from "../completion-resolve.js";
import type { PaybondPolicyLoadSource } from "./load.js";
import { PaybondPolicy } from "./load.js";
import {
  PaybondPolicyValidationError,
  type PaybondPolicyDocumentV1,
  type PaybondPolicyValidationIssue,
} from "./schema.js";

export type PolicyValidatorError = {
  path: string;
  code: string;
  message: string;
};

export type PolicyValidatorToolCounts = {
  side_effecting: number;
  read_only: number;
};

export type PolicyValidatorResult = {
  valid: boolean;
  policy_name: string | null;
  tools: PolicyValidatorToolCounts;
  errors: PolicyValidatorError[];
};

export type PolicyGatewayTemplateLookup = {
  listTemplateIds(): Promise<string[]>;
};

export type PolicyValidatorOptions = {
  /** When true, side-effecting tools must appear in intent.allowed_tools when that list is set. */
  strict?: boolean;
  /** Verify intent.policy_binding.template_id against the Harbor template catalog. */
  checkGateway?: boolean;
  gateway?: PolicyGatewayTemplateLookup;
};

function issueToError(issue: PaybondPolicyValidationIssue): PolicyValidatorError {
  return {
    path: issue.path,
    code: issue.code,
    message: issue.message,
  };
}

function pushError(
  errors: PolicyValidatorError[],
  path: string,
  code: string,
  message: string,
): void {
  errors.push({ path, code, message });
}

function countTools(document: PaybondPolicyDocumentV1): PolicyValidatorToolCounts {
  let sideEffecting = 0;
  let readOnly = 0;
  for (const entry of Object.values(document.tools)) {
    if (entry.side_effecting) {
      sideEffecting += 1;
    } else {
      readOnly += 1;
    }
  }
  return { side_effecting: sideEffecting, read_only: readOnly };
}

function catalogHasPreset(presetId: string): boolean {
  return listCompletionPresetIds().includes(presetId);
}

function validatePresetReference(
  errors: PolicyValidatorError[],
  toolName: string,
  presetId: string,
): void {
  if (!catalogHasPreset(presetId)) {
    pushError(
      errors,
      `tools.${toolName}.evidence_preset`,
      "policy.unknown_evidence_preset",
      `unknown completion preset: ${presetId}`,
    );
    return;
  }
  try {
    getCompletionPreset(presetId);
  } catch {
    pushError(
      errors,
      `tools.${toolName}.evidence_preset`,
      "policy.unknown_evidence_preset",
      `unknown completion preset: ${presetId}`,
    );
  }
}

function validateVendorPackReference(
  errors: PolicyValidatorError[],
  toolName: string,
  vendorPackId: string,
): void {
  let preset: CompletionPreset;
  try {
    preset = getCompletionPreset(vendorPackId);
  } catch {
    pushError(
      errors,
      `tools.${toolName}.vendor_pack`,
      "policy.unknown_vendor_pack",
      `unknown vendor pack preset: ${vendorPackId}`,
    );
    return;
  }
  if (!isVendorPack(preset)) {
    pushError(
      errors,
      `tools.${toolName}.vendor_pack`,
      "policy.invalid_vendor_pack",
      `preset ${vendorPackId} is not a vendor_pack entry`,
    );
  }
}

function validateIntentAlignment(
  document: PaybondPolicyDocumentV1,
  errors: PolicyValidatorError[],
  strict: boolean,
): void {
  const allowedTools = document.intent?.allowed_tools;
  if (!allowedTools || allowedTools.length === 0) {
    return;
  }

  const registered = new Set(Object.keys(document.tools));
  for (const toolName of allowedTools) {
    if (!registered.has(toolName)) {
      pushError(
        errors,
        `intent.allowed_tools`,
        "policy.allowed_tool_not_registered",
        `allowed tool "${toolName}" is not declared in tools`,
      );
    }
  }

  if (!strict || !document.default_deny) {
    return;
  }

  const allowed = new Set(allowedTools);
  for (const [toolName, entry] of Object.entries(document.tools)) {
    if (entry.side_effecting && !allowed.has(toolName)) {
      pushError(
        errors,
        `tools.${toolName}`,
        "policy.side_effecting_not_allowed",
        `side-effecting tool "${toolName}" is missing from intent.allowed_tools (default_deny is true)`,
      );
    }
  }
}

function validateToolEntries(document: PaybondPolicyDocumentV1, errors: PolicyValidatorError[]): void {
  for (const [toolName, entry] of Object.entries(document.tools)) {
    if (entry.side_effecting) {
      if (!entry.evidence_preset) {
        pushError(
          errors,
          `tools.${toolName}.evidence_preset`,
          "policy.missing_evidence_preset",
          "side-effecting tools must declare evidence_preset",
        );
      } else {
        validatePresetReference(errors, toolName, entry.evidence_preset);
      }
    } else if (entry.evidence_preset) {
      validatePresetReference(errors, toolName, entry.evidence_preset);
    }

    if (entry.vendor_pack) {
      validateVendorPackReference(errors, toolName, entry.vendor_pack);
    }
  }
}

async function validateGatewayTemplate(
  document: PaybondPolicyDocumentV1,
  errors: PolicyValidatorError[],
  gateway: PolicyGatewayTemplateLookup,
): Promise<void> {
  const templateId = document.intent?.policy_binding?.template_id;
  if (!templateId) {
    return;
  }
  const templateIds = await gateway.listTemplateIds();
  if (!templateIds.includes(templateId)) {
    pushError(
      errors,
      "intent.policy_binding.template_id",
      "policy.unknown_policy_template",
      `policy template "${templateId}" was not found in the Harbor catalog`,
    );
  }
}

function validateDocumentSync(
  document: PaybondPolicyDocumentV1,
  options: PolicyValidatorOptions = {},
): PolicyValidatorResult {
  const strict = options.strict ?? PolicyValidator.isStrictFromEnv();
  const errors: PolicyValidatorError[] = [];

  validateToolEntries(document, errors);
  validateIntentAlignment(document, errors, strict);

  return {
    valid: errors.length === 0,
    policy_name: document.name,
    tools: countTools(document),
    errors,
  };
}

/** Client-side policy alignment checks before deploy or agent bind. */
export class PolicyValidator {
  /** True when `PAYBOND_POLICY_STRICT=1`. */
  static isStrictFromEnv(): boolean {
    return process.env.PAYBOND_POLICY_STRICT === "1";
  }

  /** Validate a loaded or raw policy source. */
  static async validate(
    source: PaybondPolicyLoadSource,
    options: PolicyValidatorOptions = {},
  ): Promise<PolicyValidatorResult> {
    try {
      const policy = await PaybondPolicy.load(source);
      return PolicyValidator.validateDocument(policy.document, options);
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        return {
          valid: false,
          policy_name: null,
          tools: { side_effecting: 0, read_only: 0 },
          errors: err.issues.map(issueToError),
        };
      }
      throw err;
    }
  }

  /** Validate an already-parsed policy document (and optional gateway checks). */
  static async validateDocument(
    document: PaybondPolicyDocumentV1,
    options: PolicyValidatorOptions = {},
  ): Promise<PolicyValidatorResult> {
    const result = validateDocumentSync(document, options);

    if (options.checkGateway && options.gateway) {
      await validateGatewayTemplate(document, result.errors, options.gateway);
      result.valid = result.errors.length === 0;
    }

    return result;
  }
}
