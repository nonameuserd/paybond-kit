import { access, writeFile } from "node:fs/promises";
import { constants } from "node:fs";

import { getCompletionPreset } from "../completion-catalog.js";
import { composePolicyLayers, type LayeredPolicyPresetId } from "./compose.js";
import { domain } from "./domain.js";
import { parseGuardrailSpecs } from "./guardrail-spec.js";
import { resolveComposedPresetDocument, type PolicyPresetId } from "./presets.js";
import { renderPolicyDocumentYaml } from "./render-yaml.js";
import { PaybondPolicyValidationError, type PaybondPolicyDocumentV1 } from "./schema.js";
import { parsePolicyDocumentText } from "./parse-text.js";

const ORG_ID_RE = /^org_[a-z][a-z0-9_]*$/;
const POLICY_NAME_RE = /^[a-z][a-z0-9-]*$/;

export type ScaffoldPaybondPolicyOptions = {
  out: string;
  operation: string;
  evidencePreset: string;
  force?: boolean;
};

export type ScaffoldPolicyFromPresetOptions = {
  out: string;
  presetId: PolicyPresetId;
  /** Intent budget and side-effecting tool cap override in USD. */
  maxSpendUsd?: number;
  force?: boolean;
};

export type ScaffoldComposedPolicyOptions = {
  out: string;
  domainId: LayeredPolicyPresetId;
  guardrails: string;
  force?: boolean;
};

function policyPresetScaffoldHeader(regenerateCommand: string): string {
  return `# Reference implementation — edit freely. Regenerate with:\n# ${regenerateCommand}\n\n`;
}

function applyMaxSpendUsdOverride(
  document: PaybondPolicyDocumentV1,
  maxSpendUsdValue: number,
): PaybondPolicyDocumentV1 {
  const cents = Math.round(maxSpendUsdValue * 100);
  const next: PaybondPolicyDocumentV1 = {
    ...document,
    tools: Object.fromEntries(
      Object.entries(document.tools).map(([toolName, entry]) => [
        toolName,
        entry.side_effecting ? { ...entry, max_spend_cents: cents } : { ...entry },
      ]),
    ),
    intent: document.intent
      ? {
          ...document.intent,
          budget: {
            ...document.intent.budget,
            currency: document.intent.budget?.currency ?? "usd",
            max_spend_usd: maxSpendUsdValue,
          },
        }
      : {
          budget: { currency: "usd", max_spend_usd: maxSpendUsdValue },
        },
  };
  return next;
}

function resolvePresetInitDocument(options: ScaffoldPolicyFromPresetOptions): PaybondPolicyDocumentV1 {
  const document = resolveComposedPresetDocument(options.presetId);
  if (options.maxSpendUsd === undefined) {
    return document;
  }
  return applyMaxSpendUsdOverride(document, options.maxSpendUsd);
}

function resolveComposedInitDocument(options: ScaffoldComposedPolicyOptions): PaybondPolicyDocumentV1 {
  const layers = parseGuardrailSpecs(options.guardrails);
  return composePolicyLayers(domain[options.domainId](), ...layers);
}

export type ScaffoldOrgBasePolicyOptions = {
  out: string;
  policyId: string;
  operation: string;
  evidencePreset: string;
  maxSpendCents?: number;
  force?: boolean;
};

export type ScaffoldTenantOverlayPolicyOptions = {
  out: string;
  extendsRef: string;
  name?: string;
  operation?: string;
  evidencePreset?: string;
  basePolicy?: string;
  force?: boolean;
};

/** Parse `org_id/org_policy_id` extends reference used by CLI and docs. */
export function parsePolicyExtendsRef(ref: string): { orgId: string; orgPolicyId: string } {
  const trimmed = ref.trim();
  const slash = trimmed.indexOf("/");
  if (slash <= 0 || slash === trimmed.length - 1) {
    throw new PaybondPolicyValidationError("extends must be org_id/org_policy_id (example: org_acme_corp/acme-agent-spend-v1)");
  }
  const orgId = trimmed.slice(0, slash);
  const orgPolicyId = trimmed.slice(slash + 1);
  if (!ORG_ID_RE.test(orgId)) {
    throw new PaybondPolicyValidationError(`org_id must match org_<snake_case>: ${orgId}`);
  }
  if (!POLICY_NAME_RE.test(orgPolicyId)) {
    throw new PaybondPolicyValidationError(`org_policy_id must be a lowercase policy name: ${orgPolicyId}`);
  }
  return { orgId, orgPolicyId };
}

function overlayNameFromPolicyId(orgPolicyId: string, explicit?: string): string {
  if (explicit?.trim()) {
    return explicit.trim();
  }
  return orgPolicyId.endsWith("-overlay-v1") ? orgPolicyId : `${orgPolicyId}-overlay-v1`;
}

function policyNameFromOperation(operation: string): string {
  const slug = operation
    .trim()
    .toLowerCase()
    .replace(/[._]+/g, "-")
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "");
  const base = slug || "agent";
  return base.endsWith("-v1") ? base : `${base}-v1`;
}

function templateIdStubForPreset(presetId: string): string {
  try {
    return getCompletionPreset(presetId).harbor_template_id;
  } catch {
    return "completion_v1";
  }
}

/** Render a starter paybond.policy.yaml document. */
export function renderPaybondPolicyYaml(options: ScaffoldPaybondPolicyOptions): string {
  const operation = options.operation.trim();
  const evidencePreset = options.evidencePreset.trim();
  if (!operation) {
    throw new PaybondPolicyValidationError("operation is required");
  }
  if (!evidencePreset) {
    throw new PaybondPolicyValidationError("evidence preset is required");
  }

  getCompletionPreset(evidencePreset);

  const name = policyNameFromOperation(operation);
  const templateId = templateIdStubForPreset(evidencePreset);

  return `version: 1
name: ${name}
default_deny: true

tools:
  ${operation}:
    side_effecting: true
    evidence_preset: ${evidencePreset}
    operation: ${operation}

intent:
  # Production: publish template head, then paybond.intents.createWithPolicyBinding(policy.toIntentCreateInput(...))
  policy_binding:
    template_id: ${templateId}
  allowed_tools:
    - ${operation}
`;
}

/** Render a v2 org base policy document (no extends). */
export function renderOrgBasePolicyYaml(options: ScaffoldOrgBasePolicyOptions): string {
  const policyId = options.policyId.trim();
  const operation = options.operation.trim();
  const evidencePreset = options.evidencePreset.trim();
  if (!policyId) {
    throw new PaybondPolicyValidationError("policy_id is required");
  }
  if (!POLICY_NAME_RE.test(policyId)) {
    throw new PaybondPolicyValidationError("policy_id must be a lowercase policy name");
  }
  if (!operation) {
    throw new PaybondPolicyValidationError("operation is required");
  }
  if (!evidencePreset) {
    throw new PaybondPolicyValidationError("evidence preset is required");
  }

  getCompletionPreset(evidencePreset);

  const templateId = templateIdStubForPreset(evidencePreset);
  const maxSpendLine =
    options.maxSpendCents !== undefined ? `\n    max_spend_cents: ${options.maxSpendCents}` : "";

  return `version: 2
name: ${policyId}
default_deny: true

tools:
  ${operation}:
    side_effecting: true
    evidence_preset: ${evidencePreset}${maxSpendLine}
    operation: ${operation}

intent:
  # Production: publish template head, then paybond.intents.createWithPolicyBinding(policy.toIntentCreateInput(...))
  policy_binding:
    template_id: ${templateId}
  allowed_tools:
    - ${operation}
`;
}

/** Write a v2 org base policy file for platform operators. */
export async function scaffoldOrgBasePolicy(options: ScaffoldOrgBasePolicyOptions): Promise<{
  out: string;
  policy_id: string;
  operation: string;
  evidence_preset: string;
  bytes_written: number;
}> {
  if (!options.force) {
    try {
      await access(options.out, constants.F_OK);
      throw new PaybondPolicyValidationError(
        `${options.out} already exists (pass --force to overwrite)`,
      );
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        throw err;
      }
    }
  }

  const yaml = renderOrgBasePolicyYaml(options);
  await writeFile(options.out, yaml, "utf8");
  return {
    out: options.out,
    policy_id: options.policyId.trim(),
    operation: options.operation.trim(),
    evidence_preset: options.evidencePreset.trim(),
    bytes_written: Buffer.byteLength(yaml, "utf8"),
  };
}

/** Render a v2 tenant overlay policy that extends an org base. */
export function renderTenantOverlayPolicyYaml(options: ScaffoldTenantOverlayPolicyOptions): string {
  const { orgId, orgPolicyId } = parsePolicyExtendsRef(options.extendsRef);
  const name = overlayNameFromPolicyId(orgPolicyId, options.name);
  if (!POLICY_NAME_RE.test(name)) {
    throw new PaybondPolicyValidationError("overlay name must be a lowercase policy name");
  }

  const operation = options.operation?.trim();
  const evidencePreset = options.evidencePreset?.trim();
  if (operation && !evidencePreset) {
    throw new PaybondPolicyValidationError("tenant-only tool requires --evidence-preset");
  }
  if (evidencePreset && !operation) {
    throw new PaybondPolicyValidationError("--evidence-preset requires --operation for tenant-only tools");
  }
  if (evidencePreset) {
    getCompletionPreset(evidencePreset);
  }

  const basePolicyLine = options.basePolicy?.trim()
    ? `\n  base_policy: ${options.basePolicy.trim()}`
    : "";

  const toolsBlock =
    operation && evidencePreset
      ? `tools:
  ${operation}:
    side_effecting: true
    evidence_preset: ${evidencePreset}
    operation: ${operation}
`
      : "";

  return `version: 2
name: ${name}
extends:
  org_policy_id: ${orgPolicyId}
  org_id: ${orgId}${basePolicyLine}
default_deny: true

${toolsBlock}`;
}

/** Write a v2 tenant overlay policy file extending an org base. */
export async function scaffoldTenantOverlayPolicy(
  options: ScaffoldTenantOverlayPolicyOptions,
): Promise<{
  out: string;
  name: string;
  org_id: string;
  org_policy_id: string;
  operation?: string;
  evidence_preset?: string;
  bytes_written: number;
}> {
  const { orgId, orgPolicyId } = parsePolicyExtendsRef(options.extendsRef);
  const name = overlayNameFromPolicyId(orgPolicyId, options.name);

  if (!options.force) {
    try {
      await access(options.out, constants.F_OK);
      throw new PaybondPolicyValidationError(
        `${options.out} already exists (pass --force to overwrite)`,
      );
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        throw err;
      }
    }
  }

  const yaml = renderTenantOverlayPolicyYaml(options);
  await writeFile(options.out, yaml, "utf8");
  const operation = options.operation?.trim();
  const evidencePreset = options.evidencePreset?.trim();
  return {
    out: options.out,
    name,
    org_id: orgId,
    org_policy_id: orgPolicyId,
    ...(operation ? { operation } : {}),
    ...(evidencePreset ? { evidence_preset: evidencePreset } : {}),
    bytes_written: Buffer.byteLength(yaml, "utf8"),
  };
}

/** Render a bundled preset as editable local YAML with a scaffold header comment. */
export function renderPolicyPresetScaffoldYaml(
  presetId: PolicyPresetId,
  options?: { maxSpendUsd?: number },
): string {
  const regenerate =
    options?.maxSpendUsd !== undefined
      ? `paybond policy init --preset ${presetId} --max-spend ${options.maxSpendUsd} --force`
      : `paybond policy init --preset ${presetId} --force`;
  const body = renderPolicyDocumentYaml(
    options?.maxSpendUsd !== undefined
      ? resolvePresetInitDocument({ out: "", presetId, maxSpendUsd: options.maxSpendUsd })
      : resolveComposedPresetDocument(presetId),
  ).trimEnd();
  return `${policyPresetScaffoldHeader(regenerate)}${body}\n`;
}

/** Render a composed domain + guardrails policy as editable local YAML. */
export function renderComposedPolicyScaffoldYaml(options: ScaffoldComposedPolicyOptions): string {
  const regenerate = `paybond policy init --domain ${options.domainId} --guardrails ${options.guardrails} --force`;
  const body = renderPolicyDocumentYaml(resolveComposedInitDocument(options)).trimEnd();
  return `${policyPresetScaffoldHeader(regenerate)}${body}\n`;
}

/** Preview composed domain + guardrails YAML for `paybond policy presets show`. */
export function renderComposedPolicyPreviewYaml(
  options: Pick<ScaffoldComposedPolicyOptions, "domainId" | "guardrails">,
): string {
  return renderPolicyDocumentYaml(
    resolveComposedInitDocument({ out: "", domainId: options.domainId, guardrails: options.guardrails }),
  );
}

/** Preview composed policy YAML for `paybond policy presets show`. */
export function renderPolicyPresetPreviewYaml(
  presetId: PolicyPresetId,
  options?: { maxSpendUsd?: number },
): string {
  const document =
    options?.maxSpendUsd !== undefined
      ? resolvePresetInitDocument({ out: "", presetId, maxSpendUsd: options.maxSpendUsd })
      : resolveComposedPresetDocument(presetId);
  return renderPolicyDocumentYaml(document);
}

/** Write a bundled vertical preset to an owned local policy file. */
export async function scaffoldPolicyFromPreset(options: ScaffoldPolicyFromPresetOptions): Promise<{
  out: string;
  preset: string;
  name: string;
  bytes_written: number;
}> {
  if (!options.force) {
    try {
      await access(options.out, constants.F_OK);
      throw new PaybondPolicyValidationError(
        `${options.out} already exists (pass --force to overwrite)`,
      );
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        throw err;
      }
    }
  }

  const yaml = renderPolicyPresetScaffoldYaml(options.presetId, {
    maxSpendUsd: options.maxSpendUsd,
  });
  await writeFile(options.out, yaml, "utf8");
  const parsed = parsePolicyDocumentText(yaml, options.out);
  const name = typeof parsed.name === "string" ? parsed.name : options.presetId;
  return {
    out: options.out,
    preset: options.presetId,
    name,
    ...(options.maxSpendUsd !== undefined ? { max_spend_usd: options.maxSpendUsd } : {}),
    bytes_written: Buffer.byteLength(yaml, "utf8"),
  };
}

/** Write a composed domain + guardrails policy file. */
export async function scaffoldComposedPolicy(options: ScaffoldComposedPolicyOptions): Promise<{
  out: string;
  domain: string;
  guardrails: string;
  name: string;
  bytes_written: number;
}> {
  if (!options.force) {
    try {
      await access(options.out, constants.F_OK);
      throw new PaybondPolicyValidationError(
        `${options.out} already exists (pass --force to overwrite)`,
      );
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        throw err;
      }
    }
  }

  const yaml = renderComposedPolicyScaffoldYaml(options);
  await writeFile(options.out, yaml, "utf8");
  const parsed = parsePolicyDocumentText(yaml, options.out);
  const name = typeof parsed.name === "string" ? parsed.name : options.domainId;
  return {
    out: options.out,
    domain: options.domainId,
    guardrails: options.guardrails,
    name,
    bytes_written: Buffer.byteLength(yaml, "utf8"),
  };
}

/** Write a starter paybond.policy.yaml file. */
export async function scaffoldPaybondPolicy(options: ScaffoldPaybondPolicyOptions): Promise<{
  out: string;
  name: string;
  operation: string;
  evidence_preset: string;
  bytes_written: number;
}> {
  if (!options.force) {
    try {
      await access(options.out, constants.F_OK);
      throw new PaybondPolicyValidationError(
        `${options.out} already exists (pass --force to overwrite)`,
      );
    } catch (err) {
      if (err instanceof PaybondPolicyValidationError) {
        throw err;
      }
      // File does not exist — continue.
    }
  }

  const yaml = renderPaybondPolicyYaml(options);
  await writeFile(options.out, yaml, "utf8");
  return {
    out: options.out,
    name: policyNameFromOperation(options.operation),
    operation: options.operation.trim(),
    evidence_preset: options.evidencePreset.trim(),
    bytes_written: Buffer.byteLength(yaml, "utf8"),
  };
}
