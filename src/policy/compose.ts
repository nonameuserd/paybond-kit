import { cloneToolEntry } from "./compose-utils.js";
import { guardrailLayerFromDocument, type PolicyGuardrailLayer } from "./guardrails.js";
import {
  loadBundledDefaultGuardrailsDocument,
  loadBundledDomainDocument,
  readPresetLayerYaml,
} from "./layers-io.js";
import { parsePolicyDocumentText } from "./parse-text.js";
import { readPolicyPresetYaml, resolvePolicyPresetPath, type PolicyPresetId } from "./presets.js";
import {
  parsePaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV1,
  type PaybondPolicyIntentSection,
  type PaybondPolicyToolEntry,
} from "./schema.js";

export const LAYERED_POLICY_PRESET_IDS = ["travel", "shopping", "saas", "aws"] as const;

export type LayeredPolicyPresetId = (typeof LAYERED_POLICY_PRESET_IDS)[number];

function mergeStricterDefaultDeny(...values: Array<boolean | undefined>): boolean {
  return values.some((value) => value === true);
}

function cloneDocument(document: PaybondPolicyDocumentV1): PaybondPolicyDocumentV1 {
  return {
    ...document,
    tools: Object.fromEntries(
      Object.entries(document.tools).map(([name, entry]) => [name, cloneToolEntry(entry)]),
    ),
    intent: document.intent
      ? {
          ...document.intent,
          ...(document.intent.allowed_tools
            ? { allowed_tools: [...document.intent.allowed_tools] }
            : {}),
          ...(document.intent.budget ? { budget: { ...document.intent.budget } } : {}),
          ...(document.intent.policy_binding
            ? { policy_binding: { ...document.intent.policy_binding } }
            : {}),
        }
      : undefined,
  };
}

function mergeToolEntry(
  base: PaybondPolicyToolEntry,
  patch: Partial<PaybondPolicyToolEntry>,
): PaybondPolicyToolEntry {
  const merged = cloneToolEntry(base);
  if (patch.side_effecting !== undefined) {
    merged.side_effecting = patch.side_effecting;
  }
  if (patch.max_spend_cents !== undefined) {
    merged.max_spend_cents =
      merged.max_spend_cents !== undefined
        ? Math.min(merged.max_spend_cents, patch.max_spend_cents)
        : patch.max_spend_cents;
  }
  if (patch.spend_from_args !== undefined) {
    merged.spend_from_args = patch.spend_from_args;
    delete merged.max_spend_cents;
  }
  if (patch.evidence_preset !== undefined) {
    merged.evidence_preset = patch.evidence_preset;
  }
  if (patch.vendor_pack !== undefined) {
    merged.vendor_pack = patch.vendor_pack;
  }
  if (patch.operation !== undefined) {
    merged.operation = patch.operation;
  }
  return merged;
}

function mergeBudgetCaps(
  current: PaybondPolicyIntentSection["budget"] | undefined,
  nextUsd: number,
): PaybondPolicyIntentSection["budget"] {
  const currency = current?.currency ?? "usd";
  const currentUsd = current?.max_spend_usd;
  return {
    ...current,
    currency,
    max_spend_usd:
      currentUsd !== undefined ? Math.min(currentUsd, nextUsd) : nextUsd,
  };
}

function applyReadOnlyFilter(document: PaybondPolicyDocumentV1, searchOnly: boolean): void {
  const filteredEntries = Object.entries(document.tools).filter(([name, entry]) => {
    if (entry.side_effecting) {
      return false;
    }
    return !searchOnly || name.startsWith("search.");
  });
  document.tools = Object.fromEntries(filteredEntries);
  if (document.intent?.allowed_tools) {
    const allowed = new Set(Object.keys(document.tools));
    document.intent.allowed_tools = document.intent.allowed_tools.filter((tool) => allowed.has(tool));
  }
}

function assertEvidenceRequired(document: PaybondPolicyDocumentV1): void {
  for (const [name, entry] of Object.entries(document.tools)) {
    if (entry.side_effecting && !entry.evidence_preset) {
      throw new Error(`side-effecting tool "${name}" must declare evidence_preset`);
    }
  }
}

function applyGuardrailLayer(
  document: PaybondPolicyDocumentV1,
  layer: PolicyGuardrailLayer,
): void {
  if (layer.default_deny !== undefined) {
    document.default_deny = mergeStricterDefaultDeny(document.default_deny, layer.default_deny);
  }

  if (layer.tools) {
    for (const [toolName, patch] of Object.entries(layer.tools)) {
      const existing = document.tools[toolName];
      if (existing) {
        document.tools[toolName] = mergeToolEntry(existing, patch);
      }
    }
  }

  if (layer.intent) {
    document.intent = {
      ...document.intent,
      ...layer.intent,
      ...(layer.intent.allowed_tools
        ? {
            allowed_tools: layer.intent.allowed_tools,
          }
        : {}),
      ...(layer.intent.budget
        ? {
            budget: {
              ...document.intent?.budget,
              ...layer.intent.budget,
            },
          }
        : {}),
      ...(layer.intent.policy_binding
        ? {
            policy_binding: {
              ...document.intent?.policy_binding,
              ...layer.intent.policy_binding,
            },
          }
        : {}),
    };
  }

  if (layer.caps?.sideEffectingMaxSpendCents !== undefined) {
    const cents = layer.caps.sideEffectingMaxSpendCents;
    for (const [toolName, entry] of Object.entries(document.tools)) {
      if (entry.side_effecting) {
        document.tools[toolName] = mergeToolEntry(entry, { max_spend_cents: cents });
      }
    }
  }

  if (layer.caps?.budgetMaxSpendUsd !== undefined) {
    document.intent = {
      ...document.intent,
      budget: mergeBudgetCaps(document.intent?.budget, layer.caps.budgetMaxSpendUsd),
    };
  }

  if (layer.filters?.readOnly || layer.filters?.readOnlySearch) {
    applyReadOnlyFilter(document, Boolean(layer.filters.readOnlySearch));
  }

  if (layer.requireEvidence) {
    assertEvidenceRequired(document);
  }
}

/** Stack a domain document with one or more guardrail layers (same-tenant compose, not org inheritance). */
export function composePolicyLayers(
  domainDocument: PaybondPolicyDocumentV1,
  ...layers: PolicyGuardrailLayer[]
): PaybondPolicyDocumentV1 {
  const composed = cloneDocument(domainDocument);
  for (const layer of layers) {
    applyGuardrailLayer(composed, layer);
  }
  assertEvidenceRequired(composed);
  return composed;
}

/** True when a bundled preset is composed from domain + guardrails layers. */
export function isLayeredPolicyPreset(presetId: string): presetId is LayeredPolicyPresetId {
  return (LAYERED_POLICY_PRESET_IDS as readonly string[]).includes(presetId.trim());
}

function guardrailsFileName(presetId: LayeredPolicyPresetId): string {
  return `default-${presetId}.yaml`;
}

function deepMergeRecord(
  base: Record<string, unknown>,
  patch: Record<string, unknown>,
): Record<string, unknown> {
  const result = { ...base };
  for (const [key, patchValue] of Object.entries(patch)) {
    const baseValue = result[key];
    if (
      baseValue &&
      patchValue &&
      typeof baseValue === "object" &&
      typeof patchValue === "object" &&
      !Array.isArray(baseValue) &&
      !Array.isArray(patchValue)
    ) {
      result[key] = deepMergeRecord(
        baseValue as Record<string, unknown>,
        patchValue as Record<string, unknown>,
      );
    } else {
      result[key] = patchValue;
    }
  }
  return result;
}

/** Merge domain and guardrail YAML objects (bundled preset file generation). */
export function composePolicyPresetLayers(
  domain: Record<string, unknown>,
  guardrails: Record<string, unknown>,
): Record<string, unknown> {
  return deepMergeRecord(domain, guardrails);
}

/** Default bundled guardrail layers for a vertical preset id. */
export function bundledDefaultGuardrails(presetId: LayeredPolicyPresetId): PolicyGuardrailLayer[] {
  return [guardrailLayerFromDocument(loadBundledDefaultGuardrailsDocument(presetId))];
}

/** Compose the shipped default for a vertical preset (domain + bundled guardrails). */
export function composeBundledPresetDefault(presetId: LayeredPolicyPresetId): PaybondPolicyDocumentV1 {
  return composePolicyLayers(
    parsePaybondPolicyDocumentV1(loadBundledDomainDocument(presetId)),
    ...bundledDefaultGuardrails(presetId),
  );
}

/** Load and compose a layered vertical preset (domain + guardrails YAML files). */
export function composeLayeredPolicyPresetDocument(
  presetId: LayeredPolicyPresetId,
): Record<string, unknown> {
  const domain = loadBundledDomainDocument(presetId);
  const guardrails = loadBundledDefaultGuardrailsDocument(presetId);
  return composePolicyPresetLayers(domain, guardrails);
}

/** Compare composed layered presets with bundled flat preset files (tests). */
export function assertLayeredPresetMatchesFlat(presetId: PolicyPresetId): void {
  if (!isLayeredPolicyPreset(presetId)) {
    return;
  }
  const composed = composeLayeredPolicyPresetDocument(presetId);
  const flatPath = resolvePolicyPresetPath(presetId);
  const flat = parsePolicyDocumentText(readPolicyPresetYaml(presetId), flatPath);
  if (
    JSON.stringify(normalizePolicyPresetDocument(composed)) !==
    JSON.stringify(normalizePolicyPresetDocument(flat))
  ) {
    throw new Error(`composed preset ${presetId} does not match flat bundled file`);
  }
}

function normalizePolicyPresetDocument(document: Record<string, unknown>): Record<string, unknown> {
  const tools = document.tools;
  const normalizedTools =
    tools && typeof tools === "object" && !Array.isArray(tools)
      ? Object.fromEntries(
          Object.entries(tools as Record<string, unknown>)
            .sort(([left], [right]) => left.localeCompare(right))
            .map(([name, entry]) => [
              name,
              entry && typeof entry === "object" && !Array.isArray(entry)
                ? Object.fromEntries(
                    Object.entries(entry as Record<string, unknown>).sort(([left], [right]) =>
                      left.localeCompare(right),
                    ),
                  )
                : entry,
            ]),
        )
      : tools;

  const intent = document.intent;
  const normalizedIntent =
    intent && typeof intent === "object" && !Array.isArray(intent)
      ? {
          ...intent,
          ...(Array.isArray((intent as Record<string, unknown>).allowed_tools)
            ? {
                allowed_tools: [
                  ...((intent as Record<string, unknown>).allowed_tools as unknown[]),
                ].sort(),
              }
            : {}),
        }
      : intent;

  return {
    ...document,
    ...(normalizedTools !== undefined ? { tools: normalizedTools } : {}),
    ...(normalizedIntent !== undefined ? { intent: normalizedIntent } : {}),
  };
}

export { readPresetLayerYaml } from "./layers-io.js";
