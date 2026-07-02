import {
  bundledDefaultGuardrails,
  composeBundledPresetDefault,
  composePolicyLayers,
  type LayeredPolicyPresetId,
} from "./compose.js";
import { domain } from "./domain.js";
import { guardrails, maxSpend, maxSpendUsd, type PolicyGuardrailLayer } from "./guardrails.js";
import { PaybondPolicy } from "./load.js";
import {
  isKnownPolicyPresetId,
  isLayeredPolicyPresetId,
  resolveComposedPresetDocument,
  type PolicyPresetId,
} from "./presets.js";
import type { PaybondPolicyDocumentV1 } from "./schema.js";

export type VerticalPolicyOptions = {
  /** Per side-effecting tool spend cap in cents. */
  maxSpend?: number;
  /** Intent budget cap in USD. */
  maxSpendUsd?: number;
  /** Additional guardrail layers applied after bundled defaults. */
  guardrails?: PolicyGuardrailLayer[];
};

function verticalPolicy(
  presetId: LayeredPolicyPresetId,
  options?: VerticalPolicyOptions,
): PaybondPolicy {
  const hasCustomizations =
    options?.maxSpend !== undefined ||
    options?.maxSpendUsd !== undefined ||
    (options?.guardrails?.length ?? 0) > 0;

  if (!hasCustomizations) {
    return PaybondPolicy.fromDocument(composeBundledPresetDefault(presetId));
  }

  const layers: PolicyGuardrailLayer[] = [...bundledDefaultGuardrails(presetId)];
  if (options?.maxSpend !== undefined) {
    layers.push(maxSpend(options.maxSpend));
  }
  if (options?.maxSpendUsd !== undefined) {
    layers.push(maxSpendUsd(options.maxSpendUsd));
  }
  if (options?.guardrails?.length) {
    layers.push(...options.guardrails);
  }

  return PaybondPolicy.fromDocument(composePolicyLayers(domain[presetId](), ...layers));
}

function composeToPolicy(
  domainDocument: PaybondPolicyDocumentV1,
  ...layers: PolicyGuardrailLayer[]
): PaybondPolicy {
  return PaybondPolicy.fromDocument(composePolicyLayers(domainDocument, ...layers));
}

function presetPolicy(presetId: PolicyPresetId): PaybondPolicy {
  return PaybondPolicy.fromDocument(resolveComposedPresetDocument(presetId));
}

/** Programmatic policy composition API (`paybond.policyPresets.*`). */
export const paybondPolicyPresets = {
  travel(options?: VerticalPolicyOptions): PaybondPolicy {
    return verticalPolicy("travel", options);
  },
  shopping(options?: VerticalPolicyOptions): PaybondPolicy {
    return verticalPolicy("shopping", options);
  },
  saas(options?: VerticalPolicyOptions): PaybondPolicy {
    return verticalPolicy("saas", options);
  },
  aws(options?: VerticalPolicyOptions): PaybondPolicy {
    return verticalPolicy("aws", options);
  },
  readOnly(): PaybondPolicy {
    return presetPolicy("read-only");
  },
  strict(): PaybondPolicy {
    return presetPolicy("strict");
  },
  compose: composeToPolicy,
  domain,
  guardrails,
  resolvePresetDocument(presetId: string): PaybondPolicyDocumentV1 {
    if (!isKnownPolicyPresetId(presetId)) {
      throw new Error(`unknown policy preset: ${presetId}`);
    }
    return resolveComposedPresetDocument(presetId);
  },
  isLayeredPreset: isLayeredPolicyPresetId,
} as const;

export type PaybondPolicyPresets = typeof paybondPolicyPresets;
