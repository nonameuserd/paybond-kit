import { PaybondPolicy } from "../policy/load.js";
import { paybondPolicyPresets, type VerticalPolicyOptions } from "../policy/policy-api.js";
import type { LayeredPolicyPresetId } from "../policy/presets.js";
import type { PaybondPolicyDocumentV1 } from "../policy/schema.js";
import { getSolutionSmokeDefaults, loadSolutionManifest, type SolutionId, type SolutionSmokeDefaults } from "./catalog.js";

export type PaybondSolutionBundle = {
  id: SolutionId;
  title: string;
  policy: PaybondPolicy;
  smokeDefaults: SolutionSmokeDefaults;
  completionPreset: string;
  vendorPack?: string;
  operations: string[];
};

function listSideEffectingOperations(document: PaybondPolicyDocumentV1): string[] {
  return Object.entries(document.tools)
    .filter(([, entry]) => entry.side_effecting)
    .map(([toolName, entry]) => entry.operation?.trim() || toolName);
}

function resolveSolutionBundle(
  solutionId: LayeredPolicyPresetId,
  options?: VerticalPolicyOptions,
): PaybondSolutionBundle {
  const manifest = loadSolutionManifest(solutionId);
  const policy =
    options === undefined
      ? paybondPolicyPresets[solutionId]()
      : paybondPolicyPresets[solutionId](options);
  const document = policy.document;
  return {
    id: solutionId,
    title: manifest.title,
    policy,
    smokeDefaults: getSolutionSmokeDefaults(solutionId),
    completionPreset: manifest.completion_preset,
    ...(manifest.vendor_pack ? { vendorPack: manifest.vendor_pack } : {}),
    operations: listSideEffectingOperations(document),
  };
}

/** Programmatic solution bundle API (`paybond.solution.*`). */
export const paybondSolutionPresets = {
  travel(options?: VerticalPolicyOptions): PaybondSolutionBundle {
    return resolveSolutionBundle("travel", options);
  },
  shopping(options?: VerticalPolicyOptions): PaybondSolutionBundle {
    return resolveSolutionBundle("shopping", options);
  },
  saas(options?: VerticalPolicyOptions): PaybondSolutionBundle {
    return resolveSolutionBundle("saas", options);
  },
  aws(options?: VerticalPolicyOptions): PaybondSolutionBundle {
    return resolveSolutionBundle("aws", options);
  },
  loadManifest: loadSolutionManifest,
  smokeDefaults: getSolutionSmokeDefaults,
} as const;

export type PaybondSolutionPresets = typeof paybondSolutionPresets;
