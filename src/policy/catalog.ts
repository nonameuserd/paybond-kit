import { LAYERED_POLICY_PRESET_IDS } from "./compose.js";
import { listGuardrailCatalogEntries } from "./guardrail-spec.js";
import { isLayeredPolicyPresetId, listPolicyPresetIds } from "./presets.js";
import { listSolutionIds, loadSolutionManifest } from "../solutions/catalog.js";

export type PolicyDomainCatalogEntry = {
  id: string;
  title: string;
  layered: boolean;
};

export type PolicyPresetCatalogEntry = {
  id: string;
  kind: "composed" | "flat";
  layered: boolean;
};

export type PolicySolutionCatalogEntry = {
  id: string;
  title: string;
  domain: string;
  guardrails: string[];
  primary_operation: string;
};

const DOMAIN_TITLES: Record<string, string> = {
  travel: "Travel booking",
  shopping: "Shopping checkout",
  saas: "SaaS provisioning",
  aws: "AWS operator",
};

/** List bundled domain layers for CLI and docs. */
export function listPolicyDomainCatalog(): PolicyDomainCatalogEntry[] {
  return LAYERED_POLICY_PRESET_IDS.map((id) => ({
    id,
    title: DOMAIN_TITLES[id] ?? id,
    layered: true,
  }));
}

/** List flat and composed policy presets. */
export function listPolicyPresetCatalog(): PolicyPresetCatalogEntry[] {
  return listPolicyPresetIds().map((id) => ({
    id,
    kind: isLayeredPolicyPresetId(id) ? "composed" : "flat",
    layered: isLayeredPolicyPresetId(id),
  }));
}

/** List bundled solution manifests. */
export function listPolicySolutionCatalog(): PolicySolutionCatalogEntry[] {
  return listSolutionIds().map((id) => {
    const manifest = loadSolutionManifest(id);
    return {
      id: manifest.id,
      title: manifest.title,
      domain: manifest.policy_default.domain,
      guardrails: [...manifest.policy_default.guardrails],
      primary_operation: manifest.primary_operation,
    };
  });
}

/** Combined catalog payload for `paybond policy presets list`. */
export function listPolicyPresetsCatalog(): {
  domains: PolicyDomainCatalogEntry[];
  guardrails: ReturnType<typeof listGuardrailCatalogEntries>;
  solutions: PolicySolutionCatalogEntry[];
  presets: PolicyPresetCatalogEntry[];
} {
  return {
    domains: listPolicyDomainCatalog(),
    guardrails: listGuardrailCatalogEntries(),
    solutions: listPolicySolutionCatalog(),
    presets: listPolicyPresetCatalog(),
  };
}
