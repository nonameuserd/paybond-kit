import {
  parsePaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV1,
} from "./schema.js";
import { loadBundledDomainDocument } from "./layers-io.js";

const LAYERED_POLICY_PRESET_IDS = ["travel", "shopping", "saas", "aws"] as const;

type LayeredPolicyPresetId = (typeof LAYERED_POLICY_PRESET_IDS)[number];

function loadDomain(presetId: LayeredPolicyPresetId): PaybondPolicyDocumentV1 {
  return parsePaybondPolicyDocumentV1(loadBundledDomainDocument(presetId));
}

/** Travel booking domain: hotel booking + read-only web search. */
export function travel(): PaybondPolicyDocumentV1 {
  return loadDomain("travel");
}

/** Shopping domain: checkout + product search. */
export function shopping(): PaybondPolicyDocumentV1 {
  return loadDomain("shopping");
}

/** SaaS domain: seat provisioning + plan listing. */
export function saas(): PaybondPolicyDocumentV1 {
  return loadDomain("saas");
}

/** AWS operator domain: EC2 start + describe. */
export function aws(): PaybondPolicyDocumentV1 {
  return loadDomain("aws");
}

export const domain = {
  travel,
  shopping,
  saas,
  aws,
} as const;
