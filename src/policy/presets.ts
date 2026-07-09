import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  composeBundledPresetDefault,
  composeLayeredPolicyPresetDocument,
  isLayeredPolicyPreset,
} from "./compose.js";
import type { LayeredPolicyPresetId } from "./compose.js";
import { parsePolicyDocumentText } from "./parse-text.js";
import {
  parsePaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV1,
} from "./schema.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

export type { LayeredPolicyPresetId };

const KNOWN_POLICY_PRESET_IDS = [
  "travel",
  "shopping",
  "saas",
  "aws",
  "stripe-commerce",
  "read-only",
  "strict",
] as const;

export type PolicyPresetId = (typeof KNOWN_POLICY_PRESET_IDS)[number];

function presetCandidatePaths(presetId: string): string[] {
  const fileName = `${presetId}.yaml`;
  const roots = [
    join(MODULE_DIR, "../../policy/presets"),
    join(MODULE_DIR, "../../../policy/presets"),
    join(MODULE_DIR, "../../../../kit/policy/presets"),
  ];
  return roots.map((root) => join(root, fileName));
}

/** True when `value` is a bundled vertical policy preset id (not a file path). */
export function isKnownPolicyPresetId(value: string): value is PolicyPresetId {
  return (KNOWN_POLICY_PRESET_IDS as readonly string[]).includes(value.trim());
}

/** True when the preset is composed from domain + guardrails layers. */
export function isLayeredPolicyPresetId(value: string): value is LayeredPolicyPresetId {
  return isLayeredPolicyPreset(value);
}

/** List bundled vertical policy preset ids shipped with Paybond Kit. */
export function listPolicyPresetIds(): PolicyPresetId[] {
  return [...KNOWN_POLICY_PRESET_IDS];
}

/** Resolve a bundled preset id to an on-disk `paybond.policy.yaml` path. */
export function resolvePolicyPresetPath(presetId: string): string {
  const trimmed = presetId.trim();
  if (!isKnownPolicyPresetId(trimmed)) {
    throw new Error(`unknown policy preset: ${trimmed}`);
  }
  for (const candidate of presetCandidatePaths(trimmed)) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(`policy preset file not found for: ${trimmed}`);
}

/** Load a bundled vertical policy preset as YAML text (for tests and scaffolding). */
export function readPolicyPresetYaml(presetId: PolicyPresetId): string {
  const path = resolvePolicyPresetPath(presetId);
  return readFileSync(path, "utf8");
}

/** Resolve a bundled preset to its composed v1 policy document. */
export function resolveComposedPresetDocument(presetId: PolicyPresetId): PaybondPolicyDocumentV1 {
  if (isLayeredPolicyPreset(presetId)) {
    return composeBundledPresetDefault(presetId);
  }
  const flatPath = resolvePolicyPresetPath(presetId);
  return parsePaybondPolicyDocumentV1(
    parsePolicyDocumentText(readPolicyPresetYaml(presetId), flatPath),
  );
}

/** @deprecated Internal alias used by YAML flat-file parity checks. */
export function readComposedPresetYamlObject(presetId: LayeredPolicyPresetId): Record<string, unknown> {
  return composeLayeredPolicyPresetDocument(presetId);
}
