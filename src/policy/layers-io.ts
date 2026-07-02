import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parsePolicyDocumentText } from "./parse-text.js";
import type { LayeredPolicyPresetId } from "./compose.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

export function presetLayerCandidatePaths(subdir: string, fileName: string): string[] {
  return [
    join(MODULE_DIR, "../../policy/presets", subdir, fileName),
    join(MODULE_DIR, "../../../policy/presets", subdir, fileName),
    join(MODULE_DIR, "../../../../kit/policy/presets", subdir, fileName),
  ];
}

export function readPresetLayerYaml(subdir: string, fileName: string): string {
  for (const candidate of presetLayerCandidatePaths(subdir, fileName)) {
    if (existsSync(candidate)) {
      return readFileSync(candidate, "utf8");
    }
  }
  throw new Error(`policy preset layer not found: ${subdir}/${fileName}`);
}

/** Load a bundled domain layer YAML document. */
export function loadBundledDomainDocument(presetId: LayeredPolicyPresetId): Record<string, unknown> {
  return parsePolicyDocumentText(
    readPresetLayerYaml("domain", `${presetId}.yaml`),
    `domain/${presetId}.yaml`,
  );
}

/** Load a bundled default guardrails layer YAML document. */
export function loadBundledDefaultGuardrailsDocument(
  presetId: LayeredPolicyPresetId,
): Record<string, unknown> {
  return parsePolicyDocumentText(
    readPresetLayerYaml("guardrails", `default-${presetId}.yaml`),
    `guardrails/default-${presetId}.yaml`,
  );
}
