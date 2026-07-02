import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type SolutionPolicyDefault = {
  domain: string;
  guardrails: string[];
};

export type SolutionSmokeManifest = {
  result_body: Record<string, unknown>;
  evidence_preset: string;
};

export type SolutionManifest = {
  id: string;
  title: string;
  policy_default: SolutionPolicyDefault;
  primary_operation: string;
  completion_preset: string;
  vendor_pack?: string;
  smoke: SolutionSmokeManifest;
};

export type SolutionSmokeDefaults = {
  operation: string;
  requestedSpendCents: number;
  evidencePreset: string;
  resultBody: Record<string, unknown>;
};

const KNOWN_SOLUTION_IDS = ["travel", "shopping", "saas", "aws"] as const;

export type SolutionId = (typeof KNOWN_SOLUTION_IDS)[number];

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

function solutionCandidatePaths(solutionId: string): string[] {
  const fileName = `${solutionId}.json`;
  const roots = [
    join(MODULE_DIR, "../../solutions"),
    join(MODULE_DIR, "../../../solutions"),
    join(MODULE_DIR, "../../../../kit/solutions"),
  ];
  return roots.map((root) => join(root, fileName));
}

function parseSolutionManifest(raw: unknown, sourceLabel: string): SolutionManifest {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`invalid solution manifest at ${sourceLabel}`);
  }
  const record = raw as Record<string, unknown>;
  const smoke = record.smoke;
  if (!smoke || typeof smoke !== "object" || Array.isArray(smoke)) {
    throw new Error(`solution manifest ${sourceLabel} missing smoke block`);
  }
  const smokeRecord = smoke as Record<string, unknown>;
  const resultBody = smokeRecord.result_body;
  if (!resultBody || typeof resultBody !== "object" || Array.isArray(resultBody)) {
    throw new Error(`solution manifest ${sourceLabel} missing smoke.result_body object`);
  }
  const evidencePreset = smokeRecord.evidence_preset;
  if (typeof evidencePreset !== "string" || !evidencePreset.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing smoke.evidence_preset`);
  }
  const policyDefault = record.policy_default;
  if (!policyDefault || typeof policyDefault !== "object" || Array.isArray(policyDefault)) {
    throw new Error(`solution manifest ${sourceLabel} missing policy_default block`);
  }
  const policyDefaultRecord = policyDefault as Record<string, unknown>;
  const domain = policyDefaultRecord.domain;
  const guardrails = policyDefaultRecord.guardrails;
  if (typeof domain !== "string" || !domain.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing policy_default.domain`);
  }
  if (!Array.isArray(guardrails) || guardrails.some((entry) => typeof entry !== "string")) {
    throw new Error(`solution manifest ${sourceLabel} missing policy_default.guardrails`);
  }

  const id = record.id;
  const title = record.title;
  const primaryOperation = record.primary_operation;
  const completionPreset = record.completion_preset;
  if (typeof id !== "string" || !id.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing id`);
  }
  if (typeof title !== "string" || !title.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing title`);
  }
  if (typeof primaryOperation !== "string" || !primaryOperation.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing primary_operation`);
  }
  if (typeof completionPreset !== "string" || !completionPreset.trim()) {
    throw new Error(`solution manifest ${sourceLabel} missing completion_preset`);
  }

  const vendorPack = record.vendor_pack;
  if (vendorPack !== undefined && (typeof vendorPack !== "string" || !vendorPack.trim())) {
    throw new Error(`solution manifest ${sourceLabel} has invalid vendor_pack`);
  }

  return {
    id: id.trim(),
    title: title.trim(),
    policy_default: {
      domain: domain.trim(),
      guardrails: guardrails.map((entry) => entry.trim()),
    },
    primary_operation: primaryOperation.trim(),
    completion_preset: completionPreset.trim(),
    ...(vendorPack ? { vendor_pack: vendorPack.trim() } : {}),
    smoke: {
      result_body: resultBody as Record<string, unknown>,
      evidence_preset: evidencePreset.trim(),
    },
  };
}

/** True when `value` is a bundled solution id (travel, shopping, saas, aws). */
export function isKnownSolutionId(value: string): value is SolutionId {
  return (KNOWN_SOLUTION_IDS as readonly string[]).includes(value.trim());
}

/** List bundled solution ids shipped with Paybond Kit. */
export function listSolutionIds(): SolutionId[] {
  return [...KNOWN_SOLUTION_IDS];
}

/** Load a bundled solution manifest from disk. */
export function loadSolutionManifest(solutionId: string): SolutionManifest {
  const trimmed = solutionId.trim();
  if (!isKnownSolutionId(trimmed)) {
    throw new Error(`unknown solution: ${trimmed}`);
  }
  let lastError: unknown;
  for (const candidate of solutionCandidatePaths(trimmed)) {
    try {
      const raw = JSON.parse(readFileSync(candidate, "utf8")) as unknown;
      const manifest = parseSolutionManifest(raw, candidate);
      if (manifest.id !== trimmed) {
        throw new Error(`manifest id "${manifest.id}" does not match file name "${trimmed}"`);
      }
      return manifest;
    } catch (err) {
      lastError = err;
    }
  }
  throw new Error(
    `solution manifest not found for: ${trimmed} (${solutionCandidatePaths(trimmed).join(", ")}): ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
  );
}

function resolveRequestedSpendCents(resultBody: Record<string, unknown>): number {
  const costCents = resultBody.cost_cents;
  if (typeof costCents === "number" && Number.isFinite(costCents) && costCents >= 0) {
    return Math.trunc(costCents);
  }
  throw new Error("solution smoke.result_body must include non-negative cost_cents");
}

/** Resolve CLI smoke defaults from a bundled solution manifest. */
export function getSolutionSmokeDefaults(solutionId: string): SolutionSmokeDefaults {
  const manifest = loadSolutionManifest(solutionId);
  const resultBody = { ...manifest.smoke.result_body };
  return {
    operation: manifest.primary_operation,
    requestedSpendCents: resolveRequestedSpendCents(resultBody),
    evidencePreset: manifest.smoke.evidence_preset,
    resultBody,
  };
}
