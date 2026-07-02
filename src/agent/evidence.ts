import {
  getCompletionPreset,
  type CompletionPreset,
} from "../completion-catalog.js";
import {
  isVendorPack,
  mapVendorEvidenceToCanonical,
  resolveCompletionPreset,
} from "../completion-resolve.js";
import {
  PaybondSideEffectingToolEntry,
  PaybondToolCallContext,
} from "./types.js";

export type BuiltAutoEvidence = {
  payload: Record<string, unknown>;
  vendorPayload?: Record<string, unknown>;
};

function assertEvidenceRecord(value: unknown, message: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(message);
  }
  return value as Record<string, unknown>;
}

/**
 * Build canonical evidence payloads from a tool result using the completion catalog.
 */
export function buildAutoEvidencePayload(
  entry: Pick<PaybondSideEffectingToolEntry, "evidencePreset" | "evidenceMapper">,
  toolResult: unknown,
  ctx: PaybondToolCallContext,
): Record<string, unknown> {
  if (entry.evidenceMapper) {
    return assertEvidenceRecord(
      entry.evidenceMapper(toolResult, ctx),
      "evidenceMapper must return a JSON object payload",
    );
  }

  const resolved = resolveCompletionPreset(entry.evidencePreset);
  const preset: CompletionPreset = resolved.preset;

  if (isVendorPack(preset)) {
    if (typeof toolResult === "object" && toolResult !== null && !Array.isArray(toolResult)) {
      return mapVendorEvidenceToCanonical(preset, toolResult as Record<string, unknown>);
    }
    throw new Error(
      `side-effecting tool "${ctx.toolName}" uses vendor pack preset "${entry.evidencePreset}"; provide evidenceMapper when tool result is not a JSON object`,
    );
  }

  if (typeof toolResult === "object" && toolResult !== null && !Array.isArray(toolResult)) {
    return { ...(toolResult as Record<string, unknown>) };
  }

  return { ...getCompletionPreset(resolved.archetype.preset_id).sample_evidence };
}
