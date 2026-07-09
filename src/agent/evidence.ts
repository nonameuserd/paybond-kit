import {
  getCompletionPreset,
  type CompletionPreset,
} from "../completion-catalog.js";
import {
  isVendorPack,
  mapVendorEvidenceToCanonical,
  resolveCompletionPreset,
} from "../completion-resolve.js";
import { assertNotStripeFundingWebhook } from "../stripe-commerce/evidence.js";
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
 * Reject Stripe funding webhook envelopes before they become completion evidence.
 *
 * Funding webhooks (`payment_intent.succeeded`, `charge.*`, event envelopes) fund Harbor
 * intents; tool-completion evidence must use SDK charge/result shapes (or mapped
 * {@link mapStripeToolResultToEvidence} outputs), not webhook bodies.
 */
export function assertToolResultNotFundingWebhook(toolResult: unknown): void {
  if (typeof toolResult === "object" && toolResult !== null && !Array.isArray(toolResult)) {
    assertNotStripeFundingWebhook(toolResult as Record<string, unknown>);
  }
}

/**
 * Build canonical evidence payloads from a tool result using the completion catalog.
 *
 * Fail-closed: Stripe funding webhook-shaped tool results are rejected before mapping.
 */
export function buildAutoEvidencePayload(
  entry: Pick<PaybondSideEffectingToolEntry, "evidencePreset" | "evidenceMapper">,
  toolResult: unknown,
  ctx: PaybondToolCallContext,
): Record<string, unknown> {
  assertToolResultNotFundingWebhook(toolResult);

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
