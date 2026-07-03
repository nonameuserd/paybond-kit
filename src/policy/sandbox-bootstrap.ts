import { getCompletionPreset } from "../completion-catalog.js";
import type { PaybondRunBindingSandboxBootstrapInput } from "../agent/types.js";
import type { PaybondPolicyDocumentV1, PaybondPolicyToolEntry } from "./schema.js";

/** Raised when policy cannot derive sandbox bootstrap parameters. */
export class PaybondPolicySandboxBootstrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondPolicySandboxBootstrapError";
  }
}

export type PaybondPolicySandboxBootstrapOptions = {
  /** Registry tool name to bootstrap against. */
  toolName?: string;
  /** Harbor operation string; matched against tool names and optional `operation` overrides. */
  operation?: string;
  requestedSpendCents?: number;
  currency?: string;
  evidenceSchema?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
};

function listSideEffectingTools(
  document: PaybondPolicyDocumentV1,
): Array<[string, PaybondPolicyToolEntry]> {
  return Object.entries(document.tools).filter(([, entry]) => entry.side_effecting);
}

function resolveHarborOperation(toolName: string, entry: PaybondPolicyToolEntry): string {
  return entry.operation?.trim() || toolName;
}

function resolveSideEffectingTool(
  document: PaybondPolicyDocumentV1,
  options: PaybondPolicySandboxBootstrapOptions,
): { toolName: string; entry: PaybondPolicyToolEntry } {
  const sideEffecting = listSideEffectingTools(document);
  if (sideEffecting.length === 0) {
    throw new PaybondPolicySandboxBootstrapError(
      "policy has no side-effecting tools for sandbox bootstrap",
    );
  }

  if (options.toolName?.trim()) {
    const toolName = options.toolName.trim();
    const entry = document.tools[toolName];
    if (!entry?.side_effecting) {
      throw new PaybondPolicySandboxBootstrapError(
        `tool "${toolName}" is not a registered side-effecting tool in policy`,
      );
    }
    return { toolName, entry };
  }

  if (options.operation?.trim()) {
    const operation = options.operation.trim();
    for (const [toolName, entry] of sideEffecting) {
      const harborOperation = resolveHarborOperation(toolName, entry);
      if (harborOperation === operation || toolName === operation) {
        return { toolName, entry };
      }
    }
    throw new PaybondPolicySandboxBootstrapError(
      `operation "${operation}" does not match any side-effecting tool in policy`,
    );
  }

  const [toolName, entry] = sideEffecting[0]!;
  return { toolName, entry };
}

/** Build {@link PaybondAgentRun.bind} sandbox bootstrap input from a validated policy document. */
export function policySandboxBootstrap(
  document: PaybondPolicyDocumentV1,
  options: PaybondPolicySandboxBootstrapOptions = {},
): PaybondRunBindingSandboxBootstrapInput {
  const { toolName, entry } = resolveSideEffectingTool(document, options);
  const operation = resolveHarborOperation(toolName, entry);
  const evidencePreset = entry.evidence_preset!;
  const preset = getCompletionPreset(evidencePreset);

  let requestedSpendCents = options.requestedSpendCents;
  if (requestedSpendCents === undefined) {
    requestedSpendCents = entry.max_spend_cents ?? preset.recommended_amount_cents ?? 0;
  }
  if (!Number.isFinite(requestedSpendCents) || requestedSpendCents < 0) {
    throw new PaybondPolicySandboxBootstrapError(
      "requestedSpendCents must be a non-negative number",
    );
  }

  const bootstrap: PaybondRunBindingSandboxBootstrapInput = {
    kind: "sandbox",
    operation,
    requestedSpendCents,
    currency: options.currency ?? document.intent?.budget?.currency,
    completionPreset: evidencePreset,
    metadata: options.metadata,
    idempotencyKey: options.idempotencyKey,
    templateId: preset.harbor_template_id,
    parameters: preset.parameters,
  };

  // Gateway rejects requests that include both completion_preset and evidence_schema.
  if (!evidencePreset.trim()) {
    bootstrap.evidenceSchema = options.evidenceSchema ?? preset.evidence_schema;
  } else if (options.evidenceSchema !== undefined) {
    throw new PaybondPolicySandboxBootstrapError(
      "completion_preset and evidenceSchema are mutually exclusive for sandbox bootstrap",
    );
  }

  return bootstrap;
}
