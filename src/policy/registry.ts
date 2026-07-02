import { createPaybondToolRegistry, PaybondToolRegistry } from "../agent/registry.js";
import {
  PaybondSideEffectingToolPolicy,
  PaybondToolRegistryConfig,
} from "../agent/types.js";
import { resolveSpendCentsFromJsonPath } from "./json-path.js";
import type { PaybondPolicyDocumentV1 } from "./schema.js";

/** Convert a validated policy document into middleware registry config. */
export function policyDocumentToToolRegistryConfig(
  document: PaybondPolicyDocumentV1,
): PaybondToolRegistryConfig {
  const sideEffecting: Record<string, PaybondSideEffectingToolPolicy> = {};

  for (const [toolName, entry] of Object.entries(document.tools)) {
    if (!entry.side_effecting) {
      continue;
    }

    const policy: PaybondSideEffectingToolPolicy = {
      evidencePreset: entry.evidence_preset!,
    };

    if (entry.operation?.trim()) {
      policy.operation = entry.operation.trim();
    }

    if (entry.max_spend_cents !== undefined) {
      policy.spendCents = entry.max_spend_cents;
    } else if (entry.spend_from_args) {
      const path = entry.spend_from_args;
      policy.spendCents = (args) => resolveSpendCentsFromJsonPath(args, path, toolName);
    }

    sideEffecting[toolName] = policy;
  }

  return {
    defaultDeny: document.default_deny,
    sideEffecting,
  };
}

/** Build a validated {@link PaybondToolRegistry} from a policy document. */
export function policyToToolRegistry(document: PaybondPolicyDocumentV1): PaybondToolRegistry {
  return createPaybondToolRegistry(policyDocumentToToolRegistryConfig(document));
}
