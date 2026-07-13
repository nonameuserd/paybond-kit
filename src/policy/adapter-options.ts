import type { PaybondPolicyDocumentV1 } from "./schema.js";
import type { PaybondVercelAgentConfigOptions } from "../vercel-ai/config.js";

/** Adapter options derived from a flat effective `paybond.policy.yaml` document. */
export type PaybondPolicyAdapterOptions = Pick<
  PaybondVercelAgentConfigOptions,
  "denyProviderExecutedTools"
>;

/**
 * Map policy `adapter.deny_provider_executed_tools` to Vercel AI / Cloudflare Agents options.
 * Returns an empty object when the policy leaves the flag unset (adapter default applies).
 */
export function policyToAdapterOptions(
  document: PaybondPolicyDocumentV1,
): PaybondPolicyAdapterOptions {
  const deny = document.adapter?.deny_provider_executed_tools;
  if (deny !== true) {
    return {};
  }
  return { denyProviderExecutedTools: true };
}
