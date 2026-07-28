import type { PaybondPolicyDocumentV1 } from "./schema.js";
import type { PaybondVercelAgentConfigOptions } from "../vercel-ai/config.js";

/** Adapter options derived from a flat effective `paybond.policy.yaml` document. */
export type PaybondPolicyAdapterOptions = Pick<
  PaybondVercelAgentConfigOptions,
  "denyProviderExecutedTools"
>;

/**
 * Map policy adapter / default_deny posture to Vercel AI / Cloudflare Agents options.
 *
 * Fail-closed alignment: when `default_deny` is true and the adapter flag is unset,
 * provider-executed tools are denied (they never reach the interceptor). Explicit
 * `adapter.deny_provider_executed_tools: false` opts out of that alignment.
 */
export function policyToAdapterOptions(
  document: PaybondPolicyDocumentV1,
): PaybondPolicyAdapterOptions {
  const deny = document.adapter?.deny_provider_executed_tools;
  if (deny === true) {
    return { denyProviderExecutedTools: true };
  }
  if (deny === false) {
    return {};
  }
  if (document.default_deny === true) {
    return { denyProviderExecutedTools: true };
  }
  return {};
}
