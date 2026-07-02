import { resolve } from "node:path";

import type { PaybondToolRegistry } from "../../agent/registry.js";
import type { PaybondRunBindingSandboxBootstrapInput } from "../../agent/types.js";
import { PaybondPolicy } from "../../policy/load.js";
import { parsePolicyDocumentText } from "../../policy/parse-text.js";
import { parsePaybondPolicyDocument, parsePaybondPolicyDocumentV1 } from "../../policy/schema.js";
import { PaybondPolicySandboxBootstrapError } from "../../policy/sandbox-bootstrap.js";
import { createPolicySnapshot, type PaybondPolicySnapshot } from "../../policy/snapshot.js";

export type ResolvedAgentPolicyBind = {
  policyPath: string;
  policy: PaybondPolicy;
  registry: PaybondToolRegistry;
  policySnapshot: PaybondPolicySnapshot;
  defaultDeny: boolean;
  bootstrap?: PaybondRunBindingSandboxBootstrapInput;
  operation: string;
  completionPreset?: string;
};

function resolveAgentPolicyDocument(
  policyPath: string,
  content: string,
): PaybondPolicy {
  const raw = parsePolicyDocumentText(content, policyPath);
  const document = parsePaybondPolicyDocument(raw);
  return PaybondPolicy.fromDocument(parsePaybondPolicyDocumentV1(document));
}

function finalizeAgentPolicyBind(
  policyPath: string,
  policy: PaybondPolicy,
  options: {
    operation?: string;
    requestedSpendCents?: number;
    forAttach?: boolean;
  },
): ResolvedAgentPolicyBind {
  const registry = policy.toToolRegistry();
  const defaultDeny = policy.defaultDeny;
  const policySnapshot = createPolicySnapshot({
    document: policy.document,
    registry,
    source: "file",
  });

  if (options.forAttach) {
    const sideEffecting = Object.entries(policy.document.tools).find(([, entry]) => entry.side_effecting);
    const operation =
      options.operation?.trim() ||
      (sideEffecting
        ? sideEffecting[1].operation?.trim() || sideEffecting[0]
        : "");
    return { policyPath, policy, registry, policySnapshot, defaultDeny, operation };
  }

  const bootstrap = policy.sandboxBootstrap({
    operation: options.operation,
    requestedSpendCents: options.requestedSpendCents,
  });

  return {
    policyPath,
    policy,
    registry,
    policySnapshot,
    defaultDeny,
    bootstrap,
    operation: bootstrap.operation,
    completionPreset: bootstrap.completionPreset,
  };
}

/** Resolve bind inputs from persisted policy file content (CLI re-attach for reload). */
export function resolveAgentPolicyBindFromContent(options: {
  policyPath: string;
  content: string;
  operation?: string;
  requestedSpendCents?: number;
  forAttach?: boolean;
}): ResolvedAgentPolicyBind {
  const policy = resolveAgentPolicyDocument(options.policyPath, options.content);
  return finalizeAgentPolicyBind(options.policyPath, policy, options);
}

export async function resolveAgentPolicyBind(options: {
  cwd: string;
  policyFile: string;
  operation?: string;
  requestedSpendCents?: number;
  forAttach?: boolean;
}): Promise<ResolvedAgentPolicyBind> {
  const policyPath = resolve(options.cwd, options.policyFile);
  let policy: PaybondPolicy;
  try {
    policy = await PaybondPolicy.load(policyPath);
  } catch (err) {
    if (err instanceof PaybondPolicySandboxBootstrapError) {
      throw err;
    }
    throw err;
  }

  return finalizeAgentPolicyBind(policyPath, policy, options);
}
