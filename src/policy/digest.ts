import { createHash } from "node:crypto";

import type { PaybondPolicyDocumentV1 } from "./schema.js";

/** Serialize a validated v1 policy document to Gateway-compatible JSON dict form. */
export function policyDocumentToDict(document: PaybondPolicyDocumentV1): Record<string, unknown> {
  const tools = Object.fromEntries(
    Object.entries(document.tools).map(([toolName, entry]) => [
      toolName,
      {
        side_effecting: entry.side_effecting,
        ...(entry.max_spend_cents !== undefined ? { max_spend_cents: entry.max_spend_cents } : {}),
        ...(entry.spend_from_args !== undefined ? { spend_from_args: entry.spend_from_args } : {}),
        ...(entry.evidence_preset !== undefined ? { evidence_preset: entry.evidence_preset } : {}),
        ...(entry.vendor_pack !== undefined ? { vendor_pack: entry.vendor_pack } : {}),
        ...(entry.operation !== undefined ? { operation: entry.operation } : {}),
      },
    ]),
  );

  const payload: Record<string, unknown> = {
    version: document.version,
    name: document.name,
    default_deny: document.default_deny,
    tools,
  };

  if (document.intent) {
    const intent: Record<string, unknown> = {};
    if (document.intent.policy_binding) {
      const binding: Record<string, unknown> = {
        template_id: document.intent.policy_binding.template_id,
      };
      if (document.intent.policy_binding.version_seq !== undefined) {
        binding.version_seq = document.intent.policy_binding.version_seq;
      }
      if (document.intent.policy_binding.head_digest !== undefined) {
        binding.head_digest = document.intent.policy_binding.head_digest;
      }
      intent.policy_binding = binding;
    }
    if (document.intent.budget) {
      intent.budget = document.intent.budget;
    }
    if (document.intent.allowed_tools?.length) {
      intent.allowed_tools = document.intent.allowed_tools;
    }
    if (Object.keys(intent).length > 0) {
      payload.intent = intent;
    }
  }

  return payload;
}

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(canonicalizeJson);
  }
  if (value && typeof value === "object") {
    const row = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(row).sort()) {
      out[key] = canonicalizeJson(row[key]);
    }
    return out;
  }
  return value;
}

/** Return `sha256:<hex>` for the canonical JSON encoding of a v1 policy document. */
export function canonicalPolicyDocumentDigest(document: PaybondPolicyDocumentV1): string {
  const wire = policyDocumentToDict(document);
  const text = JSON.stringify(canonicalizeJson(wire));
  const hash = createHash("sha256").update(text, "utf8").digest("hex");
  return `sha256:${hash}`;
}

/** Human-readable policy version label (`{name}@{digest_short}`). */
export function policyVersionLabel(name: string, digest: string): string {
  const trimmed = digest.trim();
  const short =
    trimmed.startsWith("sha256:") && trimmed.length >= 15
      ? trimmed.slice(7, 15)
      : trimmed.slice(0, 8);
  return `${name}@${short}`;
}
