import type { PaybondPolicyDocumentV1 } from "./schema.js";

function yamlScalar(value: string): string {
  if (/^[a-z0-9_.-]+$/i.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function renderToolEntry(entry: PaybondPolicyDocumentV1["tools"][string], indent: string): string[] {
  const lines = [`${indent}side_effecting: ${entry.side_effecting}`];
  if (entry.max_spend_cents !== undefined) {
    lines.push(`${indent}max_spend_cents: ${entry.max_spend_cents}`);
  }
  if (entry.spend_from_args !== undefined) {
    lines.push(`${indent}spend_from_args: ${yamlScalar(entry.spend_from_args)}`);
  }
  if (entry.evidence_preset !== undefined) {
    lines.push(`${indent}evidence_preset: ${entry.evidence_preset}`);
  }
  if (entry.vendor_pack !== undefined) {
    lines.push(`${indent}vendor_pack: ${entry.vendor_pack}`);
  }
  if (entry.operation !== undefined) {
    lines.push(`${indent}operation: ${yamlScalar(entry.operation)}`);
  }
  return lines;
}

/** Serialize a validated v1 policy document to paybond.policy.yaml text. */
export function renderPolicyDocumentYaml(document: PaybondPolicyDocumentV1): string {
  const lines: string[] = [
    `version: ${document.version}`,
    `name: ${document.name}`,
    `default_deny: ${document.default_deny}`,
    "",
    "tools:",
  ];

  for (const [toolName, entry] of Object.entries(document.tools)) {
    lines.push(`  ${toolName}:`);
    lines.push(...renderToolEntry(entry, "    "));
    lines.push("");
  }

  if (document.intent) {
    lines.push("intent:");
    if (document.intent.allowed_tools?.length) {
      lines.push("  allowed_tools:");
      for (const tool of document.intent.allowed_tools) {
        lines.push(`    - ${tool}`);
      }
    }
    if (document.intent.budget) {
      lines.push("  budget:");
      if (document.intent.budget.currency) {
        lines.push(`    currency: ${document.intent.budget.currency}`);
      }
      if (document.intent.budget.max_spend_usd !== undefined) {
        lines.push(`    max_spend_usd: ${document.intent.budget.max_spend_usd}`);
      }
    }
    if (document.intent.policy_binding) {
      lines.push("  policy_binding:");
      lines.push(`    template_id: ${document.intent.policy_binding.template_id}`);
      if (document.intent.policy_binding.version_seq !== undefined) {
        lines.push(`    version_seq: ${document.intent.policy_binding.version_seq}`);
      }
      if (document.intent.policy_binding.head_digest !== undefined) {
        lines.push(`    head_digest: ${document.intent.policy_binding.head_digest}`);
      }
    }
  }

  return `${lines.join("\n").replace(/\n+$/u, "")}\n`;
}
