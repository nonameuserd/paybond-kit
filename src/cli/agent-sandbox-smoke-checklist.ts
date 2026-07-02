import { basename } from "node:path";

import { colorize, shouldUseColor } from "./color.js";
import type { GlobalOptions } from "./types.js";

function formatUsdFromCents(cents: number): string {
  return `$${(cents / 100).toFixed(2)}`;
}

function evidencePresetFromBind(bind: Record<string, unknown>): string | undefined {
  const preset = bind.completion_preset;
  return typeof preset === "string" && preset.trim() ? preset.trim() : undefined;
}

/** Build human-readable sandbox smoke checklist lines for `--format table`. */
export function formatAgentSandboxSmokeChecklist(options: {
  presetId?: string;
  bind: Record<string, unknown>;
  execute: Record<string, unknown>;
  resultBody: Record<string, unknown>;
  globals: GlobalOptions;
}): string[] {
  const useColor = shouldUseColor(options.globals);
  const mark = (line: string): string => {
    if (line.startsWith("✓") || line === "Success") {
      return colorize(line, "green", useColor);
    }
    return line;
  };

  const presetLabel =
    options.presetId?.trim() ||
    (typeof options.bind.policy_file === "string"
      ? basename(options.bind.policy_file)
      : "custom");

  const lines: string[] = [];
  lines.push(mark(`✓ Policy loaded (${presetLabel})`));

  if (options.bind.intent_id) {
    lines.push(mark("✓ Sandbox intent created"));
  }

  const operation = String(options.bind.operation ?? "").trim();
  if (operation) {
    lines.push(mark(`✓ Tool call: ${operation}`));
  }

  const authorization = options.execute.authorization as Record<string, unknown> | undefined;
  if (authorization?.allow) {
    const costCents =
      typeof options.resultBody.cost_cents === "number"
        ? options.resultBody.cost_cents
        : typeof options.bind.requested_spend_cents === "number"
          ? options.bind.requested_spend_cents
          : undefined;
    const spendLabel = costCents !== undefined ? formatUsdFromCents(costCents) : "approved";
    lines.push(mark(`✓ Spend approved (${spendLabel})`));
  }

  const evidence = options.execute.evidence as Record<string, unknown> | undefined;
  if (evidence?.submitted) {
    const preset = evidencePresetFromBind(options.bind) ?? "cost_and_completion";
    lines.push(mark(`✓ Evidence validated (${preset})`));
    lines.push(mark("✓ Settlement simulated"));
  }

  lines.push(mark("Success"));
  return lines;
}
