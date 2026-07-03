import { colorize, shouldUseColor } from "./color.js";
import type { GlobalOptions } from "./types.js";

/** Build human-readable production attach smoke checklist lines for `--format table`. */
export function formatAgentProductionAttachSmokeChecklist(options: {
  bind: Record<string, unknown>;
  execute: Record<string, unknown>;
  globals: GlobalOptions;
}): string[] {
  const useColor = shouldUseColor(options.globals);
  const mark = (line: string): string => {
    if (line.startsWith("✓") || line === "Success") {
      return colorize(line, "green", useColor);
    }
    return line;
  };

  const lines: string[] = [];
  const intentId = String(options.bind.intent_id ?? "").trim();
  if (intentId) {
    lines.push(mark(`✓ Production attach bound (${intentId})`));
  }

  const operation = String(options.bind.operation ?? "").trim();
  if (operation) {
    lines.push(mark(`✓ Tool call: ${operation}`));
  }

  const authorization = options.execute.authorization as Record<string, unknown> | undefined;
  if (authorization?.allow) {
    lines.push(mark("✓ Spend approved"));
  }

  const evidence = options.execute.evidence as Record<string, unknown> | undefined;
  if (evidence?.submitted) {
    lines.push(mark("✓ Harbor evidence submitted (/harbor/* + recognition)"));
  }

  lines.push(mark("Success"));
  return lines;
}
