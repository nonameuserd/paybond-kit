import { colorize, shouldUseColor } from "./color.js";
import type { GlobalOptions } from "./types.js";

/** Build human-readable harbor proxy evidence smoke checklist lines for `--format table`. */
export function formatAgentHarborEvidenceSmokeChecklist(options: {
  intentId: string;
  evidence: Record<string, unknown>;
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
  const intentId = options.intentId.trim();
  if (intentId) {
    lines.push(mark(`✓ Intent ${intentId}`));
  }
  lines.push(mark("✓ POST /harbor/intents/{id}/evidence (Kit payee + recognition proof)"));

  const predicatePassed = options.evidence.predicate_passed ?? options.evidence.predicatePassed;
  if (predicatePassed === true) {
    lines.push(mark("✓ Harbor accepted evidence (no recognition replay at upstream)"));
  }

  lines.push(mark("Success"));
  return lines;
}
