import { colorize, shouldUseColor } from "./color.js";
import type { DevTraceStep } from "../dev/trace-buffer.js";
import type { GlobalOptions } from "./types.js";

/** Build human-readable agent run trace lines for `--format table`. */
export function formatAgentRunTraceTable(options: {
  runId: string;
  intentId: string;
  steps: readonly DevTraceStep[];
  globals: GlobalOptions;
}): string[] {
  const useColor = shouldUseColor(options.globals);
  const mark = (line: string): string => {
    if (line.startsWith("✓")) {
      return colorize(line, "green", useColor);
    }
    return line;
  };

  const lines: string[] = [
    `run_id: ${options.runId}`,
    `intent_id: ${options.intentId}`,
    "",
  ];

  if (options.steps.length === 0) {
    lines.push("No trace events recorded.");
    return lines;
  }

  for (const step of options.steps) {
    lines.push(mark(`✓ ${step.label}`));
  }
  return lines;
}
