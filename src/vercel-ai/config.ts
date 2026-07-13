import type { ToolSet } from "ai";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  paybondVercelToolApproval,
  type PaybondVercelToolApprovalOptions,
} from "./tool-approval.js";
import {
  paybondVercelWrapTools,
  type PaybondVercelWrapToolsOptions,
} from "./wrap-tools.js";

/** Vercel AI SDK runner config: guarded tools plus centralized `toolApproval`. */
export type PaybondVercelAgentConfig<TOOLS extends ToolSet = ToolSet> = {
  tools: TOOLS;
  toolApproval: ReturnType<typeof paybondVercelToolApproval<TOOLS>>;
};

export type PaybondVercelAgentConfigOptions = PaybondVercelToolApprovalOptions &
  PaybondVercelWrapToolsOptions;

/**
 * Framework runner helper for Vercel AI SDK `generateText` / `streamText`.
 *
 * Returns guarded `tools` and a `toolApproval` bridge for Harbor pre-checks.
 */
export function createPaybondVercelAgentConfig<TOOLS extends ToolSet>(
  run: PaybondAgentRun,
  tools: TOOLS,
  options?: PaybondVercelAgentConfigOptions,
): PaybondVercelAgentConfig<TOOLS> {
  return {
    tools: paybondVercelWrapTools(run, tools, options),
    toolApproval: paybondVercelToolApproval(run, options),
  };
}
