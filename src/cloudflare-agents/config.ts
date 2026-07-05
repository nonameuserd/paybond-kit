import type { ToolSet } from "ai";

import type { PaybondAgentRun } from "../agent/run.js";
import {
  createPaybondVercelAgentConfig,
  type PaybondVercelAgentConfigOptions,
} from "../vercel-ai/config.js";
import { paybondVercelToolApproval } from "../vercel-ai/tool-approval.js";
import { paybondVercelWrapTools } from "../vercel-ai/wrap-tools.js";

/** Cloudflare Agents `getTools()` return shape — AI SDK `ToolSet`. */
export type CloudflareAgentsToolSet = ToolSet;

/** Cloudflare Agents runner config: guarded tools plus `toolApproval` for AI SDK turns. */
export type PaybondCloudflareAgentsConfig<TOOLS extends ToolSet = ToolSet> = {
  tools: TOOLS;
  toolApproval: ReturnType<typeof paybondVercelToolApproval<TOOLS>>;
};

/**
 * Wrap side-effecting Cloudflare Agent tools with Paybond `wrapExecute`.
 *
 * Cloudflare Agents register tools via `getTools()` using the AI SDK `tool()`
 * helper — the same execute boundary as the Vercel AI adapter.
 */
export function paybondCloudflareAgentsWrapTools<TOOLS extends ToolSet>(
  run: PaybondAgentRun,
  tools: TOOLS,
): TOOLS {
  return paybondVercelWrapTools(run, tools);
}

/**
 * Framework runner helper for Cloudflare Agents `getTools()` / `streamText` wiring.
 *
 * Returns guarded `tools` and a `toolApproval` bridge for Harbor pre-checks.
 */
export function createPaybondCloudflareAgentsConfig<TOOLS extends ToolSet>(
  run: PaybondAgentRun,
  tools: TOOLS,
  options?: PaybondVercelAgentConfigOptions,
): PaybondCloudflareAgentsConfig<TOOLS> {
  const config = createPaybondVercelAgentConfig(run, tools, options);
  return {
    tools: config.tools,
    toolApproval: config.toolApproval,
  };
}
