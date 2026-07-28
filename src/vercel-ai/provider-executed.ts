import type { Tool, ToolSet } from "ai";

const PROVIDER_EXECUTED_DENIAL_REASON =
  "Paybond governs only locally executed registry tools; provider-executed tools bypass Harbor verify and auto-evidence. Remove the tool, execute it locally, or disable denyProviderExecutedTools.";

/** Returns true when the AI SDK tool is executed on the model provider (not in your process). */
export function isProviderExecutedVercelTool(tool: Tool): boolean {
  if (typeof tool !== "object" || tool === null) {
    return false;
  }
  const record = tool as Record<string, unknown>;
  if (record.isProviderExecuted === true) {
    return true;
  }
  // AI SDK v5+ provider-defined tools (and any tool without a local execute).
  if (record.type === "provider-defined") {
    return true;
  }
  return typeof record.execute !== "function";
}

/** User-facing denial reason for fail-closed provider-executed tool policy. */
export function paybondProviderExecutedToolDenialReason(): string {
  return PROVIDER_EXECUTED_DENIAL_REASON;
}

/** Resolve a tool definition from a Vercel AI SDK toolApproval `tools` map. */
export function resolveVercelToolFromSet<TOOLS extends ToolSet>(
  tools: TOOLS | undefined,
  toolName: string,
): Tool | undefined {
  if (!tools || typeof tools !== "object") {
    return undefined;
  }
  const record = tools as Record<string, Tool>;
  return record[toolName];
}
