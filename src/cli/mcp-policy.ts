export type McpToolPolicy = "readonly" | "spend-write" | "allowlist";

export const MCP_TOOL_POLICY_ENV = "PAYBOND_MCP_TOOL_POLICY";
export const MCP_TOOL_ALLOWLIST_ENV = "PAYBOND_MCP_TOOL_ALLOWLIST";

export const LIVE_MONEY_TOOL_NAMES = new Set([
  "paybond_fund_intent",
  "paybond_confirm_settlement",
]);

export type McpToolPolicyConfig = {
  policy: McpToolPolicy | null;
  allowlist: readonly string[];
};

export type McpToolAnnotations = {
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
};

export function parseMcpToolPolicy(raw: string | undefined): McpToolPolicyConfig {
  const value = (raw ?? "").trim().toLowerCase();
  if (!value) {
    return { policy: null, allowlist: [] };
  }
  if (value === "readonly" || value === "spend-write" || value === "allowlist") {
    return { policy: value, allowlist: [] };
  }
  throw new Error("invalid --tool-policy (expected readonly|spend-write|allowlist)");
}

export function parseMcpToolAllowlist(raw: string | undefined): string[] {
  if (!raw?.trim()) {
    return [];
  }
  const items = raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (items.length === 0) {
    throw new Error("invalid --tool-allowlist (expected comma-separated tool names)");
  }
  return items;
}

export function mergeMcpToolPolicy(
  policy: McpToolPolicyConfig,
  allowlist?: readonly string[],
): McpToolPolicyConfig {
  const mergedAllowlist = allowlist ?? policy.allowlist;
  if (policy.policy === "allowlist" && mergedAllowlist.length === 0) {
    throw new Error("--tool-allowlist is required when --tool-policy allowlist");
  }
  if (policy.policy !== "allowlist" && mergedAllowlist.length > 0) {
    throw new Error("--tool-allowlist is only valid with --tool-policy allowlist");
  }
  return { policy: policy.policy, allowlist: [...mergedAllowlist] };
}

export function mcpToolPolicyEnv(config: McpToolPolicyConfig): Record<string, string> {
  if (config.policy === null) {
    return {};
  }
  const env: Record<string, string> = {
    [MCP_TOOL_POLICY_ENV]: config.policy,
  };
  if (config.policy === "allowlist") {
    env[MCP_TOOL_ALLOWLIST_ENV] = config.allowlist.join(",");
  }
  return env;
}

export function toolAnnotationsFlags(annotations: McpToolAnnotations | undefined): {
  readOnly: boolean;
  destructive: boolean;
} {
  return {
    readOnly: annotations?.readOnlyHint === true,
    destructive: annotations?.destructiveHint === true,
  };
}

export function toolAllowedByPolicy(
  name: string,
  annotations: McpToolAnnotations | undefined,
  config: McpToolPolicyConfig,
): boolean {
  if (config.policy === null) {
    return true;
  }
  const { readOnly, destructive } = toolAnnotationsFlags(annotations);
  if (config.policy === "readonly") {
    return readOnly;
  }
  if (config.policy === "spend-write") {
    return !isLiveMoneyTool(name, annotations);
  }
  if (config.policy === "allowlist") {
    return new Set(config.allowlist).has(name);
  }
  return true;
}

export function validateMcpToolSchema(tool: Record<string, unknown>): string[] {
  const errors: string[] = [];
  const name = typeof tool.name === "string" ? tool.name : "";
  if (!name.trim()) {
    errors.push("tool missing non-empty name");
  }
  const description = tool.description;
  if (typeof description !== "string" || !description.trim()) {
    errors.push(`${name || "<unknown>"}: missing description`);
  }
  const inputSchema = tool.inputSchema;
  if (!inputSchema || typeof inputSchema !== "object" || Array.isArray(inputSchema)) {
    errors.push(`${name || "<unknown>"}: inputSchema must be an object`);
  } else if ((inputSchema as Record<string, unknown>).type !== "object") {
    errors.push(`${name || "<unknown>"}: inputSchema.type must be object`);
  }
  const outputSchema = tool.outputSchema;
  if (outputSchema !== undefined && (typeof outputSchema !== "object" || Array.isArray(outputSchema))) {
    errors.push(`${name || "<unknown>"}: outputSchema must be an object when present`);
  }
  const annotations = tool.annotations;
  if (annotations !== undefined && (typeof annotations !== "object" || Array.isArray(annotations))) {
    errors.push(`${name || "<unknown>"}: annotations must be an object when present`);
  }
  return errors;
}

export function isLiveMoneyTool(name: string, annotations: McpToolAnnotations | undefined): boolean {
  const { destructive } = toolAnnotationsFlags(annotations);
  return destructive || LIVE_MONEY_TOOL_NAMES.has(name);
}
