import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";

import {
  type McpInstallFormat,
  type McpInstallHost,
  type McpInstallScope,
  type McpServerEntry,
  defaultMcpServerCommand,
  planMcpInstall,
} from "./mcp-install.js";
import {
  MCP_TOOL_ALLOWLIST_ENV,
  MCP_TOOL_POLICY_ENV,
  type McpToolPolicyConfig,
  mergeMcpToolPolicy,
  parseMcpToolAllowlist,
  parseMcpToolPolicy,
  resolveMcpToolPolicy,
} from "./mcp-policy.js";

export type McpConfigSource = "generated" | "file";

export type McpConfigValidationIssue = {
  field: string;
  message: string;
};

export type McpConfigValidationResult = {
  ok: boolean;
  host: string;
  source: McpConfigSource;
  configPath: string | null;
  issues: McpConfigValidationIssue[];
  entry?: McpServerEntry;
  toolPolicy?: McpToolPolicyConfig;
  message: string;
};

function validationMessage(ok: boolean, issues: McpConfigValidationIssue[]): string {
  if (ok) {
    return "MCP host config is valid";
  }
  return issues[0]?.message ?? "invalid MCP config";
}

function parseTomlPaybondEntry(payload: string): Record<string, unknown> {
  const section = "[mcp_servers.paybond]";
  if (!payload.includes(section)) {
    throw new Error("missing [mcp_servers.paybond] section");
  }
  const afterSection = payload.split(section, 1)[1] ?? "";
  const envSection = "[mcp_servers.paybond.env]";
  const [block, envBlock = ""] = afterSection.includes(envSection)
    ? afterSection.split(envSection)
    : [afterSection, ""];
  const commandMatch = /command\s*=\s*(.+)/.exec(block);
  const argsMatch = /args\s*=\s*(\[[\s\S]*?\])/.exec(block);
  if (!commandMatch?.[1]) {
    throw new Error("missing paybond command");
  }
  const command = JSON.parse(commandMatch[1].trim()) as unknown;
  const args = argsMatch?.[1] ? (JSON.parse(argsMatch[1]) as unknown) : [];
  const env: Record<string, string> = {};
  for (const line of envBlock.split("\n")) {
    const stripped = line.trim();
    if (!stripped || stripped.startsWith("#") || !stripped.includes("=")) {
      continue;
    }
    const [key, value] = stripped.split("=", 2);
    env[key!.trim()] = JSON.parse(value!.trim()) as string;
  }
  return { command, args, env };
}

export function parseMcpHostEntry(payload: string, format: McpInstallFormat): McpServerEntry {
  const parsed =
    format === "toml"
      ? parseTomlPaybondEntry(payload)
      : (() => {
          const body = JSON.parse(payload) as Record<string, unknown>;
          const servers = body.mcpServers;
          if (!servers || typeof servers !== "object" || Array.isArray(servers)) {
            throw new Error("missing mcpServers object");
          }
          const paybond = (servers as Record<string, unknown>).paybond;
          if (!paybond || typeof paybond !== "object" || Array.isArray(paybond)) {
            throw new Error("missing mcpServers.paybond entry");
          }
          return paybond as Record<string, unknown>;
        })();
  const command = parsed.command;
  if (typeof command !== "string" || !command.trim()) {
    throw new Error("missing paybond command");
  }
  const args = parsed.args;
  if (!Array.isArray(args) || !args.every((item) => typeof item === "string")) {
    throw new Error("paybond args must be a string array");
  }
  const envRaw = parsed.env;
  if (envRaw !== undefined && (typeof envRaw !== "object" || Array.isArray(envRaw))) {
    throw new Error("paybond env must be an object");
  }
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries((envRaw as Record<string, unknown> | undefined) ?? {})) {
    env[key] = String(value);
  }
  return {
    command,
    args: [...args],
    env,
  };
}

function validateEntry(
  entry: McpServerEntry,
  cwd: string,
  expectedEnvFile?: string,
): { issues: McpConfigValidationIssue[]; toolPolicy?: McpToolPolicyConfig } {
  const issues: McpConfigValidationIssue[] = [];
  if ("PAYBOND_API_KEY" in entry.env) {
    issues.push({ field: "env", message: "config must reference PAYBOND_ENV_FILE, not PAYBOND_API_KEY" });
  }
  const envFile = entry.env.PAYBOND_ENV_FILE?.trim() ?? "";
  if (!envFile) {
    issues.push({ field: "env", message: "missing PAYBOND_ENV_FILE" });
  } else if (expectedEnvFile && envFile !== expectedEnvFile) {
    issues.push({
      field: "env",
      message: `PAYBOND_ENV_FILE mismatch: config=${JSON.stringify(envFile)} expected=${JSON.stringify(expectedEnvFile)}`,
    });
  }
  const resolvedEnv = path.isAbsolute(envFile) ? path.resolve(envFile) : path.resolve(cwd, envFile);
  if (envFile && !existsSync(resolvedEnv)) {
    issues.push({ field: "env", message: `env file not found: ${resolvedEnv}` });
  }
  if (!entry.command.trim()) {
    issues.push({ field: "command", message: "missing MCP server command" });
  }

  let toolPolicy: McpToolPolicyConfig | undefined;
  const rawPolicy = entry.env[MCP_TOOL_POLICY_ENV]?.trim() ?? "";
  const rawAllowlist = entry.env[MCP_TOOL_ALLOWLIST_ENV]?.trim() ?? "";
  try {
    toolPolicy = resolveMcpToolPolicy(
      mergeMcpToolPolicy(parseMcpToolPolicy(rawPolicy || undefined), parseMcpToolAllowlist(rawAllowlist || undefined)),
    );
  } catch (err) {
    issues.push({
      field: "tool_policy",
      message: err instanceof Error ? err.message : String(err),
    });
  }
  return { issues, toolPolicy };
}

export function validateMcpHostConfig(input: {
  host: McpInstallHost;
  format: McpInstallFormat;
  payload: string;
  cwd: string;
  expectedEnvFile?: string;
  source?: McpConfigSource;
  configPath?: string | null;
}): McpConfigValidationResult {
  try {
    const entry = parseMcpHostEntry(input.payload, input.format);
    const { issues, toolPolicy } = validateEntry(entry, input.cwd, input.expectedEnvFile);
    const ok = issues.length === 0;
    return {
      ok,
      host: input.host,
      source: input.source ?? "generated",
      configPath: input.configPath ?? null,
      issues,
      entry,
      toolPolicy,
      message: validationMessage(ok, issues),
    };
  } catch (err) {
    const issues = [{ field: "config", message: err instanceof Error ? err.message : String(err) }];
    return {
      ok: false,
      host: input.host,
      source: input.source ?? "generated",
      configPath: input.configPath ?? null,
      issues,
      message: validationMessage(false, issues),
    };
  }
}

export async function verifyMcpInstallPlan(input: {
  host: McpInstallHost;
  scope?: McpInstallScope;
  format: McpInstallFormat;
  envFile: string;
  cwd: string;
  home: string;
  configPath?: string;
  toolPolicy?: McpToolPolicyConfig;
}): Promise<McpConfigValidationResult> {
  let payload: string;
  let source: McpConfigSource = "generated";
  let configPath = input.configPath ?? null;
  if (input.configPath) {
    payload = await readFile(input.configPath, "utf8");
    source = "file";
  } else {
    const plan = planMcpInstall({
      host: input.host,
      scope: input.scope ?? "local",
      format: input.format,
      envFile: input.envFile,
      cwd: input.cwd,
      home: input.home,
      serverCommand: defaultMcpServerCommand(),
      toolPolicy: input.toolPolicy,
    });
    payload = plan.payload;
    configPath = plan.configPath;
  }
  return validateMcpHostConfig({
    host: input.host,
    format: input.format,
    payload,
    cwd: input.cwd,
    expectedEnvFile: input.envFile,
    source,
    configPath,
  });
}
