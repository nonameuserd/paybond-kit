import { fileURLToPath } from "node:url";

import { type McpToolPolicyConfig, mcpToolPolicyEnv, resolveMcpToolPolicy } from "./mcp-policy.js";

export type McpInstallFormat = "json" | "toml";
export type McpInstallScope = "local" | "project" | "user";
export type McpInstallHost = "claude" | "codex" | "openai" | "generic";

export const MCP_INSTALL_HOSTS: readonly McpInstallHost[] = ["claude", "codex", "openai", "generic"];

export type McpServerEntry = {
  command: string;
  args: string[];
  env: Record<string, string>;
};

export type McpInstallPlan = {
  host: string;
  scope: McpInstallScope;
  format: McpInstallFormat;
  envFile: string;
  configPath: string | null;
  serverCommand: string[];
  payload: string;
  printed: boolean;
  toolPolicy?: McpToolPolicyConfig | null;
};

export function resolvePackageLocalMcpServerCommand(): string[] {
  const mcpServerJs = fileURLToPath(new URL("../mcp-server.js", import.meta.url));
  return [process.execPath, mcpServerJs];
}

export function defaultMcpServerCommand(): string[] {
  return resolvePackageLocalMcpServerCommand();
}

export function buildMcpServerEntry(
  envFile: string,
  serverCommand: string[],
  toolPolicy?: McpToolPolicyConfig | null,
): McpServerEntry {
  return {
    command: serverCommand[0]!,
    args: serverCommand.slice(1),
    env: { PAYBOND_ENV_FILE: envFile, ...mcpToolPolicyEnv(resolveMcpToolPolicy(toolPolicy ?? { policy: null, allowlist: [] })) },
  };
}

export function serializeMcpInstallPayload(format: McpInstallFormat, entry: McpServerEntry): string {
  if (format === "toml") {
    const argsJson = JSON.stringify(entry.args);
    return [
      "# Paybond MCP stdio server — merge into your host MCP config",
      "[mcp_servers.paybond]",
      `command = ${JSON.stringify(entry.command)}`,
      `args = ${argsJson}`,
      "",
      "[mcp_servers.paybond.env]",
      ...Object.entries(entry.env).map(([key, value]) => `${key} = ${JSON.stringify(value)}`),
      "",
    ].join("\n");
  }
  return `${JSON.stringify(
    {
      mcpServers: {
        paybond: entry,
      },
    },
    null,
    2,
  )}\n`;
}

export function resolveMcpInstallPath(
  scope: McpInstallScope,
  format: McpInstallFormat,
  out: string | undefined,
  cwd: string,
  home: string,
): string | null {
  if (out?.trim()) {
    return out.trim();
  }
  if (scope === "local") {
    return null;
  }
  const ext = format === "toml" ? "toml" : "json";
  const base = scope === "user" ? home : cwd;
  return `${base.replace(/\/+$/, "")}/.paybond/mcp.${ext}`;
}

export function defaultMcpInstallFormat(host: McpInstallHost): McpInstallFormat {
  return host === "codex" ? "toml" : "json";
}

export function planMcpInstall(input: {
  host: McpInstallHost;
  scope: McpInstallScope;
  format: McpInstallFormat;
  envFile: string;
  out?: string;
  cwd: string;
  home: string;
  serverCommand?: string[];
  toolPolicy?: McpToolPolicyConfig | null;
}): McpInstallPlan {
  const serverCommand = input.serverCommand ?? defaultMcpServerCommand();
  const entry = buildMcpServerEntry(input.envFile, serverCommand, input.toolPolicy);
  const payload = serializeMcpInstallPayload(input.format, entry);
  const configPath = resolveMcpInstallPath(input.scope, input.format, input.out, input.cwd, input.home);
  return {
    host: input.host,
    scope: input.scope,
    format: input.format,
    envFile: input.envFile,
    configPath,
    serverCommand,
    payload,
    printed: configPath === null,
    toolPolicy: input.toolPolicy ?? null,
  };
}

export function parseMcpInstallHost(raw: string | undefined): McpInstallHost {
  const value = (raw ?? "").trim().toLowerCase();
  if (!value) {
    throw new Error("missing --host (expected claude|codex|openai|generic)");
  }
  if ((MCP_INSTALL_HOSTS as readonly string[]).includes(value)) {
    return value as McpInstallHost;
  }
  throw new Error("invalid --host (expected claude|codex|openai|generic)");
}

export function parseMcpInstallFormat(raw: string | undefined, host: McpInstallHost): McpInstallFormat {
  if (!raw?.trim()) {
    return defaultMcpInstallFormat(host);
  }
  const value = raw.trim().toLowerCase();
  if (value === "json" || value === "toml") {
    return value;
  }
  throw new Error("invalid --format (expected json|toml)");
}

export function parseMcpInstallScope(raw: string | undefined): McpInstallScope {
  const value = (raw ?? "project").trim().toLowerCase();
  if (value === "local" || value === "project" || value === "user") {
    return value;
  }
  throw new Error("invalid --scope (expected local|project|user)");
}

declare const process: { execPath: string };
