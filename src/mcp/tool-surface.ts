import type { PaybondAgentRun } from "../agent/run.js";
import {
  buildMcpServerEntry,
  defaultMcpServerCommand,
  serializeMcpInstallPayload,
  type McpInstallFormat,
  type McpServerEntry,
} from "../cli/mcp-install.js";
import type { McpToolPolicyConfig } from "../cli/mcp-policy.js";

export type PaybondMcpToolSurfaceOptions = {
  /** Env file referenced by `PAYBOND_ENV_FILE` in the MCP host config (default `.env.local`). */
  envFile?: string;
  /** Override stdio server launch command (default: package-local `paybond-mcp-server`). */
  serverCommand?: string[];
  /** Optional MCP tool exposure policy for the stdio server process. */
  toolPolicy?: McpToolPolicyConfig | null;
};

/** Stdio MCP host configuration derived from `paybond mcp install` patterns. */
export type PaybondMcpToolSurface = {
  serverConfig: McpServerEntry;
  /** Serialize host config as JSON (Claude Desktop, generic) or TOML (Codex). */
  installPayload: (format?: McpInstallFormat) => string;
};

/**
 * Framework runner helper for external MCP hosts (Claude Desktop, Codex, generic stdio).
 *
 * The bound {@link PaybondAgentRun} establishes tenant/intent context for your app;
 * the returned `serverConfig` is the stdio entry coding-agent hosts consume via
 * `PAYBOND_ENV_FILE` (never raw API keys in host config files).
 */
export function createPaybondMcpToolSurface(
  _run: PaybondAgentRun,
  options?: PaybondMcpToolSurfaceOptions,
): PaybondMcpToolSurface {
  const envFile = options?.envFile?.trim() || ".env.local";
  const serverCommand = options?.serverCommand ?? defaultMcpServerCommand();
  const serverConfig = buildMcpServerEntry(envFile, serverCommand, options?.toolPolicy);

  return {
    serverConfig,
    installPayload: (format = "json") => serializeMcpInstallPayload(format, serverConfig),
  };
}
