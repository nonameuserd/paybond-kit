import path from "node:path";

import { configFilePath } from "./config.js";
import { describeCredentialSource } from "./credentials.js";
import { packageVersion } from "./doctor-agent.js";
import type { CliContext } from "./context.js";
import { PaybondMCPServer } from "../mcp-server.js";

export type SupportDiagnostics = {
  package_name: string;
  package_version: string;
  runtime: string;
  platform: {
    os: string;
    arch: string;
  };
  config_path: string;
  env_file_path: string;
  gateway_url: string;
  request_id: string;
  mcp_tool_count: number;
  credential_source: Awaited<ReturnType<typeof describeCredentialSource>>;
};

function resolvedEnvFilePath(ctx: CliContext): string {
  const envFile = ctx.globals.envFile;
  return path.isAbsolute(envFile) ? path.resolve(envFile) : path.resolve(ctx.cwd, envFile);
}

export async function buildSupportDiagnostics(ctx: CliContext): Promise<SupportDiagnostics> {
  const server = new PaybondMCPServer({
    gatewayBaseUrl: ctx.globals.gateway,
    apiKey: "paybond_sk_sandbox_redacted_redacted_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  });
  return {
    package_name: "@paybond/kit",
    package_version: packageVersion(),
    runtime: `node ${process.version}`,
    platform: {
      os: process.platform,
      arch: process.arch,
    },
    config_path: configFilePath(),
    env_file_path: resolvedEnvFilePath(ctx),
    gateway_url: ctx.globals.gateway,
    request_id: ctx.globals.requestId,
    mcp_tool_count: server.listTools().length,
    credential_source: await describeCredentialSource(ctx.globals, ctx.cwd),
  };
}

export function formatSupportDiagnosticsTable(diagnostics: SupportDiagnostics): string[] {
  const lines = [
    `package: ${diagnostics.package_name} ${diagnostics.package_version}`,
    `runtime: ${diagnostics.runtime}`,
    `platform: ${diagnostics.platform.os} ${diagnostics.platform.arch}`,
    `config_path: ${diagnostics.config_path}`,
    `env_file_path: ${diagnostics.env_file_path}`,
    `gateway_url: ${diagnostics.gateway_url}`,
    `request_id: ${diagnostics.request_id}`,
    `mcp_tool_count: ${diagnostics.mcp_tool_count}`,
    `credential_source: ${JSON.stringify(diagnostics.credential_source)}`,
  ];
  if (diagnostics.credential_source.profile) {
    lines.push(`profile: ${diagnostics.credential_source.profile}`);
  }
  return lines;
}
