import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { readJsonBody } from "../automation.js";
import { listConfigEntries, resolveConfigValue, setConfigValue, unsetConfigValue } from "../config.js";
import { commandPath, type CliContext, withGateway } from "../context.js";
import { assertApiKeyShape, resolveApiKey, resolvedDefaultsForDoctor } from "../credentials.js";
import { runAgentMiddlewareDoctorCheck } from "../doctor-agent-middleware.js";
import { packageVersion, runAgentMcpChecks } from "../doctor-agent.js";
import { runCompletionCatalogDoctorChecks } from "../../doctor-completion.js";
import { consumeBooleanFlag, consumeFlag, parseCliArgv } from "../globals.js";
import { helpForCommand } from "../help.js";
import { maskApiKey, redactConfigValue, redactSensitiveFields } from "../redact.js";
import {
  mergeMcpToolPolicy,
  parseMcpToolAllowlist,
  parseMcpToolPolicy,
  resolveMcpToolPolicy,
} from "../mcp-policy.js";
import {
  parseMcpInstallFormat,
  parseMcpInstallHost,
  parseMcpInstallScope,
  planMcpInstall,
} from "../mcp-install.js";
import { verifyMcpInstallPlan } from "../mcp-verify-config.js";
import { buildSupportDiagnostics, formatSupportDiagnosticsTable } from "../support-diagnostics.js";
import { CliError, type CommandResult } from "../types.js";
import { main as runInitMain } from "../../init.js";
import { parseCompletionInitArgs, scaffoldCompletionInit } from "../../completion-init.js";
import { parseProjectInitArgv, runProjectInit } from "../../project-init.js";
import {
  copyTemplateToDirectory,
  normalizeTemplateId,
  templateInitUsage,
} from "../../template-init.js";
import { parseArgs as parseLoginArgs, runLogin, type LoginOptions, type LoginResult } from "../../login.js";
import { main as runMcpServerMain } from "../../mcp-server.js";
import { PaybondMCPServer } from "../../mcp-server.js";

declare const process: {
  stdin: NodeJS.ReadableStream;
  version: string;
  env: Record<string, string | undefined>;
  cwd(): string;
};

async function readJsonFile(filePath: string): Promise<Record<string, unknown>> {
  return readJsonBody(filePath, process.stdin);
}

function loginResultData(result: LoginResult): Record<string, unknown> {
  const data: Record<string, unknown> = {
    env_file: result.envPath,
    key_masked: result.keyMasked,
    key_written: result.keyWritten,
    environment: result.environment,
    tenant_id: result.tenantId,
    tenant_uuid: result.tenantUuid,
    verification_uri: result.verificationUri,
    user_code: result.userCode,
  };
  if (result.expiresAt) {
    data.expires_at = result.expiresAt;
  }
  return data;
}

export async function handleLogin(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let parsed: LoginOptions | "help";
  try {
    parsed = parseLoginArgs(["login", ...argv]);
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "validation",
      code: "cli.login.rejected",
    });
  }
  if (parsed === "help") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  const options: LoginOptions = {
    ...parsed,
    gateway: ctx.globals.gateway,
    envFile: ctx.globals.envFile,
    noOpen: ctx.globals.noOpen,
  };
  let result: LoginResult;
  try {
    result = await runLogin(options, {
      cwd: ctx.cwd,
      fetch: ctx.fetch,
      humanOutput: ctx.globals.format !== "json",
      stdout: {
        write(chunk: string): boolean {
          ctx.stdout.write(chunk);
          return true;
        },
      },
      stderr: {
        write(chunk: string): boolean {
          ctx.stderr.write(chunk);
          return true;
        },
      },
      sleep: ctx.deps.sleep,
      openBrowser: ctx.deps.openBrowser,
      now: ctx.deps.now,
    });
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "validation",
      code: "cli.login.failed",
    });
  }
  return { data: loginResultData(result) };
}

export async function handleInitWizard(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let parsed: ReturnType<typeof parseProjectInitArgv>;
  try {
    parsed = parseProjectInitArgv(argv);
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "usage",
      code: "cli.usage.invalid_init",
    });
  }
  if (parsed === "help") {
    throw new CliError(templateInitUsage(), { category: "usage", code: "cli.help" });
  }
  try {
    if (parsed.template) {
      const result = await copyTemplateToDirectory({
        cwd: ctx.cwd,
        templateId: normalizeTemplateId(parsed.template),
        framework: parsed.framework,
        force: parsed.force,
        writeStdout(line) {
          if (ctx.globals.format !== "json") {
            ctx.stdout.write(`${line}\n`);
          }
        },
      });
      return { data: result };
    }
    const { template: _template, ...wizardOptions } = parsed;
    const result = await runProjectInit({
      cwd: ctx.cwd,
      ...wizardOptions,
      writeStdout(line) {
        if (ctx.globals.format !== "json") {
          ctx.stdout.write(`${line}\n`);
        }
      },
    });
    return { data: result };
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "validation",
      code: "cli.init.failed",
    });
  }
}

export async function handleInitGuardrail(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  return handleInitScaffold(ctx, argv, "paid-tool-guard", "paybond-paid-tool-guard.ts");
}

export async function handleInitAgentMiddleware(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  return handleInitScaffold(ctx, argv, "agent-middleware", "paybond-agent-middleware.ts");
}

async function handleInitScaffold(
  ctx: CliContext,
  argv: string[],
  defaultPreset: "paid-tool-guard" | "agent-middleware",
  defaultOut: string,
): Promise<CommandResult> {
  const code = await runInitMain(["--preset", defaultPreset, ...argv]);
  if (code !== 0) {
    throw new CliError(`init ${defaultPreset} failed`, { category: "validation", code: "cli.init.failed", exitCode: code });
  }
  const outFlag = consumeFlag(argv, "--out");
  const frameworkFlag = consumeFlag(argv, "--framework");
  return {
    data: {
      out: outFlag.value ?? defaultOut,
      preset: defaultPreset,
      framework: frameworkFlag.value ?? (defaultPreset === "agent-middleware" ? "generic" : "provider-agnostic"),
      bytes_written: true,
      completion_preset: "cost_and_completion",
    },
  };
}

export async function handleInitCompletion(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let parsed;
  try {
    const result = parseCompletionInitArgs(argv);
    if (result === "help") {
      throw new CliError("help", { category: "usage", code: "cli.help" });
    }
    parsed = result;
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "usage",
      code: "cli.usage.invalid_init_completion",
    });
  }
  try {
    await scaffoldCompletionInit(parsed);
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "validation",
      code: "cli.init.failed",
    });
  }
  return {
    data: {
      out: parsed.out,
      preset: parsed.preset,
      bytes_written: true,
    },
  };
}

export function mcpServeArgvMatches(argv: string[]): boolean {
  try {
    const { command } = parseCliArgv(argv);
    return command.length >= 2 && command[0] === "mcp" && command[1] === "serve";
  } catch {
    return false;
  }
}

function isMcpServeHelpCommand(command: string[]): boolean {
  return command.length === 0 || command.includes("--help") || command.includes("-h");
}

/** Run the blocking MCP stdio server. Must not run through the async CLI dispatcher. */
export function runMcpServeCommandSync(
  argv: string[],
  writers: {
    stdout: { write(chunk: string): boolean };
    stderr: { write(chunk: string): boolean };
  },
): number {
  let command: string[];
  try {
    ({ command } = parseCliArgv(argv));
  } catch (err) {
    const message = err instanceof CliError ? err.message : String(err);
    writers.stderr.write(`${message}\n`);
    return err instanceof CliError ? err.exitCode : 1;
  }

  if (isMcpServeHelpCommand(command)) {
    const helpPath = command.filter((part) => part !== "--help" && part !== "-h").join(" ") || "mcp serve";
    writers.stdout.write(`${helpForCommand(helpPath)}\n`);
    return 0;
  }

  const rest = command.slice(2);
  if (rest.length > 0 && rest[0] !== "--help" && rest[0] !== "-h") {
    writers.stderr.write(`unexpected arguments: ${rest.join(" ")}\n`);
    return 2;
  }

  writers.stderr.write("Starting Paybond MCP stdio server (stdout is reserved for MCP JSON-RPC).\n");
  const code = runMcpServerMain([]);
  return code;
}

export async function handleMcpServe(_ctx: CliContext, _argv: string[]): Promise<CommandResult> {
  throw new CliError("mcp serve must run via the sync CLI entrypoint (not the async dispatcher)", {
    category: "internal",
    code: "cli.mcp.serve_async_forbidden",
  });
}

export async function handleMcpTools(ctx: CliContext): Promise<CommandResult> {
  const server = new PaybondMCPServer({ gatewayBaseUrl: ctx.globals.gateway, apiKey: "paybond_sk_sandbox_redacted_redacted_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" });
  const tools = server.listTools().map((tool) => ({
    name: tool.name,
    title: tool.title ?? tool.name,
    description: tool.description,
  }));
  return { data: { tools } };
}

export async function handleMcpInstall(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const hostFlag = consumeFlag(argv, "--host");
  const formatFlag = consumeFlag(argv, "--format");
  const scopeFlag = consumeFlag(argv, "--scope");
  const outFlag = consumeFlag(argv, "--out");
  const envFileFlag = consumeFlag(argv, "--env-file");
  const toolPolicyFlag = consumeFlag(argv, "--tool-policy");
  const toolAllowlistFlag = consumeFlag(argv, "--tool-allowlist");
  let format: ReturnType<typeof parseMcpInstallFormat>;
  let scope: ReturnType<typeof parseMcpInstallScope>;
  let installHost: ReturnType<typeof parseMcpInstallHost>;
  let toolPolicy: ReturnType<typeof mergeMcpToolPolicy>;
  try {
    installHost = parseMcpInstallHost(hostFlag.value);
    format = parseMcpInstallFormat(formatFlag.value, installHost);
    scope = parseMcpInstallScope(scopeFlag.value);
    toolPolicy = mergeMcpToolPolicy(
      parseMcpToolPolicy(toolPolicyFlag.value),
      parseMcpToolAllowlist(toolAllowlistFlag.value),
    );
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "usage",
      code: "cli.usage.invalid_mcp_install",
    });
  }
  const plan = planMcpInstall({
    host: installHost,
    scope,
    format,
    envFile: envFileFlag.value ?? ctx.globals.envFile,
    out: outFlag.value,
    cwd: ctx.cwd,
    home: process.env.HOME ?? process.env.USERPROFILE ?? ctx.cwd,
    toolPolicy: resolveMcpToolPolicy(toolPolicy),
  });
  if (plan.printed) {
    if (ctx.globals.format !== "json") {
      ctx.stdout.write(plan.payload);
    }
  } else {
    const configPath = plan.configPath!;
    await mkdir(path.dirname(configPath), { recursive: true });
    const { writeAtomicFileAsync } = await import("../automation.js");
    await writeAtomicFileAsync(configPath, plan.payload, 0o600);
  }
  const data: Record<string, unknown> = {
    host: plan.host,
    scope: plan.scope,
    format: plan.format,
    config_path: plan.configPath,
    server_command: plan.serverCommand.join(" "),
    printed: plan.printed,
  };
  if (plan.toolPolicy?.policy) {
    data.tool_policy = plan.toolPolicy.policy;
    if (plan.toolPolicy.allowlist.length > 0) {
      data.tool_allowlist = [...plan.toolPolicy.allowlist];
    }
  }
  if (plan.printed && ctx.globals.format === "json") {
    data.payload = plan.payload;
  }
  return { data };
}

export async function handleMcpVerifyConfig(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const hostFlag = consumeFlag(argv, "--host");
  const formatFlag = consumeFlag(argv, "--format");
  const envFileFlag = consumeFlag(argv, "--env-file");
  const configFlag = consumeFlag(argv, "--config");
  let installHost: ReturnType<typeof parseMcpInstallHost>;
  let format: ReturnType<typeof parseMcpInstallFormat>;
  try {
    installHost = parseMcpInstallHost(hostFlag.value);
    format = parseMcpInstallFormat(formatFlag.value, installHost);
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "usage",
      code: "cli.usage.invalid_mcp_verify_config",
    });
  }
  const result = await verifyMcpInstallPlan({
    host: installHost,
    format,
    envFile: envFileFlag.value ?? ctx.globals.envFile,
    cwd: ctx.cwd,
    home: process.env.HOME ?? process.env.USERPROFILE ?? ctx.cwd,
    configPath: configFlag.value,
  });
  return {
    data: {
      ok: result.ok,
      host: result.host,
      source: result.source,
      config_path: result.configPath,
      message: result.message,
      issues: result.issues,
      tool_policy: result.toolPolicy?.policy ?? null,
    },
  };
}

export async function handleDoctor(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const agentFlag = consumeBooleanFlag(argv, "--agent");
  const hostFlag = consumeFlag(agentFlag.rest, "--host");
  const checks: Array<{ name: string; ok: boolean; message: string; details?: Record<string, unknown> }> = [];
  const defaults = resolvedDefaultsForDoctor(ctx.globals);
  checks.push({
    name: "runtime",
    ok: true,
    message: `node ${process.version}`,
  });
  checks.push({
    name: "package",
    ok: true,
    message: "@paybond/kit",
    details: { version: packageVersion() },
  });

  const envPath = path.isAbsolute(defaults.envFile)
    ? path.resolve(defaults.envFile)
    : path.resolve(ctx.cwd, defaults.envFile);
  try {
    await readFile(envPath, "utf8");
    checks.push({ name: "env_file", ok: true, message: envPath });
  } catch {
    checks.push({ name: "env_file", ok: false, message: `env file not found: ${envPath}` });
  }

  let apiKey = "";
  try {
    apiKey = await resolveApiKey(ctx.globals, ctx.cwd);
    assertApiKeyShape(apiKey);
    checks.push({ name: "key_shape", ok: true, message: maskApiKey(apiKey) });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    checks.push({ name: "key_shape", ok: false, message });
  }

  if (apiKey) {
    try {
      await withGateway(ctx, async (gateway) => {
        await gateway.getJson("/v1/auth/principal");
        return { data: {} };
      });
      checks.push({ name: "principal", ok: true, message: "principal lookup succeeded" });
    } catch (err) {
      checks.push({
        name: "principal",
        ok: false,
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  if (agentFlag.present) {
    if (!apiKey) {
      for (const name of [
        "mcp_host_config",
        "mcp_env_resolution",
        "mcp_launch",
        "mcp_initialize",
        "mcp_tools_list",
        "mcp_tool_schemas",
        "mcp_stdout_purity",
      ]) {
        checks.push({ name, ok: false, message: "skipped MCP probe (missing API key)" });
      }
    } else {
      const agentChecks = await runAgentMcpChecks({
        envFile: defaults.envFile,
        cwd: ctx.cwd,
        host: hostFlag.value ?? "generic",
      });
      checks.push(...agentChecks);
    }
    if (apiKey) {
      checks.push(await runAgentMiddlewareDoctorCheck(ctx, apiKey));
    } else {
      checks.push({
        name: "agent_middleware_smoke",
        ok: false,
        message: "skipped (missing API key)",
      });
    }
  }

  const completionChecks = await runCompletionCatalogDoctorChecks({
    cwd: ctx.cwd,
    gateway: apiKey
      ? {
          async getJson(path: string) {
            const result = await withGateway(ctx, async (gateway) => {
              const body = await gateway.getJson(path);
              return { data: body };
            });
            return result.data as Record<string, unknown>;
          },
        }
      : undefined,
  });
  checks.push(...completionChecks);

  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  return { data: { checks, summary } };
}

export async function handleConfig(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  if (subcommand === "list") {
    const entries = await listConfigEntries(ctx.globals.profile);
    return { data: { entries } };
  }
  if (subcommand === "get") {
    const key = argv[0];
    if (!key) {
      throw new CliError("config get requires <key>", { category: "usage", code: "cli.usage.missing_key" });
    }
    const value = await resolveConfigValue(key, ctx.globals.profile);
    if (value === undefined) {
      throw new CliError(`config key not found: ${key}`, { category: "not_found", code: "cli.config.not_found" });
    }
    return { data: { key, value: redactConfigValue(key, value) } };
  }
  if (subcommand === "set") {
    const key = argv[0];
    const value = argv[1];
    if (!key || value === undefined) {
      throw new CliError("config set requires <key> <value>", { category: "usage", code: "cli.usage.missing_args" });
    }
    await setConfigValue(key, value, ctx.globals.profile);
    return { data: { key, set: true } };
  }
  if (subcommand === "unset") {
    const key = argv[0];
    if (!key) {
      throw new CliError("config unset requires <key>", { category: "usage", code: "cli.usage.missing_key" });
    }
    const removed = await unsetConfigValue(key, ctx.globals.profile);
    return { data: { key, removed } };
  }
  throw new CliError(`unknown config subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
}

export async function handleWhoami(ctx: CliContext): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    const principal = await gateway.getJson("/v1/auth/principal");
    const stripped = { ...principal };
    delete stripped.access_token;
    delete stripped.refresh_token;
    return {
      data: {
        tenant_id: String(principal.tenant_id ?? ""),
        tenant_uuid: String(principal.tenant_uuid ?? ""),
        environment: String(principal.environment ?? ""),
        service_account_role: String(principal.service_account_role ?? ""),
        principal: stripped,
      },
    };
  });
}

export async function handleVersion(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const verboseFlag = consumeBooleanFlag(argv, "--verbose");
  if (verboseFlag.rest.length > 0) {
    throw new CliError(`unexpected arguments: ${verboseFlag.rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (verboseFlag.present) {
    const diagnostics = await buildSupportDiagnostics(ctx);
    return { data: diagnostics };
  }
  return { data: { version: packageVersion() } };
}

export async function handleDiagnose(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const redactedFlag = consumeBooleanFlag(argv, "--redacted");
  if (redactedFlag.rest.length > 0) {
    throw new CliError(`unexpected arguments: ${redactedFlag.rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!redactedFlag.present) {
    throw new CliError("paybond diagnose requires --redacted for support bundles", {
      category: "usage",
      code: "cli.diagnose.redacted_required",
    });
  }
  const diagnostics = await buildSupportDiagnostics(ctx);
  return {
    data: {
      redacted: true,
      diagnostics,
      lines: formatSupportDiagnosticsTable(diagnostics),
    },
  };
}

export { readJsonFile, commandPath };
