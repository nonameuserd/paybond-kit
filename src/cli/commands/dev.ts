import { resolve } from "node:path";

import {
  activateOfflineDevMode,
  createOfflineDevGatewayFetch,
  isProductionApiKey,
} from "../../dev/offline-gateway.js";
import { runDevWiremockUp } from "../../dev/wiremock-up.js";
import {
  appendDevAuditLog,
  activateDevTraceCollector,
  buildDevStartupBannerLines,
  DEV_DEFAULT_POLICY_FILE,
  DEV_DEFAULT_PRESET,
  devTraceUrl,
  finalizeDevTraceCollector,
  recordSmokeTraceEvent,
} from "../../dev/trace-buffer.js";
import { startDevTraceServer } from "../../dev/trace-server.js";
import { getSolutionSmokeDefaults } from "../../solutions/catalog.js";
import { describeCredentialSource, loadEnvFile } from "../credentials.js";
import { colorize, shouldUseColor } from "../color.js";
import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import type { CliContext } from "../context.js";
import { CliError, type CommandResult } from "../types.js";
import { handleAgentSandboxSmoke } from "./agent.js";
import { handleLogin } from "./setup.js";
import { handlePolicyInit, handlePolicyValidateTools } from "./policy.js";
import { scheduleCliCommandTelemetry } from "../telemetry.js";

function devCliError(
  message: string,
  options: { code: string; category?: "usage" | "validation"; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

function appendDevLoopTraceLine(
  checklistLines: string[],
  traceUrl: string,
  globals: CliContext["globals"],
): string[] {
  const useColor = shouldUseColor(globals);
  return [...checklistLines, colorize(`✓ Trace → ${traceUrl}`, "green", useColor)];
}

function writeDevStartupBanner(ctx: CliContext): void {
  for (const line of buildDevStartupBannerLines()) {
    ctx.stderr.write(`${line}\n`);
  }
}

type OfflineDevSession = {
  ctx: CliContext;
  restore: () => void;
};

function rejectOfflineWithProductionKey(apiKey: string | undefined): void {
  const trimmed = apiKey?.trim();
  if (trimmed && isProductionApiKey(trimmed)) {
    throw devCliError(
      "offline dev mode cannot be used with production API keys (paybond_sk_live_...); unset PAYBOND_API_KEY or use a sandbox key",
      { code: "cli.dev.offline_production_key", category: "validation" },
    );
  }
}

async function assertOfflineDevCredentialsSafe(ctx: CliContext): Promise<void> {
  rejectOfflineWithProductionKey(process.env.PAYBOND_API_KEY);
  if (process.env.PAYBOND_API_KEY?.trim()) {
    return;
  }
  const fromFile = await loadEnvFile(ctx.globals.envFile, ctx.cwd);
  rejectOfflineWithProductionKey(fromFile);
}

function beginOfflineDevSession(ctx: CliContext): OfflineDevSession {
  const { restore } = activateOfflineDevMode();
  return {
    ctx: {
      ...ctx,
      fetch: createOfflineDevGatewayFetch(),
    },
    restore,
  };
}

async function finalizeSmokeResult(
  ctx: CliContext,
  preset: string,
  smokeResult: CommandResult,
  offline = false,
): Promise<CommandResult> {
  const bind = smokeResult.data.bind as Record<string, unknown>;
  const execute = smokeResult.data.execute as Record<string, unknown>;
  const defaults = getSolutionSmokeDefaults(preset);
  const resultBody =
    execute.tool_result && typeof execute.tool_result === "object" && !Array.isArray(execute.tool_result)
      ? (execute.tool_result as Record<string, unknown>)
      : defaults.resultBody;
  const traceEvent =
    finalizeDevTraceCollector(resultBody, ctx.cwd) ??
    recordSmokeTraceEvent(
      {
        preset,
        bind,
        execute,
        resultBody,
      },
      ctx.cwd,
    );
  const auditLog = await appendDevAuditLog(ctx.cwd, {
    kind: "dev.smoke",
    recorded_at: traceEvent.recorded_at,
    preset,
    bind,
    execute,
    offline,
  });
  const traceUrl = devTraceUrl();
  return {
    data: {
      ...smokeResult.data,
      offline,
      trace_url: `${traceUrl}/runs/${encodeURIComponent(traceEvent.id)}`,
      audit_log: auditLog,
    },
    warnings: smokeResult.warnings,
  };
}

async function runDevSmokeCore(
  ctx: CliContext,
  preset: string,
  offline: boolean,
): Promise<CommandResult> {
  activateDevTraceCollector({ preset, cwd: ctx.cwd });
  const smokeArgv = ["--preset", preset];
  const smokeResult = await handleAgentSandboxSmoke(ctx, smokeArgv);
  return finalizeSmokeResult(ctx, preset, smokeResult, offline);
}

export async function handleDevSmoke(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const offlineFlag = consumeBooleanFlag(rest, "--offline");
  rest = offlineFlag.rest;
  const presetFlag = consumeFlag(rest, "--preset");
  if (presetFlag.rest.length > 0) {
    throw devCliError(`unexpected arguments: ${presetFlag.rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const preset = presetFlag.value?.trim() || DEV_DEFAULT_PRESET;

  if (offlineFlag.present) {
    await assertOfflineDevCredentialsSafe(ctx);
  }
  const offlineSession = offlineFlag.present ? beginOfflineDevSession(ctx) : null;
  try {
    const result = await runDevSmokeCore(offlineSession?.ctx ?? ctx, preset, offlineFlag.present);
    scheduleCliCommandTelemetry(offlineSession?.ctx ?? ctx, {
      commandPath: "dev smoke",
      offline: offlineFlag.present,
    });
    return result;
  } finally {
    offlineSession?.restore();
  }
}

export async function handleDevTrace(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  const portFlag = consumeFlag(argv, "--port");
  if (portFlag.rest.length > 0) {
    throw devCliError(`unexpected arguments: ${portFlag.rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const port = portFlag.value ? Number.parseInt(portFlag.value, 10) : undefined;
  if (port !== undefined && (!Number.isFinite(port) || port <= 0 || port > 65535)) {
    throw devCliError("dev trace --port must be a valid TCP port", {
      code: "cli.usage.invalid_port",
      category: "usage",
    });
  }

  const credentials = await describeCredentialSource(ctx.globals, ctx.cwd);
  if (credentials.source === "missing") {
    ctx.stderr.write(
      "No PAYBOND_API_KEY configured. Run paybond dev smoke --offline or paybond login, then paybond dev smoke.\n",
    );
  }

  let traceUrl = devTraceUrl(port);
  const server = await startDevTraceServer({
    port,
    cwd: ctx.cwd,
    envFile: ctx.globals.envFile,
    hasCredentials: credentials.source !== "missing",
    onListen(url) {
      traceUrl = url;
      ctx.stderr.write(`Paybond dev trace dashboard listening on ${url}\n`);
      ctx.stderr.write("Press Ctrl+C to stop.\n");
    },
  });

  await new Promise<void>((resolvePromise) => {
    const shutdown = () => {
      server.close(() => resolvePromise());
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });

  ctx.stderr.write("Trace dashboard stopped.\n");

  return {
    data: {
      trace_url: traceUrl,
      port: port ?? devTraceUrl().match(/:(\d+)/)?.[1] ?? "9477",
      events: [],
    },
  };
}

export async function handleDevUp(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const downFlag = consumeBooleanFlag(rest, "--down");
  rest = downFlag.rest;
  const portFlag = consumeFlag(rest, "--port");
  if (portFlag.rest.length > 0) {
    throw devCliError(`unexpected arguments: ${portFlag.rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const port = portFlag.value ? Number.parseInt(portFlag.value, 10) : undefined;
  if (port !== undefined && (!Number.isFinite(port) || port <= 0 || port > 65535)) {
    throw devCliError("dev up --port must be a valid TCP port", {
      code: "cli.usage.invalid_port",
      category: "usage",
    });
  }

  try {
    const result = await runDevWiremockUp({ port, down: downFlag.present });
    if (result.status === "stopped") {
      ctx.stderr.write(`Stopped WireMock container ${result.container_name}.\n`);
    } else if (result.status === "already_running") {
      ctx.stderr.write(`WireMock already running at ${result.gateway_url}\n`);
    } else {
      ctx.stderr.write(`WireMock Gateway listening at ${result.gateway_url}\n`);
      ctx.stderr.write(`Mappings loaded from ${result.wiremock_dir}\n`);
    }
    if (result.next_commands.length > 0) {
      ctx.stderr.write("Next:\n");
      for (const command of result.next_commands) {
        ctx.stderr.write(`  ${command}\n`);
      }
    }
    return { data: result };
  } catch (err) {
    throw devCliError(err instanceof Error ? err.message : String(err), {
      code: "cli.dev.wiremock_failed",
      category: "validation",
    });
  }
}

export async function handleDevLoop(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const offlineFlag = consumeBooleanFlag(rest, "--offline");
  rest = offlineFlag.rest;
  const policyFlag = consumeFlag(rest, "--policy-file");
  rest = policyFlag.rest;
  const noLoginFlag = consumeBooleanFlag(rest, "--no-login");
  rest = noLoginFlag.rest;
  if (rest.length > 0) {
    throw devCliError(`unexpected arguments: ${rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }

  const policyFile = policyFlag.value?.trim() || DEV_DEFAULT_POLICY_FILE;
  const steps: Array<Record<string, unknown>> = [];
  const bannerLines = buildDevStartupBannerLines();
  if (offlineFlag.present) {
    await assertOfflineDevCredentialsSafe(ctx);
  }
  const offlineSession = offlineFlag.present ? beginOfflineDevSession(ctx) : null;
  const activeCtx = offlineSession?.ctx ?? ctx;

  writeDevStartupBanner(ctx);

  try {
    if (offlineFlag.present) {
      steps.push({
        name: "login",
        ok: true,
        skipped: true,
        message: "offline mode (no PAYBOND_API_KEY required)",
      });
    } else {
      const credentials = await describeCredentialSource(ctx.globals, ctx.cwd);
      if (credentials.source === "missing" && !noLoginFlag.present) {
        const loginResult = await handleLogin(ctx, []);
        steps.push({ name: "login", ok: true, data: loginResult.data });
      } else {
        steps.push({
          name: "login",
          ok: credentials.source !== "missing",
          skipped: credentials.source !== "missing",
          message:
            credentials.source === "missing" ? "missing credentials; run paybond login" : "credentials present",
        });
        if (credentials.source === "missing") {
          throw devCliError(
            "dev loop requires sandbox credentials; run paybond login, pass --offline, or omit --no-login",
            {
              code: "cli.dev.missing_credentials",
              category: "validation",
              details: { steps },
            },
          );
        }
      }
    }

    const initResult = await handlePolicyInit(activeCtx, [
      "--preset",
      DEV_DEFAULT_PRESET,
      "--out",
      policyFile,
      "--force",
    ]);
    steps.push({ name: "policy_init", ok: true, data: initResult.data });

    const validateResult = await handlePolicyValidateTools(activeCtx, [
      "--file",
      policyFile,
      "--local-only",
    ]);
    const validateData = validateResult.data as Record<string, unknown>;
    steps.push({
      name: "validate_tools",
      ok: validateData.valid === true,
      data: validateData,
    });
    if (validateData.valid !== true) {
      throw devCliError("dev loop failed policy validate-tools --local-only", {
        code: "cli.dev.validate_failed",
        category: "validation",
        details: { steps },
      });
    }

    const smokeResult = await runDevSmokeCore(activeCtx, DEV_DEFAULT_PRESET, offlineFlag.present);
    steps.push({ name: "smoke", ok: true, data: smokeResult.data });

    const traceUrl = String(smokeResult.data.trace_url ?? devTraceUrl());
    const auditLog = String(smokeResult.data.audit_log ?? resolve(ctx.cwd, ".paybond/dev-audit.jsonl"));
    const smokeChecklist = Array.isArray(smokeResult.data.checklist_lines)
      ? (smokeResult.data.checklist_lines as string[])
      : [];
    scheduleCliCommandTelemetry(activeCtx, {
      commandPath: "dev loop",
      offline: offlineFlag.present,
    });
    return {
      data: {
        offline: offlineFlag.present,
        steps,
        smoke: smokeResult.data,
        trace_url: traceUrl,
        audit_log: auditLog,
        banner_lines: bannerLines,
        checklist_lines: appendDevLoopTraceLine(smokeChecklist, traceUrl, ctx.globals),
      },
      warnings: smokeResult.warnings,
    };
  } finally {
    offlineSession?.restore();
  }
}

export async function handleDev(
  ctx: CliContext,
  subcommand: string,
  argv: string[],
): Promise<CommandResult> {
  if (subcommand === "smoke") {
    return handleDevSmoke(ctx, argv);
  }
  if (subcommand === "trace") {
    return handleDevTrace(ctx, argv);
  }
  if (subcommand === "loop") {
    return handleDevLoop(ctx, argv);
  }
  if (subcommand === "up") {
    return handleDevUp(ctx, argv);
  }
  throw devCliError(`unknown dev subcommand: dev ${subcommand}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
