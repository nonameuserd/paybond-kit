import { existsSync, readFileSync, statSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  DEV_AUDIT_FILE,
  DEV_DEFAULT_POLICY_FILE,
  DEV_TRACE_DEFAULT_PORT,
  DEV_TRACE_FILE,
  devTraceUrl,
  listDevTraceEvents,
} from "../../dev/trace-buffer.js";
import { loadEnvFile, resolveApiKeyWithMeta } from "../credentials.js";
import type { CliContext } from "../context.js";
import { consumeFlag } from "../globals.js";
import { KIT_HAPPY_PATH_COMMANDS } from "../next-actions.js";
import { maskApiKey } from "../redact.js";
import { CliError, type CommandResult } from "../types.js";

function resolvePath(cwd: string, relative: string): string {
  return resolve(cwd, relative);
}

function fileMeta(path: string): { path: string; present: boolean; mtime?: string; bytes?: number } {
  if (!existsSync(path)) {
    return { path, present: false };
  }
  const st = statSync(path);
  return {
    path,
    present: true,
    mtime: st.mtime.toISOString(),
    bytes: st.size,
  };
}

function lastJsonlEntry(path: string): Record<string, unknown> | undefined {
  if (!existsSync(path)) {
    return undefined;
  }
  const lines = readFileSync(path, "utf8")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const last = lines.at(-1);
  if (!last) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(last) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Summarize sandbox auth, policy file, last smoke, and local trace URL for Kit builders.
 * Tenant scope always comes from credentials — never from CLI tenant flags.
 */
export async function handleStatus(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  const policyFlag = consumeFlag(argv, "--policy-file");
  const rest = policyFlag.rest;
  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }

  const policyPath = resolvePath(ctx.cwd, policyFlag.value?.trim() || DEV_DEFAULT_POLICY_FILE);
  const envPath = resolvePath(ctx.cwd, ctx.globals.envFile);
  const auditPath = join(ctx.cwd, DEV_AUDIT_FILE);
  const tracePath = join(ctx.cwd, DEV_TRACE_FILE);
  const traceUrl = devTraceUrl(DEV_TRACE_DEFAULT_PORT);

  let auth: Record<string, unknown> = {
    authenticated: false,
    source: "none",
    env_file: envPath,
    gateway: ctx.globals.gateway,
  };

  try {
    const resolved = await resolveApiKeyWithMeta(ctx.globals, ctx.cwd);
    auth = {
      authenticated: true,
      source: process.env.PAYBOND_API_KEY?.trim() ? "process_env" : "env_file",
      env_file: envPath,
      gateway: ctx.globals.gateway,
      key_masked: maskApiKey(resolved.apiKey),
      profile: ctx.globals.profile ?? null,
    };
    // Best-effort principal lookup — status remains useful offline if whoami fails.
    try {
      const { createGatewayClient } = await import("../context.js");
      const gateway = createGatewayClient(ctx.globals, resolved.apiKey, ctx.fetch);
      const principal = await gateway.getJson("/v1/auth/principal");
      auth = {
        ...auth,
        tenant_id: principal.tenant_id ?? principal.tenantId ?? null,
        tenant_uuid: principal.tenant_uuid ?? principal.tenantUuid ?? null,
        environment: principal.environment ?? null,
        service_account_role: principal.service_account_role ?? principal.role ?? null,
      };
    } catch {
      auth = { ...auth, principal_error: "unable to resolve principal; run paybond whoami" };
    }
  } catch {
    const fromFile = await loadEnvFile(ctx.globals.envFile, ctx.cwd);
    auth = {
      authenticated: false,
      source: fromFile ? "env_file_unreadable_shape" : "none",
      env_file: envPath,
      gateway: ctx.globals.gateway,
      next: "paybond login",
    };
  }

  const events = listDevTraceEvents(ctx.cwd);
  const lastEvent = events.at(-1);
  const lastAudit = lastJsonlEntry(auditPath);
  const lastSmoke =
    lastEvent || lastAudit
      ? {
          recorded_at: String(lastEvent?.recorded_at ?? lastAudit?.recorded_at ?? ""),
          operation: String(lastEvent?.operation ?? lastAudit?.operation ?? ""),
          authorized: Boolean(lastEvent?.authorized ?? lastAudit?.authorized ?? false),
          run_id: lastEvent?.run_id ?? lastAudit?.run_id ?? null,
          intent_id: lastEvent?.intent_id ?? lastAudit?.intent_id ?? null,
          source: lastEvent ? "dev-trace" : "dev-audit",
        }
      : null;

  const nextCommands = auth.authenticated
    ? ["paybond agent sandbox smoke --help", "paybond control", "paybond dev trace"]
    : ["paybond login", "paybond init", "paybond status"];

  return {
    data: {
      auth,
      policy: fileMeta(policyPath),
      last_smoke: lastSmoke,
      trace: {
        url: traceUrl,
        port: DEV_TRACE_DEFAULT_PORT,
        ...fileMeta(tracePath),
        event_count: events.length,
      },
      audit_log: fileMeta(auditPath),
      happy_path: [...KIT_HAPPY_PATH_COMMANDS],
      next_commands: nextCommands,
    },
  };
}

declare const process: { env: Record<string, string | undefined> };
