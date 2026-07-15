import { colorize, shouldUseColor } from "../color.js";
import type { CliContext } from "../context.js";
import { withGateway } from "../context.js";
import { resolveApiKey } from "../credentials.js";
import { requireSecureGatewayUrl } from "../../gateway-url.js";
import { CliError, type CommandResult, type ErrorCategory } from "../types.js";

/**
 * Destination / vault fields that must never appear on argv (CWE-214 / SEC-011).
 * Upsert is Console write-only; ready/doctor only read masked settlement config.
 */
export const FLUTTERWAVE_ARGV_BLOCKED_FLAGS = [
  "--secret-key",
  "--webhook-secret",
  "--client-id",
  "--client-secret",
  "--environment",
] as const;

export type FlutterwaveDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export type FlutterwaveSettlementConfigSnapshot = {
  allowed_rails?: string[];
  plan_id?: string;
  flutterwave_destination_configured?: boolean;
  flutterwave_environment?: string;
  flutterwave_label?: string;
  flutterwave_currency?: string;
  flutterwave_secret_key_configured?: boolean;
  flutterwave_webhook_secret_configured?: boolean;
  flutterwave_webhook_url?: string;
  rail_readiness?: Array<{
    rail?: string;
    ready?: boolean;
    enabled?: boolean;
    status?: string;
    reason_code?: string;
    message?: string;
  }>;
};

function flutterwaveCliError(
  message: string,
  options: { code: string; category?: ErrorCategory; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

/** True when an argv token is a blocked Flutterwave destination flag (exact or `--flag=value`). */
export function rejectsFlutterwaveSensitiveArgvFlag(arg: string): boolean {
  for (const flag of FLUTTERWAVE_ARGV_BLOCKED_FLAGS) {
    if (arg === flag || arg.startsWith(`${flag}=`)) {
      return true;
    }
  }
  return false;
}

/**
 * Reject process-visible Flutterwave destination material on argv (SEC-011).
 * Secret key / webhook secret / OAuth client credentials and environment remain Console write-only.
 */
export function assertNoFlutterwaveSensitiveArgv(argv: string[]): void {
  for (const arg of argv) {
    if (!rejectsFlutterwaveSensitiveArgvFlag(arg)) {
      continue;
    }
    const flag = FLUTTERWAVE_ARGV_BLOCKED_FLAGS.find(
      (candidate) => arg === candidate || arg.startsWith(`${candidate}=`),
    );
    throw flutterwaveCliError(
      `flutterwave CLI rejects ${flag ?? arg} on argv (visible in process listings); upsert destination credentials via Console → Configuration → Settlement (write-only)`,
      {
        code: "cli.flutterwave.argv_secret_forbidden",
        category: "usage",
        details: {
          flag: flag ?? arg,
          write_only: true,
          console_path: "/console/configuration/settlement",
        },
      },
    );
  }
}

function formatDoctorChecklistLine(check: FlutterwaveDoctorCheck, useColor: boolean): string {
  const prefix = check.ok ? colorize("✓", "green", useColor) : colorize("✗", "yellow", useColor);
  return `${prefix} ${check.name}: ${check.message}`;
}

/** Format Flutterwave ready/doctor checklist lines with a pass/fail summary. */
export function formatFlutterwaveDoctorChecklist(
  checks: FlutterwaveDoctorCheck[],
  useColor: boolean,
  label: "flutterwave ready" | "flutterwave doctor" = "flutterwave doctor",
): string[] {
  const lines = checks.map((check) => formatDoctorChecklistLine(check, useColor));
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(colorize(`${label}: ${summary}`, summary === "pass" ? "green" : "yellow", useColor));
  return lines;
}

/** Resolve Paybond gateway origin to the Flutterwave webhook base path for live or sandbox. */
export function resolveFlutterwaveWebhookAddress(
  gatewayBase: string,
  environment: "live" | "sandbox" = "sandbox",
): string {
  const secure = requireSecureGatewayUrl(gatewayBase.trim().replace(/\/$/, ""));
  return `${secure}/webhooks/${environment}/flutterwave`;
}

function allowedRails(config: FlutterwaveSettlementConfigSnapshot): string[] {
  return Array.isArray(config.allowed_rails) ? config.allowed_rails.map(String) : [];
}

function flutterwaveRailReadiness(config: FlutterwaveSettlementConfigSnapshot) {
  return config.rail_readiness?.find((entry) => entry.rail === "flutterwave_virtual_account");
}

function isLiveFlutterwaveEnvironment(environment: string | undefined): boolean {
  return (environment ?? "").trim().toLowerCase() === "live";
}

/**
 * Build settlement-config readiness checks for `paybond flutterwave ready`.
 * Pure so unit tests can exercise fixtures without Gateway I/O.
 */
export function buildFlutterwaveReadyChecks(
  config: FlutterwaveSettlementConfigSnapshot,
): FlutterwaveDoctorCheck[] {
  const rails = allowedRails(config);
  const railEnabled = rails.includes("flutterwave_virtual_account");
  const destinationOk = config.flutterwave_destination_configured === true;
  const secretKeyOk = config.flutterwave_secret_key_configured === true;
  const webhookSecretOk = config.flutterwave_webhook_secret_configured === true;
  const readiness = flutterwaveRailReadiness(config);
  const paidPlanBlocked = readiness?.reason_code === "flutterwave_paid_plan_required";

  const checks: FlutterwaveDoctorCheck[] = [
    {
      name: "rail_enabled",
      ok: railEnabled,
      message: railEnabled
        ? "flutterwave_virtual_account is in allowed_rails"
        : "enable flutterwave_virtual_account in Console → Configuration → Settlement",
      details: { allowed_rails: rails },
    },
    {
      name: "destination_configured",
      ok: destinationOk,
      message: destinationOk
        ? `destination active (${config.flutterwave_label || config.flutterwave_currency || "Flutterwave"})`
        : "save Flutterwave destination credentials in Console → Configuration → Settlement",
      details: {
        label: config.flutterwave_label,
        currency: config.flutterwave_currency,
        environment: config.flutterwave_environment,
      },
    },
    {
      name: "secret_key",
      ok: secretKeyOk,
      message: secretKeyOk
        ? "tenant secret key configured"
        : "upsert Flutterwave secret key via Console destination form (write-only; never --secret-key on argv)",
    },
    {
      name: "webhook_secret",
      ok: webhookSecretOk,
      message: webhookSecretOk
        ? "webhook secret configured"
        : "upsert Flutterwave webhook secret via Console destination form (write-only; never --webhook-secret on argv)",
    },
  ];

  if (paidPlanBlocked) {
    checks.push({
      name: "paid_plan",
      ok: false,
      message:
        readiness?.message ??
        "Live Flutterwave settlement destinations are only available on paid self-serve plans.",
      details: {
        reason_code: readiness?.reason_code,
        plan_id: config.plan_id,
      },
    });
  } else {
    const live = isLiveFlutterwaveEnvironment(config.flutterwave_environment);
    checks.push({
      name: "paid_plan",
      ok: true,
      message: live
        ? "live destination allowed on current plan"
        : "paid-plan gate applies to live Flutterwave destinations only",
      details: { plan_id: config.plan_id, environment: config.flutterwave_environment },
    });
  }

  if (!readiness) {
    checks.push({
      name: "rail_readiness",
      ok: false,
      message:
        "flutterwave_virtual_account readiness unavailable (login and save a Flutterwave destination)",
    });
  } else {
    checks.push({
      name: "rail_readiness",
      ok: readiness.ready === true && railEnabled,
      message:
        readiness.message ??
        (readiness.ready && railEnabled
          ? "flutterwave_virtual_account ready"
          : readiness.ready
            ? "destination ready — enable flutterwave_virtual_account in allowed_rails"
            : "flutterwave_virtual_account not ready"),
      details: {
        rail: readiness.rail,
        ready: readiness.ready,
        enabled: readiness.enabled,
        status: readiness.status,
        reason_code: readiness.reason_code,
      },
    });
  }

  return checks;
}

export type FlutterwaveDoctorOptions = {
  gatewayBase: string;
  /** Tenant realm from GET /v1/auth/principal when available (`sandbox` | `live`). */
  tenantEnvironment?: string;
};

/**
 * Expand ready checks with webhook URL checklist, sandbox/live mismatch hints,
 * and Console destination upsert pointer.
 */
export function buildFlutterwaveDoctorChecks(
  config: FlutterwaveSettlementConfigSnapshot,
  options: FlutterwaveDoctorOptions,
): FlutterwaveDoctorCheck[] {
  const checks = buildFlutterwaveReadyChecks(config);
  const gatewayBase = options.gatewayBase.trim().replace(/\/$/, "");
  const liveUrl = resolveFlutterwaveWebhookAddress(gatewayBase, "live");
  const sandboxUrl = resolveFlutterwaveWebhookAddress(gatewayBase, "sandbox");
  const flutterwaveEnv = (config.flutterwave_environment ?? "").trim().toLowerCase();
  const basePath = flutterwaveEnv === "live" ? liveUrl : sandboxUrl;
  // The Gateway appends a per-destination token to the webhook path; prefer the
  // configured URL (token-scoped) when a destination is saved.
  const configured = (config.flutterwave_webhook_url ?? "").trim();

  checks.push({
    name: "webhook_endpoint",
    ok: true,
    message: configured
      ? `register webhook at ${configured}`
      : `register webhook at ${basePath}/<destination-token> (token issued when you save a destination)`,
    details: {
      sandbox: sandboxUrl,
      live: liveUrl,
      configured: configured || undefined,
      events: ["charge.completed", "transfer.completed", "transfer.failed"],
    },
  });

  const tenantEnv = options.tenantEnvironment?.trim().toLowerCase();
  if (tenantEnv && flutterwaveEnv) {
    const mismatch =
      (tenantEnv === "sandbox" && flutterwaveEnv === "live") ||
      (tenantEnv === "live" && flutterwaveEnv === "sandbox");
    checks.push({
      name: "environment_match",
      ok: !mismatch,
      message: mismatch
        ? `tenant environment=${tenantEnv} but Flutterwave destination environment=${flutterwaveEnv} — use matching sandbox or live credentials`
        : `tenant environment=${tenantEnv} matches Flutterwave destination environment=${flutterwaveEnv}`,
      details: { tenant_environment: tenantEnv, flutterwave_environment: flutterwaveEnv },
    });
  } else {
    checks.push({
      name: "environment_match",
      ok: true,
      message: tenantEnv
        ? `tenant environment=${tenantEnv}; Flutterwave destination environment unset — save destination in Console`
        : flutterwaveEnv
          ? `Flutterwave destination environment=${flutterwaveEnv}; principal environment unavailable (login required for mismatch check)`
          : "environment mismatch check skipped (missing principal or destination environment)",
      details: {
        tenant_environment: tenantEnv,
        flutterwave_environment: flutterwaveEnv || undefined,
      },
    });
  }

  checks.push({
    name: "console_destination",
    ok: config.flutterwave_destination_configured === true,
    message: config.flutterwave_destination_configured
      ? "destination managed in Console → Configuration → Settlement (CLI rejects argv secrets)"
      : "upsert secret key, webhook secret, environment, and currency in Console → Configuration → Settlement (https://paybond.ai/console/configuration/settlement); never pass them on CLI argv",
    details: {
      console_path: "/console/configuration/settlement",
      write_only_secrets: true,
      argv_blocked_flags: [...FLUTTERWAVE_ARGV_BLOCKED_FLAGS],
    },
  });

  return checks;
}

async function fetchSettlementConfig(
  ctx: CliContext,
): Promise<FlutterwaveSettlementConfigSnapshot | null> {
  try {
    await resolveApiKey(ctx.globals, ctx.cwd);
  } catch {
    return null;
  }
  try {
    const result = await withGateway(ctx, async (gateway) => {
      const body = await gateway.getJson("/v1/admin/settlement/config");
      return { data: body };
    });
    return result.data as FlutterwaveSettlementConfigSnapshot;
  } catch {
    return null;
  }
}

async function fetchTenantEnvironment(ctx: CliContext): Promise<string | undefined> {
  try {
    await resolveApiKey(ctx.globals, ctx.cwd);
  } catch {
    return undefined;
  }
  try {
    const result = await withGateway(ctx, async (gateway) => {
      const body = (await gateway.getJson("/v1/auth/principal")) as {
        environment?: unknown;
      };
      return { data: body };
    });
    const raw = result.data.environment;
    const environment = typeof raw === "string" ? raw.trim() : "";
    return environment || undefined;
  } catch {
    return undefined;
  }
}

export async function handleFlutterwaveReady(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoFlutterwaveSensitiveArgv(argv);
  if (argv.length > 0) {
    throw flutterwaveCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw flutterwaveCliError("settlement config unavailable — run paybond login", {
      code: "cli.flutterwave.missing_settlement",
    });
  }
  const checks = buildFlutterwaveReadyChecks(settlement);
  const useColor = shouldUseColor(ctx.globals);
  const ready = checks.every((check) => check.ok);
  return {
    data: {
      ready,
      checks,
      summary: ready ? "pass" : "fail",
      checklist_lines: formatFlutterwaveDoctorChecklist(checks, useColor, "flutterwave ready"),
    },
  };
}

export async function handleFlutterwaveDoctor(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoFlutterwaveSensitiveArgv(argv);
  if (argv.length > 0) {
    throw flutterwaveCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw flutterwaveCliError("settlement config unavailable — run paybond login", {
      code: "cli.flutterwave.missing_settlement",
    });
  }
  const tenantEnvironment = await fetchTenantEnvironment(ctx);
  const checks = buildFlutterwaveDoctorChecks(settlement, {
    gatewayBase: ctx.globals.gateway,
    tenantEnvironment,
  });
  const useColor = shouldUseColor(ctx.globals);
  return {
    data: {
      checks,
      summary: checks.every((check) => check.ok) ? "pass" : "fail",
      checklist_lines: formatFlutterwaveDoctorChecklist(checks, useColor, "flutterwave doctor"),
      next_steps: [
        "Console destination upsert: https://paybond.ai/console/configuration/settlement",
        "Docs: https://docs.paybond.ai/guides/configure-flutterwave-settlement",
        "Ready: paybond flutterwave ready",
      ],
    },
  };
}

/** Dispatch `paybond flutterwave <subcommand>`. */
export async function handleFlutterwave(
  ctx: CliContext,
  second: string,
  argv: string[],
): Promise<CommandResult> {
  if (second === "ready") {
    return handleFlutterwaveReady(ctx, argv);
  }
  if (second === "doctor") {
    return handleFlutterwaveDoctor(ctx, argv);
  }
  throw flutterwaveCliError(`unknown flutterwave subcommand: flutterwave ${second}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
