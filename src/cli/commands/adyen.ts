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
export const ADYEN_ARGV_BLOCKED_FLAGS = [
  "--live-prefix",
  "--api-key",
  "--hmac-secret",
  "--merchant-account",
  "--environment",
  "--stored-payment-method",
  "--stored-payment-method-id",
] as const;

export type AdyenDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export type AdyenSettlementConfigSnapshot = {
  allowed_rails?: string[];
  plan_id?: string;
  adyen_destination_configured?: boolean;
  adyen_merchant_account_masked?: string;
  adyen_store_masked?: string;
  adyen_environment?: string;
  adyen_live_prefix_configured?: boolean;
  adyen_api_key_configured?: boolean;
  adyen_hmac_secret_configured?: boolean;
  adyen_stored_payment_method_configured?: boolean;
  rail_readiness?: Array<{
    rail?: string;
    ready?: boolean;
    enabled?: boolean;
    status?: string;
    reason_code?: string;
    message?: string;
  }>;
};

function adyenCliError(
  message: string,
  options: { code: string; category?: ErrorCategory; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

/** True when an argv token is a blocked Adyen destination flag (exact or `--flag=value`). */
export function rejectsAdyenSensitiveArgvFlag(arg: string): boolean {
  for (const flag of ADYEN_ARGV_BLOCKED_FLAGS) {
    if (arg === flag || arg.startsWith(`${flag}=`)) {
      return true;
    }
  }
  return false;
}

/**
 * Reject process-visible Adyen destination material on argv (SEC-011).
 * Live prefix is routing-sensitive; API key / HMAC / stored PM / merchant remain Console write-only.
 */
export function assertNoAdyenSensitiveArgv(argv: string[]): void {
  for (const arg of argv) {
    if (!rejectsAdyenSensitiveArgvFlag(arg)) {
      continue;
    }
    const flag = ADYEN_ARGV_BLOCKED_FLAGS.find(
      (candidate) => arg === candidate || arg.startsWith(`${candidate}=`),
    );
    throw adyenCliError(
      `adyen CLI rejects ${flag ?? arg} on argv (visible in process listings); upsert destination credentials and live URL prefix via Console → Configuration → Settlement (write-only)`,
      {
        code: "cli.adyen.argv_secret_forbidden",
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

function formatDoctorChecklistLine(check: AdyenDoctorCheck, useColor: boolean): string {
  const prefix = check.ok ? colorize("✓", "green", useColor) : colorize("✗", "yellow", useColor);
  return `${prefix} ${check.name}: ${check.message}`;
}

/** Format Adyen ready/doctor checklist lines with a pass/fail summary. */
export function formatAdyenDoctorChecklist(
  checks: AdyenDoctorCheck[],
  useColor: boolean,
  label: "adyen ready" | "adyen doctor" = "adyen doctor",
): string[] {
  const lines = checks.map((check) => formatDoctorChecklistLine(check, useColor));
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(colorize(`${label}: ${summary}`, summary === "pass" ? "green" : "yellow", useColor));
  return lines;
}

/** Resolve Paybond gateway origin to the Adyen webhook path for live or sandbox. */
export function resolveAdyenWebhookAddress(
  gatewayBase: string,
  environment: "live" | "sandbox" = "sandbox",
): string {
  const secure = requireSecureGatewayUrl(gatewayBase.trim().replace(/\/$/, ""));
  return `${secure}/webhooks/${environment}/adyen`;
}

function allowedRails(config: AdyenSettlementConfigSnapshot): string[] {
  return Array.isArray(config.allowed_rails) ? config.allowed_rails.map(String) : [];
}

function adyenRailReadiness(config: AdyenSettlementConfigSnapshot) {
  return config.rail_readiness?.find((entry) => entry.rail === "adyen_manual_capture");
}

function isLiveAdyenEnvironment(environment: string | undefined): boolean {
  return (environment ?? "").trim().toLowerCase() === "live";
}

/**
 * Build settlement-config readiness checks for `paybond adyen ready`.
 * Pure so unit tests can exercise fixtures without Gateway I/O.
 */
export function buildAdyenReadyChecks(config: AdyenSettlementConfigSnapshot): AdyenDoctorCheck[] {
  const rails = allowedRails(config);
  const railEnabled = rails.includes("adyen_manual_capture");
  const destinationOk = config.adyen_destination_configured === true;
  const apiKeyOk = config.adyen_api_key_configured === true;
  const hmacOk = config.adyen_hmac_secret_configured === true;
  const storedPmOk = config.adyen_stored_payment_method_configured === true;
  const live = isLiveAdyenEnvironment(config.adyen_environment);
  const livePrefixOk = !live || config.adyen_live_prefix_configured === true;
  const readiness = adyenRailReadiness(config);
  const paidPlanBlocked = readiness?.reason_code === "adyen_paid_plan_required";

  const checks: AdyenDoctorCheck[] = [
    {
      name: "rail_enabled",
      ok: railEnabled,
      message: railEnabled
        ? "adyen_manual_capture is in allowed_rails"
        : "enable adyen_manual_capture in Console → Configuration → Settlement",
      details: { allowed_rails: rails },
    },
    {
      name: "destination_configured",
      ok: destinationOk,
      message: destinationOk
        ? `destination active (${config.adyen_merchant_account_masked ?? "masked merchant"})`
        : "save Adyen Checkout destination credentials in Console → Configuration → Settlement",
      details: {
        merchant_account_masked: config.adyen_merchant_account_masked,
        environment: config.adyen_environment,
      },
    },
    {
      name: "api_key",
      ok: apiKeyOk,
      message: apiKeyOk
        ? "Checkout API key configured"
        : "upsert Adyen API key via Console destination form (write-only; never --api-key on argv)",
    },
    {
      name: "hmac",
      ok: hmacOk,
      message: hmacOk
        ? "webhook HMAC secret configured"
        : "upsert Adyen webhook HMAC secret via Console destination form (write-only; never --hmac-secret on argv)",
    },
    {
      name: "stored_payment_method",
      ok: storedPmOk,
      message: storedPmOk
        ? "tenant stored payment method vaulted for live funding"
        : "upsert stored payment method via Console destination form (write-only; never via CLI argv)",
    },
    {
      name: "live_prefix",
      ok: livePrefixOk,
      message: live
        ? livePrefixOk
          ? "live URL prefix configured"
          : "set company live URL prefix via Console → Settlement (write-only; never --live-prefix on argv)"
        : config.adyen_environment
          ? `live prefix not required (environment=${config.adyen_environment})`
          : "live prefix check skipped (no adyen_environment on destination)",
      details: {
        environment: config.adyen_environment,
        live_prefix_configured: config.adyen_live_prefix_configured === true,
        write_only: true,
      },
    },
  ];

  if (paidPlanBlocked) {
    checks.push({
      name: "paid_plan",
      ok: false,
      message:
        readiness?.message ??
        "Live Adyen settlement destinations are only available on paid self-serve plans.",
      details: {
        reason_code: readiness?.reason_code,
        plan_id: config.plan_id,
      },
    });
  } else {
    checks.push({
      name: "paid_plan",
      ok: true,
      message: live
        ? "live destination allowed on current plan"
        : "paid-plan gate applies to live Adyen destinations only",
      details: { plan_id: config.plan_id, environment: config.adyen_environment },
    });
  }

  if (!readiness) {
    checks.push({
      name: "rail_readiness",
      ok: false,
      message: "adyen_manual_capture readiness unavailable (login and save an Adyen destination)",
    });
  } else {
    checks.push({
      name: "rail_readiness",
      ok: readiness.ready === true && railEnabled,
      message:
        readiness.message ??
        (readiness.ready && railEnabled
          ? "adyen_manual_capture ready"
          : readiness.ready
            ? "destination ready — enable adyen_manual_capture in allowed_rails"
            : "adyen_manual_capture not ready"),
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

export type AdyenDoctorOptions = {
  gatewayBase: string;
  /** Tenant realm from GET /v1/auth/principal when available (`sandbox` | `live`). */
  tenantEnvironment?: string;
};

/**
 * Expand ready checks with webhook URL checklist, sandbox/live mismatch hints,
 * and Console destination upsert pointer.
 */
export function buildAdyenDoctorChecks(
  config: AdyenSettlementConfigSnapshot,
  options: AdyenDoctorOptions,
): AdyenDoctorCheck[] {
  const checks = buildAdyenReadyChecks(config);
  const gatewayBase = options.gatewayBase.trim().replace(/\/$/, "");
  const liveUrl = resolveAdyenWebhookAddress(gatewayBase, "live");
  const sandboxUrl = resolveAdyenWebhookAddress(gatewayBase, "sandbox");
  const adyenEnv = (config.adyen_environment ?? "").trim().toLowerCase();
  const preferred =
    adyenEnv === "live" ? liveUrl : adyenEnv === "test" ? sandboxUrl : sandboxUrl;

  checks.push({
    name: "webhook_endpoint",
    ok: true,
    message: `register STANDARD webhook at ${preferred} (also support live=${liveUrl})`,
    details: {
      sandbox: sandboxUrl,
      live: liveUrl,
      recommended: preferred,
      events: ["AUTHORISATION", "CAPTURE", "CAPTURE_FAILED", "CANCELLATION", "REFUND", "CHARGEBACK"],
    },
  });

  const tenantEnv = options.tenantEnvironment?.trim().toLowerCase();
  if (tenantEnv && adyenEnv) {
    const mismatch =
      (tenantEnv === "sandbox" && adyenEnv === "live") ||
      (tenantEnv === "live" && adyenEnv === "test");
    checks.push({
      name: "environment_match",
      ok: !mismatch,
      message: mismatch
        ? `tenant environment=${tenantEnv} but Adyen destination environment=${adyenEnv} — use matching sandbox/test or live credentials`
        : `tenant environment=${tenantEnv} matches Adyen destination environment=${adyenEnv}`,
      details: { tenant_environment: tenantEnv, adyen_environment: adyenEnv },
    });
  } else {
    checks.push({
      name: "environment_match",
      ok: true,
      message: tenantEnv
        ? `tenant environment=${tenantEnv}; Adyen destination environment unset — save destination in Console`
        : adyenEnv
          ? `Adyen destination environment=${adyenEnv}; principal environment unavailable (login required for mismatch check)`
          : "environment mismatch check skipped (missing principal or destination environment)",
      details: { tenant_environment: tenantEnv, adyen_environment: adyenEnv || undefined },
    });
  }

  checks.push({
    name: "console_destination",
    ok: config.adyen_destination_configured === true,
    message: config.adyen_destination_configured
      ? "destination managed in Console → Configuration → Settlement (CLI rejects argv secrets / --live-prefix)"
      : "upsert merchant account, live prefix, API key, and HMAC in Console → Configuration → Settlement (https://paybond.ai/console/configuration/settlement); never pass them on CLI argv",
    details: {
      console_path: "/console/configuration/settlement",
      write_only_secrets: true,
      argv_blocked_flags: [...ADYEN_ARGV_BLOCKED_FLAGS],
    },
  });

  return checks;
}

async function fetchSettlementConfig(ctx: CliContext): Promise<AdyenSettlementConfigSnapshot | null> {
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
    return result.data as AdyenSettlementConfigSnapshot;
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

export async function handleAdyenReady(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoAdyenSensitiveArgv(argv);
  if (argv.length > 0) {
    throw adyenCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw adyenCliError("settlement config unavailable — run paybond login", {
      code: "cli.adyen.missing_settlement",
    });
  }
  const checks = buildAdyenReadyChecks(settlement);
  const useColor = shouldUseColor(ctx.globals);
  const ready = checks.every((check) => check.ok);
  return {
    data: {
      ready,
      checks,
      summary: ready ? "pass" : "fail",
      checklist_lines: formatAdyenDoctorChecklist(checks, useColor, "adyen ready"),
    },
  };
}

export async function handleAdyenDoctor(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoAdyenSensitiveArgv(argv);
  if (argv.length > 0) {
    throw adyenCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw adyenCliError("settlement config unavailable — run paybond login", {
      code: "cli.adyen.missing_settlement",
    });
  }
  const tenantEnvironment = await fetchTenantEnvironment(ctx);
  const checks = buildAdyenDoctorChecks(settlement, {
    gatewayBase: ctx.globals.gateway,
    tenantEnvironment,
  });
  const useColor = shouldUseColor(ctx.globals);
  return {
    data: {
      checks,
      summary: checks.every((check) => check.ok) ? "pass" : "fail",
      checklist_lines: formatAdyenDoctorChecklist(checks, useColor, "adyen doctor"),
      next_steps: [
        "Console destination upsert: https://paybond.ai/console/configuration/settlement",
        "Docs: https://docs.paybond.ai/guides/configure-adyen-settlement",
        "Ready: paybond adyen ready",
      ],
    },
  };
}

/** Dispatch `paybond adyen <subcommand>`. */
export async function handleAdyen(
  ctx: CliContext,
  second: string,
  argv: string[],
): Promise<CommandResult> {
  if (second === "ready") {
    return handleAdyenReady(ctx, argv);
  }
  if (second === "doctor") {
    return handleAdyenDoctor(ctx, argv);
  }
  throw adyenCliError(`unknown adyen subcommand: adyen ${second}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
