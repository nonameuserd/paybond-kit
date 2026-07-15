import { colorize, shouldUseColor } from "../color.js";
import type { CliContext } from "../context.js";
import { withGateway } from "../context.js";
import { resolveApiKey } from "../credentials.js";
import { requireSecureGatewayUrl } from "../../gateway-url.js";
import { CliError, type CommandResult, type ErrorCategory } from "../types.js";

/**
 * Destination / vault fields that must never appear on argv (CWE-214 / SEC-011).
 * Upsert is Console write-only; ready/doctor only read masked settlement config.
 * Paystack has no separate webhook secret — the same `secret_key` verifies the
 * `X-Paystack-Signature` HMAC-SHA512, so only the secret key and environment are gated.
 */
export const PAYSTACK_ARGV_BLOCKED_FLAGS = ["--secret-key", "--environment"] as const;

export type PaystackDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export type PaystackSettlementConfigSnapshot = {
  allowed_rails?: string[];
  plan_id?: string;
  paystack_destination_configured?: boolean;
  paystack_environment?: string;
  paystack_label?: string;
  paystack_currency?: string;
  paystack_secret_key_configured?: boolean;
  paystack_webhook_url?: string;
  rail_readiness?: Array<{
    rail?: string;
    ready?: boolean;
    enabled?: boolean;
    status?: string;
    reason_code?: string;
    message?: string;
  }>;
};

function paystackCliError(
  message: string,
  options: { code: string; category?: ErrorCategory; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

/** True when an argv token is a blocked Paystack destination flag (exact or `--flag=value`). */
export function rejectsPaystackSensitiveArgvFlag(arg: string): boolean {
  for (const flag of PAYSTACK_ARGV_BLOCKED_FLAGS) {
    if (arg === flag || arg.startsWith(`${flag}=`)) {
      return true;
    }
  }
  return false;
}

/**
 * Reject process-visible Paystack destination material on argv (SEC-011).
 * The tenant `secret_key` (used for outbound API auth and inbound HMAC verification)
 * and environment remain Console write-only.
 */
export function assertNoPaystackSensitiveArgv(argv: string[]): void {
  for (const arg of argv) {
    if (!rejectsPaystackSensitiveArgvFlag(arg)) {
      continue;
    }
    const flag = PAYSTACK_ARGV_BLOCKED_FLAGS.find(
      (candidate) => arg === candidate || arg.startsWith(`${candidate}=`),
    );
    throw paystackCliError(
      `paystack CLI rejects ${flag ?? arg} on argv (visible in process listings); upsert destination credentials via Console → Configuration → Settlement (write-only)`,
      {
        code: "cli.paystack.argv_secret_forbidden",
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

function formatDoctorChecklistLine(check: PaystackDoctorCheck, useColor: boolean): string {
  const prefix = check.ok ? colorize("✓", "green", useColor) : colorize("✗", "yellow", useColor);
  return `${prefix} ${check.name}: ${check.message}`;
}

/** Format Paystack ready/doctor checklist lines with a pass/fail summary. */
export function formatPaystackDoctorChecklist(
  checks: PaystackDoctorCheck[],
  useColor: boolean,
  label: "paystack ready" | "paystack doctor" = "paystack doctor",
): string[] {
  const lines = checks.map((check) => formatDoctorChecklistLine(check, useColor));
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(colorize(`${label}: ${summary}`, summary === "pass" ? "green" : "yellow", useColor));
  return lines;
}

/** Resolve Paybond gateway origin to the Paystack webhook base path for live or sandbox. */
export function resolvePaystackWebhookAddress(
  gatewayBase: string,
  environment: "live" | "sandbox" = "sandbox",
): string {
  const secure = requireSecureGatewayUrl(gatewayBase.trim().replace(/\/$/, ""));
  return `${secure}/webhooks/${environment}/paystack`;
}

function allowedRails(config: PaystackSettlementConfigSnapshot): string[] {
  return Array.isArray(config.allowed_rails) ? config.allowed_rails.map(String) : [];
}

function paystackRailReadiness(config: PaystackSettlementConfigSnapshot) {
  return config.rail_readiness?.find((entry) => entry.rail === "paystack_nip");
}

function isLivePaystackEnvironment(environment: string | undefined): boolean {
  return (environment ?? "").trim().toLowerCase() === "live";
}

/**
 * Build settlement-config readiness checks for `paybond paystack ready`.
 * Pure so unit tests can exercise fixtures without Gateway I/O.
 */
export function buildPaystackReadyChecks(
  config: PaystackSettlementConfigSnapshot,
): PaystackDoctorCheck[] {
  const rails = allowedRails(config);
  const railEnabled = rails.includes("paystack_nip");
  const destinationOk = config.paystack_destination_configured === true;
  const secretKeyOk = config.paystack_secret_key_configured === true;
  const readiness = paystackRailReadiness(config);
  const paidPlanBlocked = readiness?.reason_code === "paystack_paid_plan_required";

  const checks: PaystackDoctorCheck[] = [
    {
      name: "rail_enabled",
      ok: railEnabled,
      message: railEnabled
        ? "paystack_nip is in allowed_rails"
        : "enable paystack_nip in Console → Configuration → Settlement",
      details: { allowed_rails: rails },
    },
    {
      name: "destination_configured",
      ok: destinationOk,
      message: destinationOk
        ? `destination active (${config.paystack_label || config.paystack_currency || "Paystack"})`
        : "save Paystack destination credentials in Console → Configuration → Settlement",
      details: {
        label: config.paystack_label,
        currency: config.paystack_currency,
        environment: config.paystack_environment,
      },
    },
    {
      name: "secret_key",
      ok: secretKeyOk,
      message: secretKeyOk
        ? "tenant secret key configured (also verifies X-Paystack-Signature HMAC-SHA512)"
        : "upsert Paystack secret key via Console destination form (write-only; never --secret-key on argv)",
    },
  ];

  if (paidPlanBlocked) {
    checks.push({
      name: "paid_plan",
      ok: false,
      message:
        readiness?.message ??
        "Live Paystack settlement destinations are only available on paid self-serve plans.",
      details: {
        reason_code: readiness?.reason_code,
        plan_id: config.plan_id,
      },
    });
  } else {
    const live = isLivePaystackEnvironment(config.paystack_environment);
    checks.push({
      name: "paid_plan",
      ok: true,
      message: live
        ? "live destination allowed on current plan"
        : "paid-plan gate applies to live Paystack destinations only",
      details: { plan_id: config.plan_id, environment: config.paystack_environment },
    });
  }

  if (!readiness) {
    checks.push({
      name: "rail_readiness",
      ok: false,
      message: "paystack_nip readiness unavailable (login and save a Paystack destination)",
    });
  } else {
    checks.push({
      name: "rail_readiness",
      ok: readiness.ready === true && railEnabled,
      message:
        readiness.message ??
        (readiness.ready && railEnabled
          ? "paystack_nip ready"
          : readiness.ready
            ? "destination ready — enable paystack_nip in allowed_rails"
            : "paystack_nip not ready"),
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

export type PaystackDoctorOptions = {
  gatewayBase: string;
  /** Tenant realm from GET /v1/auth/principal when available (`sandbox` | `live`). */
  tenantEnvironment?: string;
};

/**
 * Expand ready checks with webhook URL checklist, sandbox/live mismatch hints,
 * and Console destination upsert pointer.
 */
export function buildPaystackDoctorChecks(
  config: PaystackSettlementConfigSnapshot,
  options: PaystackDoctorOptions,
): PaystackDoctorCheck[] {
  const checks = buildPaystackReadyChecks(config);
  const gatewayBase = options.gatewayBase.trim().replace(/\/$/, "");
  const liveUrl = resolvePaystackWebhookAddress(gatewayBase, "live");
  const sandboxUrl = resolvePaystackWebhookAddress(gatewayBase, "sandbox");
  const paystackEnv = (config.paystack_environment ?? "").trim().toLowerCase();
  const basePath = paystackEnv === "live" ? liveUrl : sandboxUrl;
  // The Gateway appends a per-destination token to the webhook path; prefer the
  // configured URL (token-scoped) when a destination is saved.
  const configured = (config.paystack_webhook_url ?? "").trim();

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
      events: ["charge.success", "transfer.success", "transfer.failed", "transfer.reversed", "refund.processed"],
    },
  });

  const tenantEnv = options.tenantEnvironment?.trim().toLowerCase();
  if (tenantEnv && paystackEnv) {
    const mismatch =
      (tenantEnv === "sandbox" && paystackEnv === "live") ||
      (tenantEnv === "live" && paystackEnv === "sandbox");
    checks.push({
      name: "environment_match",
      ok: !mismatch,
      message: mismatch
        ? `tenant environment=${tenantEnv} but Paystack destination environment=${paystackEnv} — use matching sandbox or live credentials`
        : `tenant environment=${tenantEnv} matches Paystack destination environment=${paystackEnv}`,
      details: { tenant_environment: tenantEnv, paystack_environment: paystackEnv },
    });
  } else {
    checks.push({
      name: "environment_match",
      ok: true,
      message: tenantEnv
        ? `tenant environment=${tenantEnv}; Paystack destination environment unset — save destination in Console`
        : paystackEnv
          ? `Paystack destination environment=${paystackEnv}; principal environment unavailable (login required for mismatch check)`
          : "environment mismatch check skipped (missing principal or destination environment)",
      details: {
        tenant_environment: tenantEnv,
        paystack_environment: paystackEnv || undefined,
      },
    });
  }

  checks.push({
    name: "console_destination",
    ok: config.paystack_destination_configured === true,
    message: config.paystack_destination_configured
      ? "destination managed in Console → Configuration → Settlement (CLI rejects argv secrets)"
      : "upsert secret key, environment, and currency (NGN) in Console → Configuration → Settlement (https://paybond.ai/console/configuration/settlement); never pass them on CLI argv",
    details: {
      console_path: "/console/configuration/settlement",
      write_only_secrets: true,
      argv_blocked_flags: [...PAYSTACK_ARGV_BLOCKED_FLAGS],
    },
  });

  return checks;
}

async function fetchSettlementConfig(
  ctx: CliContext,
): Promise<PaystackSettlementConfigSnapshot | null> {
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
    return result.data as PaystackSettlementConfigSnapshot;
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

/** Handle `paybond paystack ready` — settlement-config readiness checklist. */
export async function handlePaystackReady(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPaystackSensitiveArgv(argv);
  if (argv.length > 0) {
    throw paystackCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw paystackCliError("settlement config unavailable — run paybond login", {
      code: "cli.paystack.missing_settlement",
    });
  }
  const checks = buildPaystackReadyChecks(settlement);
  const useColor = shouldUseColor(ctx.globals);
  const ready = checks.every((check) => check.ok);
  return {
    data: {
      ready,
      checks,
      summary: ready ? "pass" : "fail",
      checklist_lines: formatPaystackDoctorChecklist(checks, useColor, "paystack ready"),
    },
  };
}

/** Handle `paybond paystack doctor` — readiness plus webhook and Console guidance. */
export async function handlePaystackDoctor(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPaystackSensitiveArgv(argv);
  if (argv.length > 0) {
    throw paystackCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw paystackCliError("settlement config unavailable — run paybond login", {
      code: "cli.paystack.missing_settlement",
    });
  }
  const tenantEnvironment = await fetchTenantEnvironment(ctx);
  const checks = buildPaystackDoctorChecks(settlement, {
    gatewayBase: ctx.globals.gateway,
    tenantEnvironment,
  });
  const useColor = shouldUseColor(ctx.globals);
  return {
    data: {
      checks,
      summary: checks.every((check) => check.ok) ? "pass" : "fail",
      checklist_lines: formatPaystackDoctorChecklist(checks, useColor, "paystack doctor"),
      next_steps: [
        "Console destination upsert: https://paybond.ai/console/configuration/settlement",
        "Docs: https://docs.paybond.ai/guides/configure-paystack-settlement",
        "Ready: paybond paystack ready",
      ],
    },
  };
}

/** Dispatch `paybond paystack <subcommand>`. */
export async function handlePaystack(
  ctx: CliContext,
  second: string,
  argv: string[],
): Promise<CommandResult> {
  if (second === "ready") {
    return handlePaystackReady(ctx, argv);
  }
  if (second === "doctor") {
    return handlePaystackDoctor(ctx, argv);
  }
  throw paystackCliError(`unknown paystack subcommand: paystack ${second}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
