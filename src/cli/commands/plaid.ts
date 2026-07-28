/**
 * paybond plaid subcommands: safe Plaid Auth readiness inspection (H4 P2).
 *
 * Plaid Auth is a tenant-scoped bank-verification input under the existing
 * `stripe_ach_debit` rail. This module is read-only operator inspection:
 *
 * - Never implements `paybond plaid link` and never accepts `public_token`,
 *   `access_token`, `link_token`, or Stripe processor tokens on argv.
 * - Never prints Plaid secrets, Link tokens, decrypted vault material, or raw
 *   account/routing numbers. Bank metadata mirrors Admin console safe fields via
 *   `GET /v1/admin/plaid/bank-accounts`.
 * - Reason codes align with `go/gateway/internal/rails/plaid/reasons.go`.
 */

import { colorize, shouldUseColor } from "../color.js";
import type { CliContext } from "../context.js";
import { withGateway } from "../context.js";
import { resolveApiKey } from "../credentials.js";
import { requireSecureGatewayUrl } from "../../gateway-url.js";
import { CliError, type CommandResult, type ErrorCategory } from "../types.js";

/** Link/exchange/processor material must never appear on argv (CWE-214 / SEC-011). */
export const PLAID_ARGV_BLOCKED_FLAGS = [
  "--public-token",
  "--access-token",
  "--link-token",
  "--processor-token",
  "--bank-account-token",
] as const;

/** Allowlisted bank wire fields — never forward secrets if the gateway shape grows. */
const SAFE_BANK_FIELDS = [
  "id",
  "environment",
  "institution_id",
  "verification_status",
  "auth_method",
  "bank_name",
  "bank_mask",
  "bank_last4",
  "account_type",
  "account_subtype",
  "status",
  "ready",
  "readiness_reason",
  "stripe_attach_status",
  "stripe_attach_error_code",
  "relink_required",
  "bank_link_source",
  "created_at",
  "updated_at",
] as const;

export type PlaidDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export type PlaidBankAccountSummary = Record<string, unknown>;

export type PlaidBankAccountsListBody = {
  environment?: string;
  bank_accounts?: Array<Record<string, unknown>>;
};

function plaidCliError(
  message: string,
  options: { code: string; category?: ErrorCategory; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

/** True when an argv token is a blocked Plaid Link/token flag (exact or `--flag=value`). */
export function rejectsPlaidSensitiveArgvFlag(arg: string): boolean {
  for (const flag of PLAID_ARGV_BLOCKED_FLAGS) {
    if (arg === flag || arg.startsWith(`${flag}=`)) {
      return true;
    }
  }
  return false;
}

/**
 * Reject process-visible Plaid Link/token material on argv (SEC-011).
 * Paybond never accepts these outside the server-side exchange endpoint.
 */
export function assertNoPlaidSensitiveArgv(argv: string[]): void {
  for (const arg of argv) {
    if (!rejectsPlaidSensitiveArgvFlag(arg)) {
      continue;
    }
    const flag = PLAID_ARGV_BLOCKED_FLAGS.find(
      (candidate) => arg === candidate || arg.startsWith(`${candidate}=`),
    );
    throw plaidCliError(
      `plaid CLI rejects ${flag ?? arg} on argv (visible in process listings); Paybond never accepts Plaid ` +
        "Link, access, or processor tokens outside the server-side exchange endpoint",
      {
        code: "cli.plaid.argv_secret_forbidden",
        category: "usage",
        details: { flag: flag ?? arg },
      },
    );
  }
}

/** Resolve Paybond gateway origin to the corrected Plaid webhook route. */
export function resolvePlaidWebhookAddress(gatewayBase: string): string {
  const secure = requireSecureGatewayUrl(gatewayBase.trim().replace(/\/$/, ""));
  return `${secure}/webhooks/plaid`;
}

function safeBankSummary(bank: Record<string, unknown>): PlaidBankAccountSummary {
  const out: PlaidBankAccountSummary = {};
  for (const key of SAFE_BANK_FIELDS) {
    if (key in bank) {
      out[key] = bank[key];
    }
  }
  return out;
}

/**
 * Build readiness checks for `paybond plaid ready` from the bank-accounts response.
 * `fetchError` carries gateway 404 reason codes such as `feature_disabled`.
 */
export function buildPlaidReadyChecks(
  listBody: PlaidBankAccountsListBody | null,
  fetchError: CliError | null,
): PlaidDoctorCheck[] {
  if (fetchError !== null) {
    const details = fetchError.details ?? {};
    return [
      {
        name: "feature_available",
        ok: false,
        message: fetchError.message,
        details: { reason_code: details.gateway_code },
      },
    ];
  }

  const body = listBody ?? {};
  const environment = String(body.environment ?? "unknown");
  const banks = (body.bank_accounts ?? [])
    .filter((b): b is Record<string, unknown> => Boolean(b) && typeof b === "object")
    .map(safeBankSummary);
  const readyBanks = banks.filter((b) => b.ready === true);
  const notReadyBanks = banks.filter((b) => b.ready !== true);

  const checks: PlaidDoctorCheck[] = [
    {
      name: "feature_available",
      ok: true,
      message: `Plaid Auth is available for this tenant (environment=${environment})`,
      details: { environment },
    },
    {
      name: "ready_bank_available",
      ok: readyBanks.length > 0,
      message:
        readyBanks.length > 0
          ? `${readyBanks.length} linked bank(s) ready for ACH debit`
          : "no ready Plaid bank yet; link one in Console → Configuration → Settlement, or use Financial Connections",
      details: { banks_total: banks.length, banks_ready: readyBanks.length },
    },
  ];

  if (notReadyBanks.length > 0) {
    const reasons = [
      ...new Set(
        notReadyBanks.map((b) => String(b.readiness_reason ?? "not_ready")),
      ),
    ].sort();
    checks.push({
      name: "attention_needed",
      ok: true,
      message: `${notReadyBanks.length} linked bank(s) need attention: ${reasons.join(", ")}`,
      details: { reason_codes: reasons, count: notReadyBanks.length },
    });
  }
  return checks;
}

/** Expand ready checks with webhook address, environment pairing, and docs pointers. */
export function buildPlaidDoctorChecks(
  listBody: PlaidBankAccountsListBody | null,
  fetchError: CliError | null,
  options: { gatewayBase: string; tenantEnvironment?: string },
): PlaidDoctorCheck[] {
  const checks = buildPlaidReadyChecks(listBody, fetchError);
  const webhookAddress = resolvePlaidWebhookAddress(options.gatewayBase);
  checks.push({
    name: "webhook_endpoint",
    ok: true,
    message:
      `configure PLAID_WEBHOOK_URL=${webhookAddress} on the gateway deploy ` +
      "(one route serves sandbox and production; environment resolves server-side)",
    details: {
      webhook_address: webhookAddress,
      route: "/webhooks/plaid",
      events: [
        "AUTOMATICALLY_VERIFIED",
        "VERIFICATION_EXPIRED",
        "DEFAULT_UPDATE",
        "ERROR",
        "PENDING_DISCONNECT",
        "USER_PERMISSION_REVOKED",
        "USER_ACCOUNT_REVOKED",
      ],
    },
  });

  const tenantEnv = options.tenantEnvironment?.trim().toLowerCase() || undefined;
  const plaidEnv =
    String(listBody?.environment ?? "")
      .trim()
      .toLowerCase() || undefined;
  let message =
    "environment pairing check skipped (login required to resolve tenant environment)";
  if (tenantEnv && plaidEnv) {
    message =
      `tenant environment=${tenantEnv} pairs with Plaid environment=${plaidEnv} ` +
      "(the gateway enforces this pairing server-side before Link and exchange)";
  }
  checks.push({
    name: "environment_pairing",
    ok: true,
    message,
    details: { tenant_environment: tenantEnv ?? null, plaid_environment: plaidEnv ?? null },
  });

  checks.push({
    name: "console_and_docs",
    ok: true,
    message:
      "link/manage banks in Console → Configuration → Settlement; " +
      "guide: https://docs.paybond.ai/guides/configure-plaid-bank-verification",
    details: {
      console_path: "/console/configuration/settlement",
      guide_path: "/guides/configure-plaid-bank-verification",
      sandbox_smoke: "make plaid-auth-sandbox-smoke",
    },
  });
  return checks;
}

/** Format Plaid ready/doctor checklist lines with a pass/fail summary. */
export function formatPlaidChecklist(
  checks: PlaidDoctorCheck[],
  useColor: boolean,
  label: "plaid ready" | "plaid doctor" = "plaid doctor",
): string[] {
  const lines = checks.map((check) => {
    const prefix = check.ok
      ? colorize("✓", "green", useColor)
      : colorize("✗", "yellow", useColor);
    return `${prefix} ${check.name}: ${check.message}`;
  });
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(
    colorize(`${label}: ${summary}`, summary === "pass" ? "green" : "yellow", useColor),
  );
  return lines;
}

async function fetchBankAccounts(
  ctx: CliContext,
): Promise<{ body: PlaidBankAccountsListBody | null; error: CliError | null }> {
  resolveApiKey(ctx.globals, ctx.cwd);
  try {
    const result = await withGateway(ctx, async (gateway) => {
      const body = (await gateway.getJson("/v1/admin/plaid/bank-accounts")) as PlaidBankAccountsListBody;
      return { data: body };
    });
    return { body: result.data ?? {}, error: null };
  } catch (err) {
    if (err instanceof CliError) {
      return { body: null, error: err };
    }
    throw err;
  }
}

/**
 * Fetch `GET /v1/admin/plaid/bank-accounts/{id}`: one tenant-scoped bank.
 *
 * Issues a single tenant-scoped request for this id instead of downloading the
 * whole inventory and filtering client-side, so lookups stay O(1) for tenants
 * with many linked banks (H5). Missing/invalid credentials raise immediately.
 * Gateway-side failures (unknown/cross-tenant id, disabled feature, tenant not
 * allowlisted, forbidden) are returned as an error so the caller can map them.
 */
async function fetchBankAccount(
  ctx: CliContext,
  bankId: string,
): Promise<{ body: Record<string, unknown> | null; error: CliError | null }> {
  resolveApiKey(ctx.globals, ctx.cwd);
  try {
    const result = await withGateway(ctx, async (gateway) => {
      const body = (await gateway.getJson(
        `/v1/admin/plaid/bank-accounts/${encodeURIComponent(bankId)}`,
      )) as Record<string, unknown>;
      return { data: body };
    });
    return { body: result.data ?? {}, error: null };
  } catch (err) {
    if (err instanceof CliError) {
      return { body: null, error: err };
    }
    throw err;
  }
}

/**
 * Map a `banks get` Gateway failure to a stable CLI error.
 *
 * Only a 404 whose reason is unrecognized or explicitly `plaid_bank_not_found`
 * collapses into `cli.plaid.bank_not_found` (unknown and cross-tenant ids are
 * indistinguishable by design). A 404 carrying a feature-gate reason
 * (`feature_disabled` / `production_not_allowlisted`) is re-raised unchanged so
 * it stays distinct and actionable via `paybond plaid ready` / `plaid doctor`.
 */
function mapBankGetError(bankId: string, fetchError: CliError): CliError {
  const details = fetchError.details ?? {};
  const gatewayCode = details.gateway_code;
  if (
    details.gateway_status === 404 &&
    (gatewayCode === undefined || gatewayCode === null || gatewayCode === "plaid_bank_not_found")
  ) {
    return plaidCliError(`linked bank not found: ${bankId}`, {
      code: "cli.plaid.bank_not_found",
      category: "not_found",
      details: { reason_code: "plaid_bank_not_found" },
    });
  }
  return fetchError;
}

async function fetchTenantEnvironment(ctx: CliContext): Promise<string | undefined> {
  try {
    resolveApiKey(ctx.globals, ctx.cwd);
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

function rejectUnexpectedArgs(argv: string[]): void {
  if (argv.length > 0) {
    throw plaidCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
}

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export async function handlePlaidReady(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPlaidSensitiveArgv(argv);
  rejectUnexpectedArgs(argv);
  const { body, error } = await fetchBankAccounts(ctx);
  const checks = buildPlaidReadyChecks(body, error);
  const useColor = shouldUseColor(ctx.globals);
  const ready = checks.every((check) => check.ok);
  return {
    data: {
      ready,
      checks,
      summary: ready ? "pass" : "fail",
      checklist_lines: formatPlaidChecklist(checks, useColor, "plaid ready"),
    },
  };
}

export async function handlePlaidDoctor(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPlaidSensitiveArgv(argv);
  rejectUnexpectedArgs(argv);
  const { body, error } = await fetchBankAccounts(ctx);
  const checks = buildPlaidDoctorChecks(body, error, {
    gatewayBase: ctx.globals.gateway,
    tenantEnvironment: await fetchTenantEnvironment(ctx),
  });
  const useColor = shouldUseColor(ctx.globals);
  return {
    data: {
      checks,
      summary: checks.every((check) => check.ok) ? "pass" : "fail",
      checklist_lines: formatPlaidChecklist(checks, useColor, "plaid doctor"),
      next_steps: [
        "Console: https://paybond.ai/console/configuration/settlement",
        "Docs: https://docs.paybond.ai/guides/configure-plaid-bank-verification",
        "Sandbox smoke: make plaid-auth-sandbox-smoke",
        "Ready: paybond plaid ready",
      ],
    },
  };
}

export async function handlePlaidBanksList(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPlaidSensitiveArgv(argv);
  rejectUnexpectedArgs(argv);
  const { body, error } = await fetchBankAccounts(ctx);
  if (error !== null) {
    throw error;
  }
  const banks = (body?.bank_accounts ?? [])
    .filter((b): b is Record<string, unknown> => Boolean(b) && typeof b === "object")
    .map(safeBankSummary);
  return {
    data: {
      environment: body?.environment ?? null,
      bank_accounts: banks,
      count: banks.length,
    },
  };
}

export async function handlePlaidBanksGet(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPlaidSensitiveArgv(argv);
  const positional = argv.filter((arg) => !arg.startsWith("-"));
  if (positional.length !== 1) {
    throw plaidCliError("usage: paybond plaid banks get <bank-account-id>", {
      code: "cli.usage.missing_argument",
      category: "usage",
    });
  }
  const bankId = positional[0]!.trim();
  if (!UUID_RE.test(bankId)) {
    throw plaidCliError(`invalid bank account id: ${bankId}`, {
      code: "cli.plaid.invalid_bank_id",
    });
  }

  const { body, error } = await fetchBankAccount(ctx, bankId);
  if (error !== null) {
    throw mapBankGetError(bankId, error);
  }
  return { data: { bank_account: safeBankSummary(body ?? {}) } };
}

export async function handlePlaidWebhookAddress(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  assertNoPlaidSensitiveArgv(argv);
  rejectUnexpectedArgs(argv);
  const address = resolvePlaidWebhookAddress(ctx.globals.gateway);
  return {
    data: {
      webhook_address: address,
      route: "/webhooks/plaid",
      note:
        "Set PLAID_WEBHOOK_URL to this address on the gateway deploy (https required in production). " +
        "For local development, tunnel this route instead of committing a tunnel URL — see " +
        "docs/operations/plaid-account-verification-setup.md.",
    },
  };
}

export async function handlePlaidBanks(
  ctx: CliContext,
  second: string,
  argv: string[],
): Promise<CommandResult> {
  if (second === "list") {
    return handlePlaidBanksList(ctx, argv);
  }
  if (second === "get") {
    return handlePlaidBanksGet(ctx, argv);
  }
  throw plaidCliError(`unknown plaid banks subcommand: banks ${second}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}

/** Dispatch `paybond plaid <subcommand>`. */
export async function handlePlaid(
  ctx: CliContext,
  second: string,
  argv: string[],
): Promise<CommandResult> {
  if (second === "ready") {
    return handlePlaidReady(ctx, argv);
  }
  if (second === "doctor") {
    return handlePlaidDoctor(ctx, argv);
  }
  if (second === "webhook-address") {
    return handlePlaidWebhookAddress(ctx, argv);
  }
  throw plaidCliError(`unknown plaid subcommand: plaid ${second}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
