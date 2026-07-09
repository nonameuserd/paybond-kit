import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { getOrder } from "../../shopify/order.js";
import { getSolutionSmokeDefaults } from "../../solutions/catalog.js";
import { devTraceUrl } from "../../dev/trace-buffer.js";
import { colorize, shouldUseColor } from "../color.js";
import type { CliContext } from "../context.js";
import { withGateway } from "../context.js";
import { resolveApiKey } from "../credentials.js";
import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import { requireSecureGatewayUrl } from "../../gateway-url.js";
import { CliError, type CommandResult, type ErrorCategory } from "../types.js";
import { handleAgentSandboxSmoke } from "./agent.js";
import { assertOfflineDevCredentialsSafe, beginOfflineDevSession } from "../offline-session.js";

export type ShopifyDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

type ExternalCommandResult = {
  code: number;
  stdout: string;
  stderr: string;
};

type ShopifyCommandHooks = {
  whichExecutable?: (name: string) => Promise<string | null>;
  runCommand?: (command: string, args: string[]) => Promise<ExternalCommandResult>;
};

let commandHooks: ShopifyCommandHooks = {};

/** Test hook: override external CLI discovery and execution. */
export function setShopifyCommandHooks(hooks: ShopifyCommandHooks): void {
  commandHooks = hooks;
}

function shopifyCliError(
  message: string,
  options: { code: string; category?: ErrorCategory; details?: Record<string, unknown> },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    details: options.details ?? {},
  });
}

async function defaultWhichExecutable(name: string): Promise<string | null> {
  const lookup = process.platform === "win32" ? "where" : "which";
  const result = await defaultRunCommand(lookup, [name]);
  if (result.code !== 0) {
    return null;
  }
  const line = result.stdout.split(/\r?\n/).find((entry) => entry.trim().length > 0);
  return line?.trim() ?? null;
}

function defaultRunCommand(command: string, args: string[]): Promise<ExternalCommandResult> {
  return new Promise((resolvePromise) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err) => {
      resolvePromise({ code: 127, stdout: "", stderr: err.message });
    });
    child.on("close", (code) => {
      resolvePromise({ code: code ?? 1, stdout, stderr });
    });
  });
}

async function whichExecutable(name: string): Promise<string | null> {
  return (commandHooks.whichExecutable ?? defaultWhichExecutable)(name);
}

async function runCommand(command: string, args: string[]): Promise<ExternalCommandResult> {
  return (commandHooks.runCommand ?? defaultRunCommand)(command, args);
}

export type ShopifyAppTomlInfo = {
  exists: boolean;
  clientId?: string;
  path?: string;
};

/** Parse `client_id` from a linked `shopify.app.toml` in the working directory. */
export async function readShopifyAppToml(cwd: string): Promise<ShopifyAppTomlInfo> {
  const path = join(cwd, "shopify.app.toml");
  try {
    const content = await readFile(path, "utf8");
    const match = content.match(/^\s*client_id\s*=\s*"([^"]+)"/m);
    return { exists: true, clientId: match?.[1], path };
  } catch {
    return { exists: false };
  }
}

function resolveShopDomain(raw: string | undefined, cwd: string): string | undefined {
  const fromArg = raw?.trim();
  if (fromArg) {
    return fromArg.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
  const fromEnv = process.env.SHOPIFY_DEV_STORE?.trim();
  if (fromEnv) {
    return fromEnv.replace(/^https?:\/\//, "").replace(/\/$/, "");
  }
  return undefined;
}

function formatDoctorChecklistLine(check: ShopifyDoctorCheck, useColor: boolean): string {
  const prefix = check.ok ? colorize("✓", "green", useColor) : colorize("✗", "yellow", useColor);
  return `${prefix} ${check.name}: ${check.message}`;
}

export function formatShopifyDoctorChecklist(checks: ShopifyDoctorCheck[], useColor: boolean): string[] {
  const lines = checks.map((check) => formatDoctorChecklistLine(check, useColor));
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(colorize(`shopify doctor: ${summary}`, summary === "pass" ? "green" : "yellow", useColor));
  return lines;
}

export function buildShopifyNextStepsBanner(shopDomain?: string): string[] {
  const shop = shopDomain ?? "paybond-agent-commerce-dev.myshopify.com";
  return [
    "",
    "── Shopify next steps ──",
    "  Terminal 1: paybond dev trace",
    "  Terminal 2: cd examples/shopify-dev-loop && shopify app dev",
    `  Smoke: paybond shopify checkout smoke --shop ${shop}`,
    "  Doctor: paybond shopify doctor",
    "  Docs: https://docs.paybond.ai/kit/shopify-cli",
  ];
}

/** Resolve a Paybond gateway origin to the Shopify sandbox webhook path. */
export function resolveShopifyWebhookAddress(gatewayBase: string, tunnel?: string): string {
  const origin = (tunnel?.trim() || gatewayBase).trim().replace(/\/$/, "");
  const secure = requireSecureGatewayUrl(origin);
  return `${secure}/webhooks/sandbox/shopify`;
}

export function buildShopifyWebhookTriggerCommand(input: {
  topic: string;
  address: string;
  clientId?: string;
}): string[] {
  const args = ["app", "webhook", "trigger", `--topic=${input.topic}`, `--address=${input.address}`];
  if (input.clientId && !input.clientId.startsWith("env:")) {
    args.push(`--client-id=${input.clientId}`);
  }
  return args;
}

type SettlementConfigSnapshot = {
  shopify_linked_shop_configured?: boolean;
  shopify_shop_domain_masked?: string;
  shopify_manual_capture_required?: boolean;
  shopify_payments_linked?: boolean;
  shopify_payments_shop_domain_masked?: string;
  shopify_payments_app_ready?: boolean;
  shopify_payments_mtls_configured?: boolean;
  rail_readiness?: Array<{ rail?: string; ready?: boolean; message?: string }>;
};

async function fetchSettlementConfig(ctx: CliContext): Promise<SettlementConfigSnapshot | null> {
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
    return result.data as SettlementConfigSnapshot;
  } catch {
    return null;
  }
}

function railReadinessForShopifyPayments(config: SettlementConfigSnapshot | null): ShopifyDoctorCheck {
  const readiness = config?.rail_readiness?.find((entry) => entry.rail === "shopify_payments_app");
  if (!readiness) {
    return {
      name: "payments_rail_readiness",
      ok: false,
      message: "shopify_payments_app readiness unavailable (login and link the Paybond Payments app)",
    };
  }
  return {
    name: "payments_rail_readiness",
    ok: readiness.ready === true,
    message: readiness.message ?? (readiness.ready ? "shopify_payments_app ready" : "not ready"),
    details: { rail: readiness.rail, ready: readiness.ready },
  };
}

/** Locate a Paybond Payments `shopify.app.toml` for local dev (cwd or monorepo app path). */
export async function readShopifyPaymentsAppToml(cwd: string): Promise<ShopifyAppTomlInfo> {
  const candidates = [
    join(cwd, "shopify.app.toml"),
    join(cwd, "apps/shopify-payments/shopify.app.toml"),
  ];
  for (const path of candidates) {
    try {
      const content = await readFile(path, "utf8");
      const match = content.match(/^\s*client_id\s*=\s*"([^"]+)"/m);
      return { exists: true, clientId: match?.[1], path };
    } catch {
      // try next candidate
    }
  }
  return { exists: false };
}

export function buildShopifyPaymentsNextStepsBanner(shopDomain?: string): string[] {
  const shop = shopDomain ?? "paybond-agent-commerce-dev.myshopify.com";
  return [
    "",
    "── Shopify Payments app next steps ──",
    "  Terminal 1: paybond dev trace",
    "  Terminal 2: cd apps/shopify-payments && shopify app dev",
    `  Smoke: paybond shopify payments smoke --shop ${shop}`,
    "  Doctor: paybond shopify payments doctor",
    "  Docs: https://docs.paybond.ai/guides/configure-shopify-settlement",
  ];
}

function railReadinessForShopify(config: SettlementConfigSnapshot | null): ShopifyDoctorCheck {
  const readiness = config?.rail_readiness?.find((entry) => entry.rail === "shopify_authorized_order");
  if (!readiness) {
    return {
      name: "rail_readiness",
      ok: false,
      message: "shopify_authorized_order readiness unavailable (login and link a shop)",
    };
  }
  return {
    name: "rail_readiness",
    ok: readiness.ready === true,
    message: readiness.message ?? (readiness.ready ? "shopify_authorized_order ready" : "not ready"),
    details: { rail: readiness.rail, ready: readiness.ready },
  };
}

/** Readiness checks for Paybond + Shopify local development. */
export async function runShopifyDoctorChecks(ctx: CliContext): Promise<ShopifyDoctorCheck[]> {
  const checks: ShopifyDoctorCheck[] = [];
  const shopifyPath = await whichExecutable("shopify");
  if (shopifyPath) {
    const version = await runCommand(shopifyPath, ["version"]);
    const message = version.stdout.trim() || version.stderr.trim() || "shopify CLI found";
    checks.push({
      name: "shopify_cli",
      ok: version.code === 0,
      message: version.code === 0 ? message.split("\n")[0] ?? message : message,
      details: { path: shopifyPath },
    });
  } else {
    checks.push({
      name: "shopify_cli",
      ok: false,
      message: "not on PATH — install: npm install -g @shopify/cli@latest",
    });
  }

  const ucpPath = await whichExecutable("ucp");
  if (ucpPath) {
    const version = await runCommand(ucpPath, ["--version"]);
    const message = version.stdout.trim() || version.stderr.trim() || "ucp CLI found";
    checks.push({
      name: "ucp_cli",
      ok: version.code === 0,
      message: version.code === 0 ? message.split("\n")[0] ?? message : message,
      details: { path: ucpPath },
    });
  } else {
    checks.push({
      name: "ucp_cli",
      ok: false,
      message: "not on PATH (optional) — install: npm install -g @shopify/ucp-cli",
    });
  }

  const appToml = await readShopifyAppToml(ctx.cwd);
  checks.push({
    name: "shopify_app_toml",
    ok: appToml.exists,
    message: appToml.exists
      ? `found ${appToml.path ?? "shopify.app.toml"}`
      : "shopify.app.toml not found in cwd — run shopify app config link",
    details: appToml.clientId ? { client_id: appToml.clientId } : undefined,
  });

  const shopDomain = resolveShopDomain(undefined, ctx.cwd);
  checks.push({
    name: "dev_store",
    ok: Boolean(shopDomain),
    message: shopDomain
      ? `SHOPIFY_DEV_STORE=${shopDomain}`
      : "set SHOPIFY_DEV_STORE in .env.local or pass --shop",
  });

  const settlement = await fetchSettlementConfig(ctx);
  checks.push({
    name: "paybond_shop_linked",
    ok: settlement?.shopify_linked_shop_configured === true,
    message: settlement?.shopify_linked_shop_configured
      ? `linked shop ${settlement.shopify_shop_domain_masked ?? "(masked)"}`
      : "link a shop in Console → Configuration → Settlement",
  });

  checks.push({
    name: "manual_capture",
    ok: settlement ? settlement.shopify_manual_capture_required !== true : false,
    message: settlement?.shopify_manual_capture_required
      ? "enable manual payment capture in Shopify Admin (required for shopify_authorized_order)"
      : settlement
        ? "manual capture prerequisite satisfied or not required"
        : "skipped (missing settlement config)",
  });

  checks.push(railReadinessForShopify(settlement));
  return checks;
}

export async function handleShopifyDoctor(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  if (argv.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const checks = await runShopifyDoctorChecks(ctx);
  const useColor = shouldUseColor(ctx.globals);
  return {
    data: {
      checks,
      summary: checks.every((check) => check.ok) ? "pass" : "fail",
      checklist_lines: formatShopifyDoctorChecklist(checks, useColor),
    },
  };
}

export async function handleShopifyLink(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  if (argv.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const appToml = await readShopifyAppToml(ctx.cwd);
  const clientId =
    appToml.clientId && !appToml.clientId.startsWith("env:")
      ? appToml.clientId
      : process.env.SHOPIFY_FLAG_CLIENT_ID?.trim();
  const configLink = clientId
    ? `shopify app config link --client-id=${clientId}`
    : "shopify app config link";
  const useColor = shouldUseColor(ctx.globals);
  const lines = [
    colorize("Shopify + Paybond link workflow", "cyan", useColor),
    "",
    "1. paybond login",
    "2. Console → Configuration → Settlement → Link Shopify store",
    "   https://paybond.ai/console/configuration/settlement",
    `3. ${configLink}`,
    "",
    "Agents must not hold Shopify offline access tokens — linking is tenant-admin only.",
  ];
  return {
    data: {
      steps: [
        { step: 1, action: "paybond login" },
        { step: 2, action: "link_shop_in_console", url: "https://paybond.ai/console/configuration/settlement" },
        { step: 3, action: configLink },
      ],
      config_link_command: configLink,
      checklist_lines: lines,
    },
  };
}

export async function handleShopifyDev(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const tunnelFlag = consumeFlag(rest, "--tunnel");
  rest = tunnelFlag.rest;
  if (rest.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const traceUrl = devTraceUrl();
  const webhookAddress = resolveShopifyWebhookAddress(ctx.globals.gateway, tunnelFlag.value);
  const appToml = await readShopifyAppToml(ctx.cwd);
  const useColor = shouldUseColor(ctx.globals);
  const lines = [
    colorize("Paybond + Shopify local dev (two terminals)", "cyan", useColor),
    "",
    "Terminal 1 — Paybond trace:",
    `  paybond dev trace    # ${traceUrl}`,
    "",
    "Terminal 2 — Shopify app dev:",
    appToml.exists ? "  shopify app dev" : "  shopify app config link && shopify app dev",
    "",
    `Webhook address (sandbox): ${webhookAddress}`,
    "",
    "Terminal 3 — smoke:",
    "  paybond shopify checkout smoke --shop $SHOPIFY_DEV_STORE",
  ];
  return {
    data: {
      trace_url: traceUrl,
      shopify_command: "shopify app dev",
      webhook_address: webhookAddress,
      checklist_lines: lines,
    },
  };
}

export async function handleShopifyWebhookTrigger(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const topicFlag = consumeFlag(rest, "--topic");
  rest = topicFlag.rest;
  const gatewayFlag = consumeFlag(rest, "--gateway");
  rest = gatewayFlag.rest;
  const addressFlag = consumeFlag(rest, "--address");
  rest = addressFlag.rest;
  const dryRunFlag = consumeBooleanFlag(rest, "--dry-run");
  rest = dryRunFlag.rest;
  if (rest.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const topic = topicFlag.value?.trim() || "orders/paid";
  const address =
    addressFlag.value?.trim() ||
    resolveShopifyWebhookAddress(gatewayFlag.value ?? ctx.globals.gateway, undefined);
  const appToml = await readShopifyAppToml(ctx.cwd);
  const clientId =
    appToml.clientId && !appToml.clientId.startsWith("env:")
      ? appToml.clientId
      : process.env.SHOPIFY_FLAG_CLIENT_ID?.trim();
  const shopifyPath = await whichExecutable("shopify");
  if (!shopifyPath) {
    throw shopifyCliError("shopify CLI not on PATH — install: npm install -g @shopify/cli@latest", {
      code: "cli.shopify.missing_cli",
      category: "environment",
    });
  }
  const triggerArgs = buildShopifyWebhookTriggerCommand({ topic, address, clientId });
  const commandLine = `shopify ${triggerArgs.join(" ")}`;
  if (dryRunFlag.present) {
    return {
      data: {
        topic,
        address,
        command: commandLine,
        dry_run: true,
      },
    };
  }
  const result = await runCommand(shopifyPath, triggerArgs);
  if (result.code !== 0) {
    throw shopifyCliError(result.stderr.trim() || result.stdout.trim() || "shopify webhook trigger failed", {
      code: "cli.shopify.webhook_trigger_failed",
      details: { command: commandLine, exit_code: result.code },
    });
  }
  return {
    data: {
      topic,
      address,
      command: commandLine,
      stdout: result.stdout.trim(),
    },
  };
}

export async function handleShopifyCheckoutSmoke(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const shopFlag = consumeFlag(rest, "--shop");
  rest = shopFlag.rest;
  const spendFlag = consumeFlag(rest, "--requested-spend-cents");
  rest = spendFlag.rest;
  const offlineFlag = consumeBooleanFlag(rest, "--offline");
  rest = offlineFlag.rest;
  if (rest.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const defaults = getSolutionSmokeDefaults("shopping");
  const shop = resolveShopDomain(shopFlag.value, ctx.cwd) ?? "paybond-agent-commerce-dev.myshopify.com";
  const spendCents = spendFlag.value ? Number.parseInt(spendFlag.value, 10) : defaults.requestedSpendCents;
  if (!Number.isFinite(spendCents) || spendCents <= 0) {
    throw shopifyCliError("invalid --requested-spend-cents", {
      code: "cli.usage.invalid_spend",
      category: "usage",
    });
  }
  const resultBody = {
    ...defaults.resultBody,
    order_id: "gid://shopify/Order/123",
    shop,
  };
  const smokeArgv = [
    "--preset",
    "shopping",
    "--requested-spend-cents",
    String(spendCents),
    "--result-body",
    JSON.stringify(resultBody),
  ];
  if (offlineFlag.present) {
    await assertOfflineDevCredentialsSafe(ctx);
  }
  const offlineSession = offlineFlag.present ? beginOfflineDevSession(ctx) : null;
  const smokeCtx = offlineSession?.ctx ?? ctx;
  const smokeResult = await handleAgentSandboxSmoke(smokeCtx, smokeArgv);
  offlineSession?.restore();
  const ucpPath = await whichExecutable("ucp");
  const useColor = shouldUseColor(ctx.globals);
  const lines = [
    colorize("shopify checkout smoke", "cyan", useColor),
    ucpPath
      ? colorize("ucp CLI detected — use createCheckoutWithBinding for live UCP checkout", "dim", useColor)
      : colorize("ucp CLI not on PATH — used paybond agent sandbox smoke fallback", "dim", useColor),
    `shop: ${shop}`,
    `binding note_attributes: paybond_intent_id + tenant_id (injected by Kit on live checkout)`,
  ];
  const checklist = Array.isArray(smokeResult.data.checklist_lines)
    ? (smokeResult.data.checklist_lines as string[])
    : [];
  return {
    data: {
      ...smokeResult.data,
      shop,
      ucp_available: Boolean(ucpPath),
      checklist_lines: [...lines, ...checklist],
    },
    warnings: smokeResult.warnings,
  };
}

export async function handleShopifyOrderShow(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  const orderId = argv[0]?.trim();
  let rest = argv.slice(1);
  const shopFlag = consumeFlag(rest, "--shop");
  rest = shopFlag.rest;
  if (!orderId || rest.length > 0) {
    throw shopifyCliError("usage: paybond shopify order show <id> [--shop <domain>]", {
      code: "cli.usage.invalid_args",
      category: "usage",
    });
  }
  const shop = resolveShopDomain(shopFlag.value, ctx.cwd);
  if (!shop) {
    throw shopifyCliError("missing --shop or SHOPIFY_DEV_STORE", {
      code: "cli.shopify.missing_shop",
      category: "usage",
    });
  }
  const order = await getOrder({ shopDomain: shop, orderId, fetchUcp: ctx.fetch ?? fetch });
  return {
    data: {
      order,
      binding: order.binding,
      financial_status: order.financial_status,
    },
  };
}

export async function handleShopifyCaptureReady(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  if (argv.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const settlement = await fetchSettlementConfig(ctx);
  if (!settlement) {
    throw shopifyCliError("settlement config unavailable — run paybond login", {
      code: "cli.shopify.missing_settlement",
    });
  }
  const readiness = railReadinessForShopify(settlement);
  const checks: ShopifyDoctorCheck[] = [
    {
      name: "shop_linked",
      ok: settlement.shopify_linked_shop_configured === true,
      message: settlement.shopify_linked_shop_configured
        ? `linked ${settlement.shopify_shop_domain_masked ?? "shop"}`
        : "link a Shopify shop in Console",
    },
    {
      name: "manual_capture",
      ok: settlement.shopify_manual_capture_required !== true,
      message: settlement.shopify_manual_capture_required
        ? "enable manual payment capture in Shopify Admin"
        : "manual capture prerequisite satisfied",
    },
    readiness,
  ];
  const useColor = shouldUseColor(ctx.globals);
  const ready = checks.every((check) => check.ok);
  return {
    data: {
      ready,
      checks,
      checklist_lines: formatShopifyDoctorChecklist(checks, useColor),
    },
  };
}

export async function runShopifyPaymentsDoctorChecks(ctx: CliContext): Promise<ShopifyDoctorCheck[]> {
  const checks: ShopifyDoctorCheck[] = [];
  const shopifyPath = await whichExecutable("shopify");
  checks.push({
    name: "shopify_cli",
    ok: Boolean(shopifyPath),
    message: shopifyPath
      ? `found at ${shopifyPath}`
      : "not on PATH — install: npm install -g @shopify/cli@latest",
    details: shopifyPath ? { path: shopifyPath } : undefined,
  });

  const appToml = await readShopifyPaymentsAppToml(ctx.cwd);
  checks.push({
    name: "payments_app_toml",
    ok: appToml.exists,
    message: appToml.exists
      ? `found ${appToml.path ?? "shopify.app.toml"}`
      : "shopify.app.toml not found — run: cd apps/shopify-payments && shopify app config link",
    details: appToml.clientId ? { client_id: appToml.clientId } : undefined,
  });

  const shopDomain = resolveShopDomain(undefined, ctx.cwd);
  checks.push({
    name: "dev_store",
    ok: Boolean(shopDomain),
    message: shopDomain
      ? `SHOPIFY_DEV_STORE=${shopDomain}`
      : "set SHOPIFY_DEV_STORE in .env.local or pass --shop",
  });

  const settlement = await fetchSettlementConfig(ctx);
  checks.push({
    name: "payments_app_linked",
    ok: settlement?.shopify_payments_linked === true,
    message: settlement?.shopify_payments_linked
      ? `linked shop ${settlement.shopify_payments_shop_domain_masked ?? "(masked)"}`
      : "link the Paybond Payments app in Console → Configuration → Settlement",
  });
  checks.push({
    name: "payments_app_ready",
    ok: settlement?.shopify_payments_app_ready === true,
    message: settlement?.shopify_payments_app_ready
      ? "paymentsAppConfigure marked ready"
      : settlement
        ? "mark the Paybond Payments app ready in Console after install"
        : "skipped (missing settlement config)",
  });
  checks.push({
    name: "payments_mtls",
    ok: settlement?.shopify_payments_mtls_configured === true,
    message: settlement?.shopify_payments_mtls_configured
      ? "Shopify Payments mTLS ingress configured"
      : settlement
        ? "mTLS ingress not configured (required for production; optional on local dev tunnels)"
        : "skipped (missing settlement config)",
  });
  checks.push(railReadinessForShopifyPayments(settlement));
  return checks;
}

export async function handleShopifyPaymentsDoctor(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  if (argv.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${argv.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const checks = await runShopifyPaymentsDoctorChecks(ctx);
  const useColor = shouldUseColor(ctx.globals);
  const lines = checks.map((check) => formatDoctorChecklistLine(check, useColor));
  const summary = checks.every((check) => check.ok) ? "pass" : "fail";
  lines.push(colorize(`shopify payments doctor: ${summary}`, summary === "pass" ? "green" : "yellow", useColor));
  return {
    data: {
      checks,
      summary,
      checklist_lines: lines,
      next_steps: buildShopifyPaymentsNextStepsBanner(resolveShopDomain(undefined, ctx.cwd)),
    },
  };
}

export async function handleShopifyPaymentsSmoke(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  let rest = argv;
  const shopFlag = consumeFlag(rest, "--shop");
  rest = shopFlag.rest;
  const spendFlag = consumeFlag(rest, "--requested-spend-cents");
  rest = spendFlag.rest;
  const offlineFlag = consumeBooleanFlag(rest, "--offline");
  rest = offlineFlag.rest;
  if (rest.length > 0) {
    throw shopifyCliError(`unexpected arguments: ${rest.join(" ")}`, {
      code: "cli.usage.unexpected_args",
      category: "usage",
    });
  }
  const defaults = getSolutionSmokeDefaults("shopping");
  const shop = resolveShopDomain(shopFlag.value, ctx.cwd) ?? "paybond-agent-commerce-dev.myshopify.com";
  const spendCents = spendFlag.value ? Number.parseInt(spendFlag.value, 10) : defaults.requestedSpendCents;
  if (!Number.isFinite(spendCents) || spendCents <= 0) {
    throw shopifyCliError("invalid --requested-spend-cents", {
      code: "cli.usage.invalid_spend",
      category: "usage",
    });
  }
  const paymentSessionId = "paybond-smoke-payment-session";
  const resultBody = {
    ...defaults.resultBody,
    shop,
    payment_session_id: paymentSessionId,
    payment_session_gid: `gid://shopify/PaymentSession/${paymentSessionId}`,
    test_mode: true,
    settlement_rail: "shopify_payments_app",
  };
  const smokeArgv = [
    "--preset",
    "shopping",
    "--requested-spend-cents",
    String(spendCents),
    "--result-body",
    JSON.stringify(resultBody),
  ];
  if (offlineFlag.present) {
    await assertOfflineDevCredentialsSafe(ctx);
  }
  const offlineSession = offlineFlag.present ? beginOfflineDevSession(ctx) : null;
  const smokeCtx = offlineSession?.ctx ?? ctx;
  const smokeResult = await handleAgentSandboxSmoke(smokeCtx, smokeArgv);
  offlineSession?.restore();
  const useColor = shouldUseColor(ctx.globals);
  const lines = [
    colorize("shopify payments smoke", "cyan", useColor),
    "binding transaction_metadata: tenant_id + paybond_intent_id",
    `shop: ${shop}`,
    "live dev store: cd apps/shopify-payments && shopify app dev",
    "then complete a test-mode checkout and run: paybond shopify payments session show <payment_session_id>",
  ];
  const checklist = Array.isArray(smokeResult.data.checklist_lines)
    ? (smokeResult.data.checklist_lines as string[])
    : [];
  return {
    data: {
      ...smokeResult.data,
      shop,
      payment_session_id: paymentSessionId,
      checklist_lines: [...lines, ...checklist, ...buildShopifyPaymentsNextStepsBanner(shop)],
    },
    warnings: smokeResult.warnings,
  };
}

export async function handleShopifyPaymentsSessionShow(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }
  const sessionId = argv[0]?.trim();
  let rest = argv.slice(1);
  const shopFlag = consumeFlag(rest, "--shop");
  rest = shopFlag.rest;
  if (!sessionId || rest.length > 0) {
    throw shopifyCliError("usage: paybond shopify payments session show <id> [--shop <domain>]", {
      code: "cli.usage.invalid_args",
      category: "usage",
    });
  }
  const shop = resolveShopDomain(shopFlag.value, ctx.cwd);
  try {
    await resolveApiKey(ctx.globals, ctx.cwd);
  } catch {
    throw shopifyCliError("session show requires paybond login", {
      code: "cli.shopify.missing_credentials",
    });
  }
  const result = await withGateway(ctx, async (gateway) => {
    const body = await gateway.getJson(
      `/v1/admin/shopify/payments/sessions/${encodeURIComponent(sessionId)}`,
    );
    return { data: body };
  });
  const session = result.data as Record<string, unknown>;
  if (shop && typeof session.shop_domain === "string" && session.shop_domain !== shop) {
    throw shopifyCliError("session shop_domain does not match --shop", {
      code: "cli.shopify.session_shop_mismatch",
      details: { shop_domain: session.shop_domain, shop },
    });
  }
  return { data: { session } };
}

export async function handleShopify(
  ctx: CliContext,
  subcommand: string,
  third: string | undefined,
  fourth: string | undefined,
  argv: string[],
): Promise<CommandResult> {
  if (subcommand === "payments") {
    if (third === "doctor") {
      return handleShopifyPaymentsDoctor(ctx, argv);
    }
    if (third === "smoke") {
      return handleShopifyPaymentsSmoke(ctx, argv);
    }
    if (third === "session" && fourth === "show") {
      return handleShopifyPaymentsSessionShow(ctx, argv);
    }
    throw shopifyCliError(`unknown shopify payments subcommand: shopify payments ${third ?? ""}`, {
      code: "cli.usage.unknown_command",
      category: "usage",
    });
  }
  if (subcommand === "doctor") {
    return handleShopifyDoctor(ctx, argv);
  }
  if (subcommand === "link") {
    return handleShopifyLink(ctx, argv);
  }
  if (subcommand === "dev") {
    return handleShopifyDev(ctx, argv);
  }
  if (subcommand === "webhook" && third === "trigger") {
    return handleShopifyWebhookTrigger(ctx, argv);
  }
  if (subcommand === "checkout" && third === "smoke") {
    return handleShopifyCheckoutSmoke(ctx, argv);
  }
  if (subcommand === "order" && third === "show") {
    return handleShopifyOrderShow(ctx, argv);
  }
  if (subcommand === "capture" && third === "ready") {
    return handleShopifyCaptureReady(ctx, argv);
  }
  throw shopifyCliError(`unknown shopify subcommand: shopify ${subcommand}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
