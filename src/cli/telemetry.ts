import { createHash, randomUUID } from "node:crypto";
import { platform } from "node:os";

import type { CliContext } from "./context.js";
import { loadConfigFile, saveConfigFile } from "./config.js";
import { packageVersion } from "./doctor-agent.js";
import { isLocalGatewayHost } from "../gateway-url.js";

export type CliTelemetryCommand = "dev loop" | "dev smoke";

const INSTALL_ID_HASH_PREFIX = "paybond-kit-cli:";

function telemetryEnvDisabled(): boolean {
  const raw = process.env.PAYBOND_TELEMETRY?.trim().toLowerCase();
  return raw === "0" || raw === "false" || raw === "off" || raw === "no";
}

function telemetryEnvForced(): boolean {
  const raw = process.env.PAYBOND_TELEMETRY?.trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "on" || raw === "yes";
}

function isCiEnvironment(): boolean {
  const ci = process.env.CI?.trim().toLowerCase();
  return ci === "true" || ci === "1";
}

function isLocalGateway(gateway: string): boolean {
  try {
    return isLocalGatewayHost(new URL(gateway).hostname);
  } catch {
    return true;
  }
}

export function hashCliInstallId(installId: string): string {
  return createHash("sha256").update(`${INSTALL_ID_HASH_PREFIX}${installId}`).digest("hex");
}

export async function resolveCliInstallId(): Promise<string> {
  const config = await loadConfigFile();
  const existing = config.install_id?.trim();
  if (existing) {
    return existing;
  }
  const installId = randomUUID();
  await saveConfigFile({ ...config, install_id: installId });
  return installId;
}

export async function cliTelemetryEnabled(gateway: string): Promise<boolean> {
  if (telemetryEnvDisabled() || isCiEnvironment()) {
    return false;
  }
  if (telemetryEnvForced()) {
    return true;
  }
  const config = await loadConfigFile();
  if (config.telemetry === false) {
    return false;
  }
  return !isLocalGateway(gateway);
}

/**
 * Fire-and-forget adoption telemetry for successful local dev commands.
 * Failures are swallowed so CLI workflows never depend on analytics.
 */
export async function reportCliCommandSuccess(
  ctx: CliContext,
  input: Readonly<{
    commandPath: CliTelemetryCommand;
    offline: boolean;
  }>,
): Promise<void> {
  if (!(await cliTelemetryEnabled(ctx.globals.gateway))) {
    return;
  }

  const installId = await resolveCliInstallId();
  const body = {
    command_path: input.commandPath,
    success: true,
    offline: input.offline,
    kit_version: packageVersion(),
    runtime: "node",
    install_id_sha256: hashCliInstallId(installId),
    os_name: platform(),
    client_context: {
      format: ctx.globals.format,
    },
  };

  const url = `${ctx.globals.gateway.replace(/\/+$/, "")}/v1/public/analytics/kit-cli`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 2_000);
  try {
    await ctx.fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch {
    // Telemetry must never block or fail the CLI command.
  } finally {
    clearTimeout(timeout);
  }
}

export function scheduleCliCommandTelemetry(
  ctx: CliContext,
  input: Readonly<{
    commandPath: CliTelemetryCommand;
    offline: boolean;
  }>,
): void {
  void reportCliCommandSuccess(ctx, input);
}
