import { Paybond, type PaybondEnvironment } from "../../index.js";
import { resolveApiKeyWithMeta } from "../credentials.js";
import type { CliContext } from "../context.js";
import { CliError } from "../types.js";

export function apiKeyEnvironment(apiKey: string): PaybondEnvironment | "unknown" {
  if (apiKey.includes("_sandbox_")) {
    return "sandbox";
  }
  if (apiKey.includes("_live_")) {
    return "live";
  }
  return "unknown";
}

export function assertAgentSandboxDefault(apiKey: string, production: boolean): void {
  if (production) {
    return;
  }
  const env = apiKeyEnvironment(apiKey);
  if (env === "live") {
    throw new CliError(
      "agent commands default to sandbox-only; pass --production to use live credentials",
      {
        category: "validation",
        code: "cli.agent.production_required",
        exitCode: 1,
      },
    );
  }
}

export type PaybondAgentCliSession = {
  paybond: Paybond;
  apiKey: string;
  warnings: string[];
};

/**
 * Open a Paybond SDK session and run gateway-backed agent middleware work while
 * `ctx.fetch` is patched (bootstrap, verify, evidence, spend complete).
 */
export async function withPaybondAgentCli<T>(
  ctx: CliContext,
  production: boolean,
  handler: (session: PaybondAgentCliSession) => Promise<T>,
): Promise<T> {
  const resolved = await resolveApiKeyWithMeta(ctx.globals, ctx.cwd);
  assertAgentSandboxDefault(resolved.apiKey, production);
  const expectedEnvironment: PaybondEnvironment | undefined = production ? undefined : "sandbox";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = ctx.fetch;
  try {
    const paybond = await Paybond.open({
      apiKey: resolved.apiKey,
      gatewayBaseUrl: ctx.globals.gateway,
      expectedEnvironment,
    });
    return await handler({
      paybond,
      apiKey: resolved.apiKey,
      warnings: resolved.warnings,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
}

/** @deprecated Use {@link withPaybondAgentCli} so SDK gateway calls stay on `ctx.fetch`. */
export async function openPaybondForAgentCli(
  ctx: CliContext,
  production: boolean,
): Promise<PaybondAgentCliSession> {
  return withPaybondAgentCli(ctx, production, async (session) => session);
}
