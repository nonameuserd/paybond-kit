import { Paybond } from "../index.js";
import { resolveApiKeyWithMeta } from "./credentials.js";
import type { CliContext } from "./context.js";

export type PaybondCliSession = {
  paybond: Paybond;
  apiKey: string;
  warnings: string[];
};

/** Open a Paybond SDK session for general CLI commands (uses ctx.fetch for gateway I/O). */
export async function withPaybondCli<T>(
  ctx: CliContext,
  handler: (session: PaybondCliSession) => Promise<T>,
): Promise<T> {
  const resolved = await resolveApiKeyWithMeta(ctx.globals, ctx.cwd);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = ctx.fetch;
  const paybond = await Paybond.open({
    apiKey: resolved.apiKey,
    gatewayBaseUrl: ctx.globals.gateway,
  });
  try {
    return await handler({
      paybond,
      apiKey: resolved.apiKey,
      warnings: resolved.warnings,
    });
  } finally {
    await paybond.aclose();
    globalThis.fetch = originalFetch;
  }
}
