import {
  activateOfflineDevMode,
  createOfflineDevGatewayFetch,
  isProductionApiKey,
} from "../dev/offline-gateway.js";
import { loadEnvFile } from "./credentials.js";
import type { CliContext } from "./context.js";
import { CliError } from "./types.js";

export type OfflineDevSession = {
  ctx: CliContext;
  restore: () => void;
};

function rejectOfflineWithProductionKey(apiKey: string | undefined): void {
  const trimmed = apiKey?.trim();
  if (trimmed && isProductionApiKey(trimmed)) {
    throw new CliError(
      "offline dev mode cannot be used with production API keys (paybond_sk_live_...); unset PAYBOND_API_KEY or use a sandbox key",
      {
        category: "validation",
        code: "cli.dev.offline_production_key",
        exitCode: 1,
      },
    );
  }
}

/** Reject offline mode when production credentials are present in env or env file. */
export async function assertOfflineDevCredentialsSafe(ctx: CliContext): Promise<void> {
  rejectOfflineWithProductionKey(process.env.PAYBOND_API_KEY);
  if (process.env.PAYBOND_API_KEY?.trim()) {
    return;
  }
  const fromFile = await loadEnvFile(ctx.globals.envFile, ctx.cwd);
  rejectOfflineWithProductionKey(fromFile);
}

/** Patch ctx.fetch with the in-process offline Gateway mock. */
export function beginOfflineDevSession(ctx: CliContext): OfflineDevSession {
  const { restore } = activateOfflineDevMode();
  return {
    ctx: {
      ...ctx,
      fetch: createOfflineDevGatewayFetch(),
    },
    restore,
  };
}
