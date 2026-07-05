import { resolveAgentRecognitionFromCli, type AgentRecognitionCredentials } from "./agent/production-evidence.js";
import type { CliContext } from "./context.js";
import { consumeFlag } from "./globals.js";

/** Parsed recognition and idempotency flags for Harbor intent mutation CLI commands. */
export type HarborMutationFlags = {
  recognitionKeyId?: string;
  recognitionSeedHex?: string;
  idempotencyKey?: string;
  restArgv: string[];
};

/** Extract shared Harbor mutation flags from argv, leaving body and positional args in restArgv. */
export function parseHarborMutationFlags(argv: string[]): HarborMutationFlags {
  const recognitionKeyFlag = consumeFlag(argv, "--agent-recognition-key-id");
  const recognitionSeedFlag = consumeFlag(recognitionKeyFlag.rest, "--agent-recognition-signing-seed-hex");
  const idempotencyFlag = consumeFlag(recognitionSeedFlag.rest, "--idempotency-key");
  return {
    recognitionKeyId: recognitionKeyFlag.value,
    recognitionSeedHex: recognitionSeedFlag.value,
    idempotencyKey: idempotencyFlag.value,
    restArgv: idempotencyFlag.rest,
  };
}

/** Resolve agent recognition credentials for Harbor intent mutations from flags and APP_* env fallbacks. */
export async function resolveHarborRecognition(
  ctx: CliContext,
  flags: Pick<HarborMutationFlags, "recognitionKeyId" | "recognitionSeedHex">,
): Promise<AgentRecognitionCredentials> {
  return resolveAgentRecognitionFromCli({
    cwd: ctx.cwd,
    envFile: ctx.globals.envFile,
    agentRecognitionKeyId: flags.recognitionKeyId,
    agentRecognitionSigningSeedHex: flags.recognitionSeedHex,
  });
}

export const DEPRECATED_INTENTS_FUND_BODY_WARNING =
  "deprecated: intents fund --body; use --payment-signature";

/** Whether deprecated ``--body`` / ``--stdin`` shims were passed to ``intents fund``. */
export function fundBodyShimUsed(argv: string[]): boolean {
  return argv.includes("--body") || argv.includes("--stdin");
}

/** Read ``payment_signature`` from deprecated ``intents fund --body`` JSON when present. */
export function resolveFundPaymentSignatureFromBody(
  payload: Record<string, unknown>,
): string | undefined {
  const value = payload.payment_signature;
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
