import { resolveAgentRecognitionFromCli, type AgentRecognitionCredentials } from "./agent/production-evidence.js";
import type { CliContext } from "./context.js";
import { consumeFlag } from "./globals.js";
import { resolveSecretFromFileOrEnv } from "./secret-argv.js";

/** Parsed recognition and idempotency flags for Harbor intent mutation CLI commands. */
export type HarborMutationFlags = {
  recognitionKeyId?: string;
  recognitionSeedHex?: string;
  idempotencyKey?: string;
  restArgv: string[];
};

/** Extract shared Harbor mutation flags from argv, leaving body and positional args in restArgv. */
export async function parseHarborMutationFlags(
  argv: string[],
  cwd: string,
): Promise<HarborMutationFlags> {
  const recognitionKeyFlag = consumeFlag(argv, "--agent-recognition-key-id");
  const recognitionSeed = await resolveSecretFromFileOrEnv({
    argv: recognitionKeyFlag.rest,
    cwd,
    rejectedFlag: "--agent-recognition-signing-seed-hex",
    fileFlag: "--agent-recognition-signing-seed-file",
    envName: "APP_AGENT_RECOGNITION_SEED_HEX",
    alternatives: "--agent-recognition-signing-seed-file or APP_AGENT_RECOGNITION_SEED_HEX",
  });
  const idempotencyFlag = consumeFlag(recognitionSeed.rest, "--idempotency-key");
  return {
    recognitionKeyId: recognitionKeyFlag.value,
    recognitionSeedHex: recognitionSeed.value,
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
