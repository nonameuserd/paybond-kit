import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { parseHarborMutationFlags, resolveHarborRecognition, fundBodyShimUsed, resolveFundPaymentSignatureFromBody } from "../src/cli/intents-harbor-mutation.js";
import { type CliContext } from "../src/cli/context.js";
import { defaultGlobalOptions } from "../src/cli/globals.js";
import { CliError } from "../src/cli/types.js";

const AGENT_SEED_HEX = "02".repeat(32);

function makeCtx(cwd: string): CliContext {
  return {
    globals: defaultGlobalOptions(),
    cwd,
    stdout: { write: () => true },
    stderr: { write: () => true },
    fetch: globalThis.fetch,
    deps: {},
  };
}

describe("intents harbor mutation helpers", () => {
  it("parseHarborMutationFlags extracts recognition and idempotency flags", () => {
    const flags = parseHarborMutationFlags([
      "--agent-recognition-key-id",
      "kid-1",
      "--agent-recognition-signing-seed-hex",
      AGENT_SEED_HEX,
      "--idempotency-key",
      "idem-1",
      "--body",
      "payload.json",
    ]);

    expect(flags.recognitionKeyId).toBe("kid-1");
    expect(flags.recognitionSeedHex).toBe(AGENT_SEED_HEX);
    expect(flags.idempotencyKey).toBe("idem-1");
    expect(flags.restArgv).toEqual(["--body", "payload.json"]);
  });

  it("parseHarborMutationFlags leaves unrecognized args in restArgv", () => {
    const flags = parseHarborMutationFlags(["intent-123", "--body", "payload.json"]);
    expect(flags.recognitionKeyId).toBeUndefined();
    expect(flags.recognitionSeedHex).toBeUndefined();
    expect(flags.idempotencyKey).toBeUndefined();
    expect(flags.restArgv).toEqual(["intent-123", "--body", "payload.json"]);
  });

  it("resolveHarborRecognition resolves credentials from flags", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paybond-harbor-mutation-"));
    try {
      const ctx = makeCtx(dir);
      const recognition = await resolveHarborRecognition(ctx, {
        recognitionKeyId: "kid-1",
        recognitionSeedHex: AGENT_SEED_HEX,
      });
      expect(recognition.agentRecognitionKeyId).toBe("kid-1");
      expect(recognition.agentRecognitionSigningSeed).toHaveLength(32);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolveHarborRecognition falls back to APP_* env file values", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paybond-harbor-mutation-"));
    try {
      writeFileSync(
        join(dir, ".env.local"),
        ["APP_AGENT_RECOGNITION_KEY_ID=kid-env", `APP_AGENT_RECOGNITION_SEED_HEX=${AGENT_SEED_HEX}`].join("\n"),
        "utf8",
      );
      const ctx = makeCtx(dir);
      const recognition = await resolveHarborRecognition(ctx, {});
      expect(recognition.agentRecognitionKeyId).toBe("kid-env");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolveHarborRecognition rejects incomplete credentials", async () => {
    const dir = mkdtempSync(join(tmpdir(), "paybond-harbor-mutation-"));
    try {
      const ctx = makeCtx(dir);
      await expect(resolveHarborRecognition(ctx, {})).rejects.toMatchObject({
        code: "cli.agent.recognition_incomplete",
        message: expect.stringContaining("Harbor intent mutation requires"),
      } satisfies Partial<CliError>);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("resolveFundPaymentSignatureFromBody reads payment_signature", () => {
    expect(resolveFundPaymentSignatureFromBody({ payment_signature: " sig-1 " })).toBe("sig-1");
    expect(resolveFundPaymentSignatureFromBody({})).toBeUndefined();
  });

  it("fundBodyShimUsed detects deprecated body flags", () => {
    expect(fundBodyShimUsed(["--body", "fund.json"])).toBe(true);
    expect(fundBodyShimUsed(["--stdin"])).toBe(true);
    expect(fundBodyShimUsed(["--payment-signature", "sig"])).toBe(false);
  });
});
