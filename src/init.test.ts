import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { main } from "./init.js";

describe("paybond-init", () => {
  const originalExitCode = process.exitCode;

  afterEach(() => {
    process.exitCode = originalExitCode;
  });

  it("scaffolds a provider-agnostic guardrail integration", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-guardrail-demo.ts");

    await expect(
      main(["--preset", "paid-tool-guard", "--framework", "provider-agnostic", "--out", out]),
    ).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    for (const fragment of [
      "openPaybondFromEnv",
      "bootstrapSandboxGuardrailIntent",
      "wrapPaidTool",
      "submitSandboxEvidence",
      "replaceableSmokeTestPaidTool",
      "runSandboxSmokePath",
      "paybond.guardrails.bootstrapSandbox",
      "paybond.spendGuard(guardrail.intent_id, guardrail.capability_token)",
      "paybond.guardrails.submitSandboxEvidence",
      "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
      "Replace this sandbox smoke-test function with the real paid side-effecting tool.",
    ]) {
      expect(body).toContain(fragment);
    }
  });

  it("refuses to overwrite without --force", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-guardrail-demo.ts");
    await writeFile(out, "existing", "utf8");

    await expect(main(["--out", out])).resolves.toBe(1);
    expect(await readFile(out, "utf8")).toBe("existing");
  });

  it("overwrites with --force and applies framework notes", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-guardrail-demo.ts");
    await writeFile(out, "existing", "utf8");

    await expect(main(["--framework", "mcp", "--out", out, "--force"])).resolves.toBe(0);
    expect(await readFile(out, "utf8")).toContain(
      "Call the guarded handler inside the MCP tool implementation before paid or external work runs.",
    );
  });
});
