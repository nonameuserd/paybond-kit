import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  buildMcpServerEntry,
  defaultMcpServerCommand,
  serializeMcpInstallPayload,
} from "../../src/cli/mcp-install.js";
import { parseMcpToolPolicy } from "../../src/cli/mcp-policy.js";
import { validateMcpHostConfig, verifyMcpInstallPlan } from "../../src/cli/mcp-verify-config.js";

describe("mcp verify-config", () => {
  it("accepts generated JSON config when env file exists", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-verify-config-"));
    await writeFile(join(cwd, ".env.local"), "PAYBOND_API_KEY=paybond_sk_sandbox_x\n", "utf8");
    const result = await verifyMcpInstallPlan({
      host: "generic",
      format: "json",
      envFile: ".env.local",
      cwd,
      home: cwd,
    });
    expect(result.ok).toBe(true);
    expect(result.source).toBe("generated");
  });

  it("rejects configs that embed PAYBOND_API_KEY", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-verify-config-"));
    const entry = buildMcpServerEntry(".env.local", defaultMcpServerCommand());
    const payload = serializeMcpInstallPayload("json", {
      ...entry,
      env: { ...entry.env, PAYBOND_API_KEY: "secret" },
    });
    const result = validateMcpHostConfig({
      host: "generic",
      format: "json",
      payload,
      cwd,
      expectedEnvFile: ".env.local",
    });
    expect(result.ok).toBe(false);
    expect(result.issues.some((issue) => issue.field === "env")).toBe(true);
  });

  it("accepts readonly tool policy env vars", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-verify-config-"));
    await writeFile(join(cwd, ".env.local"), "PAYBOND_API_KEY=paybond_sk_sandbox_x\n", "utf8");
    const entry = buildMcpServerEntry(".env.local", defaultMcpServerCommand(), parseMcpToolPolicy("readonly"));
    const payload = serializeMcpInstallPayload("json", entry);
    const result = validateMcpHostConfig({
      host: "generic",
      format: "json",
      payload,
      cwd,
      expectedEnvFile: ".env.local",
    });
    expect(result.ok).toBe(true);
    expect(result.toolPolicy?.policy).toBe("readonly");
  });
});
