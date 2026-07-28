import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it, vi } from "vitest";

import { HarborClient } from "../src/index.js";
import { assertValidAgentRunId } from "../src/cli/agent/run-id.js";
import { agentRunFilePath, persistAgentRunContext } from "../src/cli/agent/run-store.js";
import { CliError } from "../src/cli/types.js";

describe("kit security regressions", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("rejects non-boolean allow from verifyCapability", async () => {
    const intent = "550e8400-e29b-41d4-a716-446655440000";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              allow: "false",
              audit_id: "550e8400-e29b-41d4-a716-446655440001",
              tenant: "tenant-a",
              intent_id: intent,
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          ),
      ),
    );
    const c = new HarborClient("https://harbor.test", "tenant-a", {
      staticHarborBearerToken: "test-bearer",
    });
    await expect(
      c.verifyCapability({ intentId: intent, token: "Cg==", operation: "demo.tool" }),
    ).rejects.toThrow(/allow must be a JSON boolean/);
  });

  it("rejects run-id path traversal outside .paybond/runs", async () => {
    expect(() => assertValidAgentRunId("../../package")).toThrow(CliError);
    const cwd = await mkdtemp(join(tmpdir(), "paybond-run-id-"));
    await expect(
      persistAgentRunContext(cwd, {
        run_id: "../../package",
        tenant_id: "tenant-a",
        intent_id: "intent-1",
        capability_token: "cap-1",
        operation: "paid-tool",
        allowed_tools: ["paid-tool"],
        sandbox: true,
        created_at: new Date().toISOString(),
      }),
    ).rejects.toMatchObject({ code: "cli.agent.invalid_run_id" });
    expect(() => agentRunFilePath(cwd, "../escape")).toThrow(/invalid run_id/);
  });

  it("requires Harbor bearer for non-local bases", () => {
    expect(() => new HarborClient("https://harbor.test", "tenant-a")).toThrow(
      /requires harborBearerSupplier or staticHarborBearerToken/,
    );
    expect(
      () =>
        new HarborClient("http://127.0.0.1:18089", "tenant-a", {
          allowUnauthenticatedLocal: true,
        }),
    ).not.toThrow();
  });

  it("rejects secret capability token argv via file-or-env helper", async () => {
    const { resolveSecretFromFileOrEnv } = await import("../src/cli/secret-argv.js");
    const cwd = await mkdtemp(join(tmpdir(), "paybond-secret-"));
    await writeFile(join(cwd, "cap.token"), "cap-from-file\n", "utf8");
    await expect(
      resolveSecretFromFileOrEnv({
        argv: ["--capability-token", "leaked"],
        cwd,
        rejectedFlag: "--capability-token",
        fileFlag: "--capability-token-file",
        envName: "PAYBOND_CAPABILITY_TOKEN",
        alternatives: "--capability-token-file or PAYBOND_CAPABILITY_TOKEN",
      }),
    ).rejects.toMatchObject({ code: "cli.secret.argv_rejected" });

    const resolved = await resolveSecretFromFileOrEnv({
      argv: ["--capability-token-file", "cap.token"],
      cwd,
      rejectedFlag: "--capability-token",
      fileFlag: "--capability-token-file",
      envName: "PAYBOND_CAPABILITY_TOKEN",
      alternatives: "--capability-token-file or PAYBOND_CAPABILITY_TOKEN",
    });
    expect(resolved.value).toBe("cap-from-file");
  });
});
