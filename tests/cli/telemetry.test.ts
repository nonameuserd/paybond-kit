import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  cliTelemetryEnabled,
  hashCliInstallId,
  reportCliCommandSuccess,
  resolveCliInstallId,
} from "../../src/cli/telemetry.js";
import type { CliContext } from "../../src/cli/context.js";

const originalConfigHome = process.env.XDG_CONFIG_HOME;

afterEach(async () => {
  if (originalConfigHome === undefined) {
    delete process.env.XDG_CONFIG_HOME;
  } else {
    process.env.XDG_CONFIG_HOME = originalConfigHome;
  }
  vi.unstubAllEnvs();
});

describe("cli telemetry", () => {
  it("hashes install ids with a stable prefix", () => {
    expect(hashCliInstallId("test-install")).toHaveLength(64);
    expect(hashCliInstallId("test-install")).toBe(hashCliInstallId("test-install"));
  });

  it("persists install_id in the CLI config file", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "paybond-cli-config-"));
    process.env.XDG_CONFIG_HOME = configDir;
    const first = await resolveCliInstallId();
    const second = await resolveCliInstallId();
    expect(second).toBe(first);
    const raw = await readFile(join(configDir, "paybond", "config.json"), "utf8");
    expect(raw).toContain(first);
    await rm(configDir, { recursive: true, force: true });
  });

  it("disables telemetry for local gateways unless forced", async () => {
    vi.stubEnv("PAYBOND_TELEMETRY", "");
    await expect(cliTelemetryEnabled("http://127.0.0.1:18089")).resolves.toBe(false);
    await expect(cliTelemetryEnabled("http://192.168.1.5:18089")).resolves.toBe(false);
    vi.stubEnv("PAYBOND_TELEMETRY", "1");
    await expect(cliTelemetryEnabled("http://127.0.0.1:18089")).resolves.toBe(true);
  });

  it("posts successful dev loop telemetry to the gateway", async () => {
    const configDir = await mkdtemp(join(tmpdir(), "paybond-cli-config-"));
    process.env.XDG_CONFIG_HOME = configDir;
    vi.stubEnv("PAYBOND_TELEMETRY", "1");

    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetch = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init });
      return new Response(JSON.stringify({ status: "stored" }), { status: 201 });
    }) as typeof fetch;

    const ctx = {
      cwd: configDir,
      globals: {
        gateway: "https://api.paybond.ai",
        format: "json",
      },
      fetch,
      stderr: { write: () => true },
      stdout: { write: () => true },
    } as unknown as CliContext;

    await reportCliCommandSuccess(ctx, { commandPath: "dev loop", offline: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("https://api.paybond.ai/v1/public/analytics/kit-cli");
    const body = JSON.parse(String(calls[0]?.init?.body));
    expect(body.command_path).toBe("dev loop");
    expect(body.offline).toBe(true);
    expect(body.install_id_sha256).toHaveLength(64);

    await rm(configDir, { recursive: true, force: true });
  });
});
