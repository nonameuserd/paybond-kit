import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";

import { assertGitIgnored, parseArgs, runLogin, writeEnvFile } from "../src/login.js";

const TEST_TMP_ROOT = join(dirname(fileURLToPath(import.meta.url)), ".test-tmp");

function gitIntegrationAvailable(): boolean {
  try {
    mkdirSync(TEST_TMP_ROOT, { recursive: true });
    const cwd = mkdtempSync(join(TEST_TMP_ROOT, "git-probe-"));
    execFileSync("git", ["init"], { cwd, stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const gitIt = gitIntegrationAvailable() ? it : it.skip;

async function loginTestCwd(prefix: string): Promise<string> {
  await mkdir(TEST_TMP_ROOT, { recursive: true });
  return mkdtemp(join(TEST_TMP_ROOT, prefix));
}

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function outputCollector(): { writer: { write(chunk: string): boolean }; text: () => string } {
  let output = "";
  return {
    writer: {
      write(chunk: string): boolean {
        output += chunk;
        return true;
      },
    },
    text: () => output,
  };
}

describe("paybond login", () => {
  it("runs the device flow, writes a 0600 env file, and masks the key in output", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    const envPath = join(cwd, ".env.local");
    const stdout = outputCollector();
    const sleeps: number[] = [];
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          device_code: "device-code",
          user_code: "ABCD-EFGH",
          verification_uri: "https://paybond.ai/device",
          verification_uri_complete: "https://paybond.ai/device?code=ABCD-EFGH",
          expires_in: 600,
          interval: 5,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: "authorization_pending",
            error_description: "pending",
            interval: 5,
          },
          400,
        ),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: RAW_KEY,
          token_type: "bearer",
          tenant_id: "tenant-sandbox",
          tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
          environment: "sandbox",
          service_account_role: "operator",
        }),
      );

    const result = await runLogin(
      { envFile: ".env.local", gateway: "https://gateway.test", environment: "sandbox", noOpen: true, force: false },
      {
        cwd,
        fetch: fetchMock,
        sleep: async (ms) => {
          sleeps.push(ms);
        },
        stdout: stdout.writer,
        now: () => 0,
      },
    );

    expect(result.keyWritten).toBe(true);
    expect(result.keyMasked).toBe("paybond_sk_sandbox_01234567...cdef");
    expect(result.tenantId).toBe("tenant-sandbox");

    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(sleeps).toEqual([5000, 5000]);
    expect(await readFile(envPath, "utf8")).toBe(`PAYBOND_API_KEY=${RAW_KEY}\n`);
    expect((await stat(envPath)).mode & 0o777).toBe(0o600);
    expect(stdout.text()).toContain("Target sandbox tenant: tenant-sandbox");
    expect(stdout.text()).toContain("Key: paybond_sk_sandbox_01234567...cdef");
    expect(stdout.text()).not.toContain(RAW_KEY);
    expect(stdout.text()).not.toContain("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  });

  it("rejects live device login flags before network access", () => {
    expect(() => parseArgs(["login", "--env", "live"])).toThrow(/live device login is not supported/);
    expect(() => parseArgs(["login", "--live"])).toThrow(/live device login is not supported/);
  });

  it("rejects a live key when sandbox was requested", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    const liveKey = "paybond_sk_live_fixture_not_a_real_secret";
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          device_code: "device-code",
          user_code: "ABCD-EFGH",
          verification_uri: "https://paybond.ai/device",
          expires_in: 600,
          interval: 5,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: liveKey,
          token_type: "bearer",
          tenant_id: "tenant-live",
          tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
          environment: "live",
          service_account_role: "operator",
        }),
      );

    await expect(
      runLogin(
        { envFile: ".env.local", gateway: "https://gateway.test", environment: "sandbox", noOpen: true, force: false },
        { cwd, fetch: fetchMock, sleep: async () => {}, now: () => 0 },
      ),
    ).rejects.toThrow(/live key but sandbox was requested/);
  });

  it("refuses to overwrite PAYBOND_API_KEY without force", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    const envPath = join(cwd, ".env.local");
    await writeFile(envPath, "PAYBOND_API_KEY=existing\nOTHER=value\n", "utf8");
    const fetchMock = vi.fn();

    await expect(
      runLogin(
        { envFile: ".env.local", gateway: "https://gateway.test", environment: "sandbox", noOpen: true, force: false },
        { cwd, fetch: fetchMock },
      ),
    ).rejects.toThrow(/PAYBOND_API_KEY already exists/);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await readFile(envPath, "utf8")).toBe("PAYBOND_API_KEY=existing\nOTHER=value\n");
  });

  it("replaces PAYBOND_API_KEY when force is set", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    const envPath = join(cwd, ".env.local");
    await writeFile(envPath, "OTHER=value\nexport PAYBOND_API_KEY=existing\n", "utf8");

    await writeEnvFile(envPath, RAW_KEY, true);

    expect(await readFile(envPath, "utf8")).toBe(`OTHER=value\nPAYBOND_API_KEY=${RAW_KEY}\n`);
    expect((await stat(envPath)).mode & 0o777).toBe(0o600);
  });

  gitIt("refuses env files inside a git repo when they are not ignored", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    execFileSync("git", ["init"], { cwd, stdio: "ignore" });

    await expect(assertGitIgnored(join(cwd, "paybond-login-secrets"), cwd)).rejects.toThrow(/not ignored by git/);
  });

  gitIt("allows env files inside a git repo when they are ignored", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    execFileSync("git", ["init"], { cwd, stdio: "ignore" });
    await writeFile(join(cwd, ".gitignore"), "paybond-login-secrets\n", "utf8");

    await expect(assertGitIgnored(join(cwd, "paybond-login-secrets"), cwd)).resolves.toBeUndefined();
  });

  gitIt("adds the default env file to .gitignore during login", async () => {
    const cwd = await loginTestCwd("paybond-login-");
    execFileSync("git", ["init"], { cwd, stdio: "ignore" });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          device_code: "device-code",
          user_code: "ABCD-EFGH",
          verification_uri: "https://paybond.ai/device",
          expires_in: 600,
          interval: 5,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: RAW_KEY,
          token_type: "bearer",
          tenant_id: "tenant-sandbox",
          tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
          environment: "sandbox",
          service_account_role: "operator",
        }),
      );

    const result = await runLogin(
      { envFile: ".env.local", gateway: "https://gateway.test", environment: "sandbox", noOpen: true, force: false },
      { cwd, fetch: fetchMock, sleep: async () => {}, now: () => 0 },
    );

    expect(result.keyWritten).toBe(true);

    expect(await readFile(join(cwd, ".gitignore"), "utf8")).toContain(".env.local");
    await expect(assertGitIgnored(join(cwd, ".env.local"), cwd)).resolves.toBeUndefined();
  });
});
