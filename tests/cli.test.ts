import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { ROOT_HELP } from "../src/cli/help.js";
import { runCli } from "../src/cli/router.js";
import { createAgentGatewayFetch } from "./cli/agent-gateway-mock.js";

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("paybond cli", () => {
  it("prints the canonical command tree from --help", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["--help"], { stdout });
    const output = stdout.chunks.join("");
    expect(code).toBe(0);
    expect(output).toBe(`${ROOT_HELP}\n`);
    expect(output).toContain("init guardrail");
    expect(output).toContain("mcp serve|install|verify-config|tools");
    expect(output).toContain("tools MCP server");
    expect(output).toContain("never Colorize");
    expect(output).toContain("audit exports list|get|verify|delete");
    expect(output).toContain("keys list|create|rotate|revoke");
  });

  it("rejects unauthenticated tenant override flags", async () => {
    const stderr = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["--tenant_id", "tenant-a", "whoami"], { stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/tenant scope comes from authenticated credentials/);
  });

  it("rejects live device login through the CLI", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-login-"));
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["login", "--env", "live", "--no-open"], { cwd, stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/live device login is not supported/);
  });

  it("returns masked key JSON for login without printing the raw secret", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-login-"));
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
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "login", "--no-open"], {
      cwd,
      fetch: fetchMock,
      stdout,
      stderr: stdout,
      sleep: async () => {},
    });
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(true);
    expect(payload.data.key_masked).toBe("paybond_sk_sandbox_01234567...cdef");
    expect(payload.data.tenant_id).toBe("tenant-sandbox");
    expect(stdout.chunks.join("")).not.toContain(RAW_KEY);
    const envPath = join(cwd, ".env.local");
    expect(await readFile(envPath, "utf8")).toBe(`PAYBOND_API_KEY=${RAW_KEY}\n`);
    expect((await stat(envPath)).mode & 0o777).toBe(0o600);
  });

  it("requires --host for mcp install", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-mcp-"));
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["mcp", "install"], { cwd, stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/missing --host/);
  });

  it("writes project-scoped MCP config with PAYBOND_ENV_FILE reference", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-mcp-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "project", "--env-file", ".env.local"],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(true);
    expect(payload.data.host).toBe("generic");
    const configPath = join(cwd, ".paybond", "mcp.json");
    expect((await stat(configPath)).mode & 0o777).toBe(0o600);
    const body = JSON.parse(await readFile(configPath, "utf8"));
    expect(body.mcpServers.paybond.env.PAYBOND_ENV_FILE).toBe(".env.local");
    expect(body.mcpServers.paybond.env.PAYBOND_API_KEY).toBeUndefined();
  });

  it("includes payload in JSON for local-scope mcp install", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-mcp-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "local", "--env-file", ".env.local"],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.printed).toBe(true);
    expect(payload.data.payload).toContain("PAYBOND_ENV_FILE");
  });

  it("doctor --agent runs MCP validation checks", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-doctor-"));
    await writeFile(join(cwd, ".env.local"), `PAYBOND_API_KEY=${RAW_KEY}\n`, "utf8");
    const fetchMock = createAgentGatewayFetch();
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "doctor", "--agent", "--env-file", ".env.local"], {
      cwd,
      fetch: fetchMock as typeof fetch,
      stdout,
    });
    expect(code === 0 || code === 1).toBe(true);
    const payload = JSON.parse(stdout.chunks.join(""));
    const names = new Set(payload.data.checks.map((check: { name: string }) => check.name));
    expect(names.has("runtime")).toBe(true);
    expect(names.has("package")).toBe(true);
    expect(names.has("env_file")).toBe(true);
    expect(names.has("key_shape")).toBe(true);
    expect(names.has("principal")).toBe(true);
    expect(names.has("mcp_host_config")).toBe(true);
    expect(names.has("mcp_env_resolution")).toBe(true);
    expect(names.has("mcp_launch")).toBe(true);
    expect(names.has("mcp_initialize")).toBe(true);
    expect(names.has("mcp_tools_list")).toBe(true);
    expect(names.has("mcp_tool_schemas")).toBe(true);
    expect(names.has("mcp_stdout_purity")).toBe(true);
    expect(names.has("agent_middleware_smoke")).toBe(true);
    const smoke = payload.data.checks.find((check: { name: string }) => check.name === "agent_middleware_smoke");
    expect(smoke?.ok).toBe(true);
  });

  it("prints package version", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["version"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toMatch(/^\d+\.\d+\.\d+\n$/);
  });

  it("version --verbose includes redacted support fields", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-version-"));
    process.env.PAYBOND_API_KEY = RAW_KEY;
    try {
      const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const code = await runCli(["--format", "json", "version", "--verbose", "--request-id", "01VERSIONVERBOSE01"], {
        cwd,
        stdout,
      });
      expect(code).toBe(0);
      const payload = JSON.parse(stdout.chunks.join(""));
      expect(payload.data.package_name).toBe("@paybond/kit");
      expect(payload.data.request_id).toBe("01VERSIONVERBOSE01");
      expect(payload.data.mcp_tool_count).toBeGreaterThan(0);
      expect(payload.data.credential_source.source).toBe("process_env");
      expect(payload.data.credential_source.key_masked).toContain("...");
      expect(stdout.chunks.join("")).not.toContain(RAW_KEY);
    } finally {
      delete process.env.PAYBOND_API_KEY;
    }
  });

  it("diagnose requires --redacted", async () => {
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["diagnose"], { stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/requires --redacted/);
  });

  it("diagnose --redacted never prints raw API keys", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-diagnose-"));
    await writeFile(join(cwd, ".env.local"), `PAYBOND_API_KEY=${RAW_KEY}\n`, "utf8");
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "diagnose", "--redacted"], { cwd, stdout });
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.redacted).toBe(true);
    expect(payload.data.diagnostics.credential_source.source).toBe("env_file");
    expect(stdout.chunks.join("")).not.toContain(RAW_KEY);
  });
});
