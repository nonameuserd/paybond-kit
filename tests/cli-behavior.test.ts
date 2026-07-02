import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { verifyAuditManifest } from "../src/cli/audit-export.js";
import { listConfigEntries } from "../src/cli/config.js";
import { runCli } from "../src/cli/router.js";

const CONTRACT_PATH = join(process.cwd(), "..", "cli-parity", "contract.json");
const FIXTURE_PATH = join(process.cwd(), "..", "cli-parity", "fixtures", "signed_audit_manifest.json");

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function loadSignedAuditManifest(): Record<string, unknown> {
  return JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Record<string, unknown>;
}

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("cli behavior parity", () => {
  it("verifies the shared signed audit manifest fixture", () => {
    const manifest = loadSignedAuditManifest();
    expect(verifyAuditManifest(manifest)).toBe(true);
  });

  it("audit exports verify CLI accepts the shared fixture directory", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-audit-verify-"));
    const bundleDir = join(cwd, "bundle");
    await mkdir(bundleDir, { recursive: true });
    await writeFile(join(bundleDir, "manifest.json"), `${JSON.stringify(loadSignedAuditManifest(), null, 2)}\n`, "utf8");
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "audit", "exports", "verify", bundleDir], { cwd, stdout });
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(true);
    expect(payload.data.verified).toBe(true);
    expect(payload.data.job_id).toBe("job-parity-1");
    expect(payload.data.tenant_realm_id).toBe("realm_demo");
  });

  it("config list JSON redacts sensitive values", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-config-list-"));
    const configDir = join(cwd, ".config", "paybond");
    await mkdir(configDir, { recursive: true });
    await writeFile(
      join(configDir, "config.json"),
      JSON.stringify({ values: { gateway: "https://api.paybond.ai", api_key: RAW_KEY } }),
      "utf8",
    );
    vi.stubEnv("XDG_CONFIG_HOME", join(cwd, ".config"));
    const entries = await listConfigEntries();
    expect(entries.gateway).toBe("https://api.paybond.ai");
    expect(entries.api_key).not.toBe(RAW_KEY);
    expect(entries.api_key).toContain("paybond_sk_");

    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "config", "list"], { cwd, stdout });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.entries.gateway).toBe("https://api.paybond.ai");
    expect(payload.data.entries.api_key).not.toBe(RAW_KEY);
    expect(stdout.chunks.join("")).not.toContain(RAW_KEY);
  });

  it("rejects invalid --requested-spend-cents for guardrails bootstrap", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["guardrails", "bootstrap", "--operation", "paid-tool", "--requested-spend-cents", "abc"],
      { stderr },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/invalid --requested-spend-cents/);
  });

  it("guardrails bootstrap JSON redacts capability_token", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        tenant_id: "tenant-a",
        intent_id: "intent-1",
        capability_token: "cap-secret",
        operation: "paid-tool",
        requested_spend_cents: 100,
        sandbox_lifecycle_status: "funded",
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "guardrails", "bootstrap", "--operation", "paid-tool", "--requested-spend-cents", "100"],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    const payload = JSON.parse(output);
    expect(payload.data.capability_token).toBe("[redacted]");
    expect(output).not.toContain("cap-secret");
  });

  it("intents create JSON redacts capability_token", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const cwd = await mkdtemp(join(tmpdir(), "paybond-intents-create-"));
    const bodyPath = join(cwd, "intent.json");
    await writeFile(bodyPath, "{}\n", "utf8");
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ intent_id: "intent-1", capability_token: "cap-secret" }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "intents", "create", "--body", bodyPath], {
      cwd,
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    const payload = JSON.parse(output);
    expect(payload.data.capability_token).toBe("[redacted]");
    expect(output).not.toContain("cap-secret");
  });

  it("intents fund JSON redacts capability_token", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({ intent_id: "intent-1", capability_token: "cap-secret", state: "funded" }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "intents", "fund", "intent-1"], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    const payload = JSON.parse(output);
    expect(payload.data.capability_token).toBe("[redacted]");
    expect(output).not.toContain("cap-secret");
  });

  it("mcp install writes project config with mode 0o600", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-mcp-install-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "mcp", "install", "--host", "generic", "--scope", "project", "--env-file", ".env.local"],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    const configPath = join(cwd, ".paybond", "mcp.json");
    expect(payload.data.config_path).toBe(configPath);
    expect((await stat(configPath)).mode & 0o777).toBe(0o600);
    const body = JSON.parse(await readFile(configPath, "utf8")) as {
      mcpServers: { paybond: { env: Record<string, string | undefined> } };
    };
    expect(body.mcpServers.paybond.env.PAYBOND_ENV_FILE).toBe(".env.local");
    expect(body.mcpServers.paybond.env.PAYBOND_API_KEY).toBeUndefined();
  });

  it("contract declares the shared audit manifest fixture", () => {
    const contract = JSON.parse(readFileSync(CONTRACT_PATH, "utf8")) as {
      shared_fixtures: { signed_audit_manifest: string };
    };
    const fixturePath = join(process.cwd(), "..", "cli-parity", contract.shared_fixtures.signed_audit_manifest);
    const manifest = JSON.parse(readFileSync(fixturePath, "utf8")) as Record<string, unknown>;
    expect(manifest.kind).toBe("paybond.audit_export_manifest_v1");
    expect(verifyAuditManifest(manifest)).toBe(true);
  });
});
