import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { verifyAuditManifest } from "../src/cli/audit-export.js";
import { listConfigEntries } from "../src/cli/config.js";
import { runCli } from "../src/cli/router.js";
import {
  buildShopifyWebhookTriggerCommand,
  resolveShopifyWebhookAddress,
  setShopifyCommandHooks,
} from "../src/cli/commands/shopify.js";
import { createAgentGatewayFetch, SANDBOX_RAW_KEY } from "./cli/agent-gateway-mock.js";

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

  it("spend budget-remaining and explain-policy call preflight", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const fetchMock = vi.fn(async () =>
      jsonResponse({
        classification: "allow",
        outcome: "allow",
        reason_codes: [],
        remaining_cents: 25000,
        spend_scope: { scope_type: "tenant", scope_key: "" },
        policy_version: 3,
        explanation: "Spend is allowed under the current policy.",
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const budgetCode = await runCli(
      [
        "--format",
        "json",
        "spend",
        "budget-remaining",
        "--intent-id",
        intentId,
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
      ],
      { fetch: fetchMock, stdout },
    );
    expect(budgetCode).toBe(0);
    const budgetPayload = JSON.parse(stdout.chunks.join(""));
    expect(budgetPayload.data.remaining_cents).toBe(25000);
    expect(budgetPayload.data.policy_version).toBe(3);

    stdout.chunks = [];
    const explainCode = await runCli(
      [
        "--format",
        "json",
        "spend",
        "explain-policy",
        "--intent-id",
        intentId,
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
      ],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(explainCode).toBe(0);
    const explainPayload = JSON.parse(stdout.chunks.join(""));
    expect(explainPayload.data.outcome).toBe("allow");
    expect(explainPayload.data.explanation).toMatch(/allowed/i);
    const preflightCalls = fetchMock.mock.calls.filter(([input]) =>
      String(input).includes("/v1/spend/preflight"),
    );
    expect(preflightCalls.length).toBeGreaterThanOrEqual(2);
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
    vi.stubEnv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1");
    vi.stubEnv("APP_AGENT_RECOGNITION_SEED_HEX", "02".repeat(32));
    const cwd = await mkdtemp(join(tmpdir(), "paybond-intents-create-"));
    const bodyPath = join(cwd, "intent.json");
    await writeFile(bodyPath, "{}\n", "utf8");
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      if (url.includes("/harbor/intents") && init?.method === "POST") {
        const headers = new Headers(init.headers);
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeTruthy();
        return jsonResponse({ intent_id: "intent-1", capability_token: "cap-secret" });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
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
    vi.stubEnv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1");
    vi.stubEnv("APP_AGENT_RECOGNITION_SEED_HEX", "02".repeat(32));
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      if (url.includes("/harbor/intents/intent-1/fund") && init?.method === "POST") {
        const headers = new Headers(init.headers);
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeTruthy();
        return jsonResponse({
          intent_id: "intent-1",
          tenant: "tenant-sandbox",
          capability_token: "cap-secret",
          state: "funded",
          settlement_rail: "x402_usdc_base",
          currency: "USD",
          amount_cents: 100,
          funded: true,
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "intents", "fund", "intent-1"], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    const payload = JSON.parse(output);
    expect(payload.data.capabilityToken).toBe("[redacted]");
    expect(output).not.toContain("cap-secret");
  });

  it("intents fund --body shim maps payment_signature and warns", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    vi.stubEnv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1");
    vi.stubEnv("APP_AGENT_RECOGNITION_SEED_HEX", "02".repeat(32));
    const cwd = await mkdtemp(join(tmpdir(), "paybond-intents-fund-"));
    const bodyPath = join(cwd, "fund.json");
    await writeFile(bodyPath, JSON.stringify({ payment_signature: "sig-from-body" }), "utf8");
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      if (url.includes("/harbor/intents/intent-1/fund") && init?.method === "POST") {
        const headers = new Headers(init.headers);
        expect(headers.get("payment-signature")).toBe("sig-from-body");
        return jsonResponse({
          intent_id: "intent-1",
          tenant: "tenant-sandbox",
          state: "funded",
          settlement_rail: "x402_usdc_base",
          currency: "USD",
          amount_cents: 100,
          funded: true,
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "intents", "fund", "intent-1", "--body", bodyPath],
      { cwd, fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.warnings).toContain("deprecated: intents fund --body; use --payment-signature");
  });

  it("intents evidence sends recognition proof via SDK", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    vi.stubEnv("APP_AGENT_RECOGNITION_KEY_ID", "kid-1");
    vi.stubEnv("APP_AGENT_RECOGNITION_SEED_HEX", "02".repeat(32));
    const cwd = await mkdtemp(join(tmpdir(), "paybond-intents-evidence-"));
    const bodyPath = join(cwd, "evidence.json");
    await writeFile(bodyPath, JSON.stringify({ status: "ok" }), "utf8");
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      if (url.includes("/harbor/intents/intent-1/evidence") && init?.method === "POST") {
        const headers = new Headers(init.headers);
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeTruthy();
        return jsonResponse({
          intent_id: "intent-1",
          tenant: "tenant-sandbox",
          state: "evidence_submitted",
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "intents", "evidence", "intent-1", "--body", bodyPath],
      { cwd, fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.intentId).toBe("intent-1");
    expect(payload.data.state).toBe("evidence_submitted");
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

  it("shopify doctor reports missing shopify CLI on PATH", async () => {
    setShopifyCommandHooks({
      whichExecutable: async (name) => (name === "shopify" ? null : `/usr/bin/${name}`),
      runCommand: async () => ({ code: 0, stdout: "ucp 1.0.0", stderr: "" }),
    });
    const cwd = await mkdtemp(join(tmpdir(), "paybond-shopify-doctor-"));
    await writeFile(join(cwd, "shopify.app.toml"), 'client_id = "test-client"\n', "utf8");
    vi.stubEnv("SHOPIFY_DEV_STORE", "paybond-agent-commerce-dev.myshopify.com");
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["shopify", "doctor"], { cwd, stdout });
    setShopifyCommandHooks({});
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    expect(output).toContain("shopify_cli");
    expect(output).toContain("not on PATH");
    expect(output).toContain("shopify doctor: fail");
  });

  it("shopify payments doctor reports missing payments app toml by default", async () => {
    setShopifyCommandHooks({
      whichExecutable: async (name) => (name === "shopify" ? "/usr/bin/shopify" : null),
      runCommand: async () => ({ code: 0, stdout: "3.0.0", stderr: "" }),
    });
    const cwd = await mkdtemp(join(tmpdir(), "paybond-shopify-payments-doctor-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "shopify", "payments", "doctor"], { cwd, stdout });
    setShopifyCommandHooks({});
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.summary).toBe("fail");
    expect(payload.data.checks.some((check: { name: string }) => check.name === "payments_app_toml")).toBe(true);
  });

  it("shopify payments smoke includes payment session checklist", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-shopify-payments-smoke-"));
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const fetch = createAgentGatewayFetch();
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "shopify", "payments", "smoke", "--shop", "dev.myshopify.com"],
      { cwd, stdout, fetch: fetch as typeof fetch },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.payment_session_id).toBe("paybond-smoke-payment-session");
    expect(payload.data.shop).toBe("dev.myshopify.com");
    expect(payload.data.checklist_lines.join(" ")).toContain("shopify payments smoke");
  });

  it("shopify webhook trigger --dry-run resolves sandbox webhook address", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-shopify-webhook-"));
    await writeFile(join(cwd, "shopify.app.toml"), 'client_id = "cli-test-123"\n', "utf8");
    setShopifyCommandHooks({
      whichExecutable: async () => "/usr/bin/shopify",
    });
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "shopify",
        "webhook",
        "trigger",
        "--topic",
        "orders/paid",
        "--gateway",
        "https://api.paybond.ai",
        "--dry-run",
      ],
      { cwd, stdout },
    );
    setShopifyCommandHooks({});
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.address).toBe("https://api.paybond.ai/webhooks/sandbox/shopify");
    expect(payload.data.command).toContain("shopify app webhook trigger");
    expect(payload.data.command).toContain("--client-id=cli-test-123");
    expect(resolveShopifyWebhookAddress("https://api.paybond.ai")).toBe(
      "https://api.paybond.ai/webhooks/sandbox/shopify",
    );
    expect(buildShopifyWebhookTriggerCommand({
      topic: "orders/paid",
      address: "https://api.paybond.ai/webhooks/sandbox/shopify",
      clientId: "abc",
    })).toEqual([
      "app",
      "webhook",
      "trigger",
      "--topic=orders/paid",
      "--address=https://api.paybond.ai/webhooks/sandbox/shopify",
      "--client-id=abc",
    ]);
  });
});
