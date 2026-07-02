import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { getCompletionPreset } from "../../src/completion-catalog.js";
import { runCli } from "../../src/cli/router.js";

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("paybond policy commands", () => {
  it("policy templates lists catalog presets", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "policy", "templates"], { stdout });
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(true);
    expect(payload.data.catalog_version).toBe(1);
    expect(payload.data.presets.some((row: { preset_id: string }) => row.preset_id === "api_response_ok")).toBe(true);
  });

  it("policy preview returns pass/fail against gateway", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-preview-"));
    const preset = getCompletionPreset("api_response_ok");
    const evidencePath = join(cwd, "evidence.json");
    await writeFile(evidencePath, `${JSON.stringify(preset.sample_evidence, null, 2)}\n`, "utf8");

    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      const body = init?.body ? JSON.parse(String(init.body)) : {};
      if (url.endsWith("/harbor/policy/v1/preview")) {
        expect(body.template_id).toBe("api_response_v1");
        return jsonResponse({
          template_id: "api_response_v1",
          materialized_dsl: { version: 1, root: { op: "true" } },
          human_summary: "preview ok",
        });
      }
      if (url.endsWith("/harbor/policy/v1/test")) {
        expect(body.evidence.http_status).toBe(200);
        return jsonResponse({
          template_id: "api_response_v1",
          predicate_evaluation: { passed: true, trace: [] },
        });
      }
      if (url.endsWith("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      return jsonResponse({}, 404);
    });

    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "preview", "--preset", "api_response_ok", "--evidence-file", evidencePath],
      { cwd, fetch: fetch as typeof fetch, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.pass).toBe(true);
    expect(payload.data.template_id).toBe("api_response_v1");
    expect(payload.data.materialized_dsl).toBeTruthy();
    expect(fetch).toHaveBeenCalled();
  });

  it("policy validate-evidence reports drift for missing quality fields", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-validate-"));
    const preset = getCompletionPreset("ach_travel_booking");
    const vendorPath = join(cwd, "vendor.json");
    await writeFile(
      vendorPath,
      `${JSON.stringify(
        {
          confirmation_number: "AA-123",
          http_status: 200,
          response_digest: "blake3:abc",
          status: "confirmed",
          total_cents: 12000,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );

    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "validate-evidence", "--preset", "ach_travel_booking", "--vendor-file", vendorPath],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.ok).toBe(false);
    expect(payload.data.quality_fields_missing).toContain("fare_class");
    expect(payload.data.drift_kinds).toContain("quality_field_missing");
    expect(preset.vendor_contract?.quality_fields).toContain("fare_class");
  });

  it("policy init scaffolds a valid starter policy file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-cli-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "policy",
        "init",
        "--out",
        join(cwd, "paybond.policy.yaml"),
        "--operation",
        "travel.book_hotel",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.name).toBe("travel-book-hotel-v1");
    expect(payload.data.bytes_written).toBeGreaterThan(0);
  });

  it("policy validate-tools rejects misaligned allowed_tools", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-validate-tools-"));
    const policyPath = join(cwd, "paybond.policy.yaml");
    await writeFile(
      policyPath,
      `version: 1
name: bad-allowed-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
intent:
  allowed_tools:
    - payments.charge
`,
      "utf8",
    );

    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "validate-tools", "--file", policyPath],
      { cwd, stdout, stderr },
    );
    expect(code).toBe(3);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.policy.validation_failed");
  });

  it("policy validate-tools accepts a valid policy file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-validate-tools-ok-"));
    const policyPath = join(cwd, "paybond.policy.yaml");
    await writeFile(
      policyPath,
      `version: 1
name: travel-agent-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
intent:
  allowed_tools:
    - travel.book_hotel
`,
      "utf8",
    );

    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "validate-tools", "--file", policyPath, "--local-only"],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.valid).toBe(true);
    expect(payload.data.policy_name).toBe("travel-agent-v1");
  });

  it("policy validate-tools --remote calls Gateway /v1/policy/validate", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-validate-remote-"));
    const policyPath = join(cwd, "paybond.policy.yaml");
    await writeFile(
      policyPath,
      `version: 1
name: travel-agent-v1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
intent:
  allowed_tools:
    - travel.book_hotel
`,
      "utf8",
    );

    const fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.includes("/v1/auth/principal")) {
        return jsonResponse({ tenant_id: "tenant-sandbox", environment: "sandbox" });
      }
      if (url.includes("/v1/policy/validate")) {
        expect(init?.method).toBe("POST");
        const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        expect(body.name).toBe("travel-agent-v1");
        return jsonResponse({
          valid: true,
          local_valid: true,
          remote_valid: true,
          policy_name: "travel-agent-v1",
          tenant_id: "tenant-sandbox",
          errors: [],
          warnings: [],
          checks: [{ name: "template_exists", passed: true }],
        });
      }
      return jsonResponse({}, 404);
    });

    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "validate-tools", "--file", policyPath, "--remote"],
      { cwd, fetch: fetch as typeof fetch, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.remote_valid).toBe(true);
    expect(fetch).toHaveBeenCalled();
  });

  it("policy init-org scaffolds a v2 org base policy", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-org-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "policy",
        "init-org",
        "--policy-id",
        "acme-agent-spend-v1",
        "--out",
        join(cwd, "org-base.yaml"),
      ],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.policy_id).toBe("acme-agent-spend-v1");
    expect(payload.data.bytes_written).toBeGreaterThan(0);
  });

  it("policy extend scaffolds a tenant overlay", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-extend-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "policy",
        "extend",
        "--extends",
        "org_acme_corp/acme-agent-spend-v1",
        "--out",
        join(cwd, "paybond.policy.yaml"),
      ],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.org_id).toBe("org_acme_corp");
    expect(payload.data.org_policy_id).toBe("acme-agent-spend-v1");
  });
});
