import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { runCli } from "../src/cli/router.js";
import { COMMAND_HELP, ROOT_HELP } from "../src/cli/help.js";
import { maskApiKey } from "../src/cli/redact.js";

const CONTRACT_PATH = join(process.cwd(), "..", "cli-parity", "contract.json");
const COMMANDS_PATH = join(process.cwd(), "..", "cli-parity", "commands.json");

type CliParityContract = {
  root_help: string;
  command_help: Record<string, string>;
  envelope: {
    success_keys: string[];
    error_object_keys: string[];
  };
  command_data_keys: Record<string, string[]>;
  nested_data_keys: Record<string, string[]>;
  key_masking: Array<{ input: string; expected: string }>;
  error_cases: Array<{
    argv: string[];
    format: "table" | "json";
    with_api_key?: boolean;
    exit_code: number;
    error?: { category: string; code: string };
    message_contains: string;
  }>;
  parse_error_cases?: Array<{
    argv: string[];
    format: "table" | "json";
    exit_code: number;
    error?: { category: string; code: string };
    message_contains: string;
  }>;
  help_paths?: Array<{ argv: string[]; contains: string }>;
  global_flag_placement?: Array<{
    argv: string[];
    with_api_key?: boolean;
    exit_code: number;
    envelope_ok?: boolean;
  }>;
};

function loadContract(): CliParityContract {
  return JSON.parse(readFileSync(CONTRACT_PATH, "utf8")) as CliParityContract;
}

function buildArgv(caseItem: { argv: string[]; format: "table" | "json" }): string[] {
  if (caseItem.format === "json" && !caseItem.argv.some((arg) => arg === "--format" || arg.startsWith("--format="))) {
    return ["--format", "json", ...caseItem.argv];
  }
  return caseItem.argv;
}

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("cli parity contract", () => {
  const contract = loadContract();

  it("matches canonical root help", () => {
    expect(ROOT_HELP).toBe(contract.root_help);
  });

  it("matches canonical subcommand help", () => {
    for (const [path, text] of Object.entries(contract.command_help)) {
      expect(COMMAND_HELP[path], `help for ${path}`).toBe(text);
    }
    expect(Object.keys(COMMAND_HELP).sort()).toEqual(Object.keys(contract.command_help).sort());
  });

  it("applies identical key masking cases", () => {
    for (const sample of contract.key_masking) {
      expect(maskApiKey(sample.input)).toBe(sample.expected);
    }
  });

  it.each(contract.error_cases.map((item, index) => [index, item] as const))(
    "error case %# matches exit code and envelope",
    async (_index, item) => {
      if (item.with_api_key) {
        vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
      }
      const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const argv = buildArgv(item);
      const code = await runCli(argv, { stdout, stderr });
      if (item.with_api_key) {
        vi.unstubAllEnvs();
      }
      expect(code).toBe(item.exit_code);
      if (item.format === "json") {
        const payload = JSON.parse(stdout.chunks.join(""));
        expect(payload.ok).toBe(false);
        expect(payload.error).toBeTruthy();
        for (const key of contract.envelope.success_keys) {
          expect(payload).toHaveProperty(key);
        }
        for (const key of contract.envelope.error_object_keys) {
          expect(payload.error).toHaveProperty(key);
        }
        if (item.error) {
          expect(payload.error.category).toBe(item.error.category);
          expect(payload.error.code).toBe(item.error.code);
        }
        expect(payload.error.message).toContain(item.message_contains);
      } else {
        expect(stderr.chunks.join("")).toContain(item.message_contains);
      }
    },
  );

  it("whoami JSON output keys match contract", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        tenant_id: "tenant-sandbox",
        tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
        environment: "sandbox",
        service_account_role: "operator",
        access_token: "secret",
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "--request-id", "01PARITYWHOAMI", "whoami", "--env-file", ".env.local"],
      {
        cwd: process.cwd(),
        fetch: fetchMock,
        stdout,
      },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    for (const key of contract.command_data_keys.whoami) {
      expect(payload.data).toHaveProperty(key);
    }
    expect(payload.data.principal.access_token).toBeUndefined();
  });

  it("doctor JSON output keys match contract", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        tenant_id: "tenant-sandbox",
        tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
        environment: "sandbox",
        service_account_role: "operator",
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "--request-id", "01PARITYDOCTOR", "doctor", "--env-file", ".env.local"],
      {
        cwd: process.cwd(),
        fetch: fetchMock,
        stdout,
      },
    );
    vi.unstubAllEnvs();
    expect(code === 0 || code === 1).toBe(true);
    const payload = JSON.parse(stdout.chunks.join(""));
    for (const key of contract.command_data_keys.doctor) {
      expect(payload.data).toHaveProperty(key);
    }
    for (const check of payload.data.checks) {
      for (const key of contract.nested_data_keys["doctor.checks[]"]) {
        expect(check).toHaveProperty(key);
      }
    }
  });

  it("keys list JSON output keys match contract", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        items: [
          {
            key_id: "key-1",
            environment: "sandbox",
            service_account_role: "operator",
            created_at: "2026-01-01T00:00:00Z",
            expires_at: null,
          },
        ],
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "--request-id", "01PARITYKEYS", "keys", "list", "--env-file", ".env.local"],
      {
        cwd: process.cwd(),
        fetch: fetchMock,
        stdout,
      },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    for (const key of contract.command_data_keys["keys list"]) {
      expect(payload.data).toHaveProperty(key);
    }
    for (const row of payload.data.keys) {
      for (const key of contract.nested_data_keys["keys list.keys[]"]) {
        expect(row).toHaveProperty(key);
      }
    }
  });

  it("guardrails bootstrap JSON output keys match contract", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        tenant_id: "tenant-sandbox",
        intent_id: "intent-1",
        capability_token: "cap-token",
        operation: "paid-tool",
        requested_spend_cents: 100,
        sandbox_lifecycle_status: "active",
      }),
    );
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "--request-id",
        "01PARITYGUARD",
        "guardrails",
        "bootstrap",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--env-file",
        ".env.local",
      ],
      {
        cwd: process.cwd(),
        fetch: fetchMock,
        stdout,
      },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    for (const key of contract.command_data_keys["guardrails bootstrap"]) {
      expect(payload.data).toHaveProperty(key);
    }
  });

  it.each((contract.parse_error_cases ?? []).map((item, index) => [index, item] as const))(
    "parse error case %# honors JSON envelope on stdout",
    async (_index, item) => {
      const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const code = await runCli(buildArgv(item), { stdout, stderr });
      expect(code).toBe(item.exit_code);
      const payload = JSON.parse(stdout.chunks.join(""));
      expect(payload.ok).toBe(false);
      expect(payload.error).toBeTruthy();
      for (const key of contract.envelope.success_keys) {
        expect(payload).toHaveProperty(key);
      }
      for (const key of contract.envelope.error_object_keys) {
        expect(payload.error).toHaveProperty(key);
      }
      if (item.error) {
        expect(payload.error.category).toBe(item.error.category);
        expect(payload.error.code).toBe(item.error.code);
      }
      expect(payload.error.message).toContain(item.message_contains);
      expect(stderr.chunks.join("")).toBe("");
    },
  );

  it.each((contract.help_paths ?? []).map((item, index) => [index, item] as const))(
    "help path %# matches contract",
    async (_index, item) => {
      const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const code = await runCli(item.argv, { stdout });
      expect(code).toBe(0);
      expect(stdout.chunks.join("")).toContain(item.contains);
    },
  );

  it.each((contract.global_flag_placement ?? []).map((item, index) => [index, item] as const))(
    "global flag placement %# matches contract",
    async (_index, item) => {
      if (item.with_api_key) {
        vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
      }
      const fetchMock = vi.fn().mockResolvedValue(
        jsonResponse({
          tenant_id: "tenant-sandbox",
          tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
          environment: "sandbox",
          service_account_role: "operator",
        }),
      );
      const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
      const code = await runCli(item.argv, { cwd: process.cwd(), fetch: fetchMock, stdout });
      if (item.with_api_key) {
        vi.unstubAllEnvs();
      }
      expect(code).toBe(item.exit_code);
      if (item.envelope_ok) {
        const payload = JSON.parse(stdout.chunks.join(""));
        expect(payload.ok).toBe(true);
        for (const key of contract.envelope.success_keys) {
          expect(payload).toHaveProperty(key);
        }
      }
    },
  );

  it("contract matches commands.json spec", () => {
    const spec = JSON.parse(readFileSync(COMMANDS_PATH, "utf8")) as {
      envelope: CliParityContract["envelope"];
      key_masking: CliParityContract["key_masking"];
      error_cases: CliParityContract["error_cases"];
      parse_error_cases?: CliParityContract["parse_error_cases"];
      help_paths?: CliParityContract["help_paths"];
      global_flag_placement?: CliParityContract["global_flag_placement"];
      commands: Array<{ path: string }>;
    };
    expect(contract.envelope).toEqual(spec.envelope);
    expect(contract.key_masking).toEqual(spec.key_masking);
    expect(contract.error_cases).toEqual(spec.error_cases);
    expect(contract.parse_error_cases ?? []).toEqual(spec.parse_error_cases ?? []);
    expect(contract.help_paths ?? []).toEqual(spec.help_paths ?? []);
    expect(contract.global_flag_placement ?? []).toEqual(spec.global_flag_placement ?? []);
    expect(Object.keys(contract.command_help).sort()).toEqual(spec.commands.map((command) => command.path).sort());
  });

  it("declares the shared signed audit manifest fixture", () => {
    const fixtureRel = (contract as CliParityContract & {
      shared_fixtures: { signed_audit_manifest: string };
    }).shared_fixtures.signed_audit_manifest;
    const fixturePath = join(process.cwd(), "..", "cli-parity", fixtureRel);
    const manifest = JSON.parse(readFileSync(fixturePath, "utf8")) as Record<string, unknown>;
    expect(manifest.kind).toBe("paybond.audit_export_manifest_v1");
    expect(manifest.job_id).toBe("job-parity-1");
  });
});
