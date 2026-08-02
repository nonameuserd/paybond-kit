import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  MCP_RESTRICTED_KEY_HINT,
  evaluateMcpCredentialChecks,
  runMcpDoctorChecks,
} from "../src/cli/doctor-mcp.js";

function checksFor(overrides: Partial<Parameters<typeof evaluateMcpCredentialChecks>[0]> = {}) {
  return evaluateMcpCredentialChecks({
    keyKind: "restricted",
    toolPolicy: null,
    toolAllowlist: null,
    configPath: "/tmp/.paybond/mcp.json",
    envFile: "/tmp/.env.local",
    ...overrides,
  });
}

function checkNamed(checks: ReturnType<typeof checksFor>, name: string) {
  const found = checks.find((check) => check.name === name);
  if (!found) {
    throw new Error(`missing check ${name}`);
  }
  return found;
}

describe("evaluateMcpCredentialChecks", () => {
  it("passes a restricted key", () => {
    const checks = checksFor();
    expect(checkNamed(checks, "mcp_credential_kind").ok).toBe(true);
    expect(checkNamed(checks, "mcp_credential_tool_policy").ok).toBe(true);
  });

  // The whole point of the check: a standard key hands an MCP host the full role
  // surface, and the gateway has nothing to cap it with.
  it("warns and fails on an unrestricted standard key", () => {
    const checks = checksFor({ keyKind: "standard" });
    const kind = checkNamed(checks, "mcp_credential_kind");
    expect(kind.ok).toBe(false);
    expect(kind.message).toContain("unrestricted paybond_sk_ key");
    expect(kind.message).toContain(MCP_RESTRICTED_KEY_HINT);
    expect(kind.details?.severity).toBe("warning");
    expect(kind.details?.remediation).toBe(MCP_RESTRICTED_KEY_HINT);
  });

  it("fails the tool-policy check for a standard key with no host-side narrowing", () => {
    const policy = checkNamed(checksFor({ keyKind: "standard" }), "mcp_credential_tool_policy");
    expect(policy.ok).toBe(false);
    expect(policy.message).toContain("PAYBOND_MCP_TOOL_POLICY");
  });

  // `spend-write` is what the MCP server assumes when nothing is configured, so
  // finding it in a host config is not evidence anyone narrowed the surface.
  it("treats the default spend-write policy as no narrowing at all", () => {
    const policy = checkNamed(
      checksFor({ keyKind: "standard", toolPolicy: "spend-write" }),
      "mcp_credential_tool_policy",
    );
    expect(policy.ok).toBe(false);
    expect(policy.message).toContain("spend-write");
  });

  // A dev-grade guardrail is still a guardrail: the key check keeps failing, but
  // the mitigation check should not double-report the same finding.
  it("accepts a standard key narrowed by a tool policy", () => {
    const checks = checksFor({ keyKind: "standard", toolPolicy: "readonly" });
    expect(checkNamed(checks, "mcp_credential_kind").ok).toBe(false);
    const policy = checkNamed(checks, "mcp_credential_tool_policy");
    expect(policy.ok).toBe(true);
    expect(policy.message).toContain("dev override");
    expect(policy.details?.tool_policy).toBe("readonly");
  });

  it("accepts an allowlist as narrowing for a standard key", () => {
    const policy = checkNamed(
      checksFor({ keyKind: "standard", toolPolicy: "allowlist", toolAllowlist: "paybond_signal_reputation" }),
      "mcp_credential_tool_policy",
    );
    expect(policy.ok).toBe(true);
  });

  it("notes that a tool policy is ignored for restricted keys", () => {
    const policy = checkNamed(checksFor({ toolPolicy: "readonly" }), "mcp_credential_tool_policy");
    expect(policy.ok).toBe(true);
    expect(policy.message).toContain("ignored for restricted keys");
  });

  it("reports an unreadable credential as skipped rather than passing", () => {
    const checks = checksFor({ keyKind: "unknown" });
    expect(checkNamed(checks, "mcp_credential_kind").ok).toBe(false);
    expect(checkNamed(checks, "mcp_credential_kind").message).toContain("no readable Paybond API key");
    expect(checkNamed(checks, "mcp_credential_tool_policy").ok).toBe(true);
  });

  it("carries the inspected config path and env file in details", () => {
    const kind = checkNamed(checksFor(), "mcp_credential_kind");
    expect(kind.details).toMatchObject({
      key_kind: "restricted",
      env_file: "/tmp/.env.local",
      config_path: "/tmp/.paybond/mcp.json",
    });
  });
});

describe("runMcpDoctorChecks", () => {
  async function workspaceWithKey(key: string): Promise<string> {
    const cwd = await mkdtemp(path.join(tmpdir(), "paybond-doctor-mcp-"));
    await writeFile(path.join(cwd, ".env.local"), `PAYBOND_API_KEY=${key}\n`, "utf8");
    return cwd;
  }

  it("grades the key in the workspace env file the generated config points at", async () => {
    const cwd = await workspaceWithKey("paybond_sk_live_example");
    const checks = await runMcpDoctorChecks({
      envFile: ".env.local",
      cwd,
      home: cwd,
      host: "claude",
    });
    const kind = checkNamed(checks, "mcp_credential_kind");
    expect(kind.ok).toBe(false);
    expect(kind.message).toContain("unrestricted paybond_sk_ key");
    expect(kind.details?.env_file).toBe(path.join(cwd, ".env.local"));
  });

  it("passes once the workspace holds a restricted key", async () => {
    const cwd = await workspaceWithKey("paybond_rk_live_example");
    const checks = await runMcpDoctorChecks({
      envFile: ".env.local",
      cwd,
      home: cwd,
      host: "claude",
    });
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it("reports an unreadable host config as a failed check instead of throwing", async () => {
    const cwd = await workspaceWithKey("paybond_rk_live_example");
    const configPath = path.join(cwd, "broken.json");
    await writeFile(configPath, "{not json", "utf8");
    const checks = await runMcpDoctorChecks({
      envFile: ".env.local",
      cwd,
      home: cwd,
      host: "claude",
      configPath,
    });
    expect(checkNamed(checks, "mcp_credential_kind").ok).toBe(false);
    expect(checkNamed(checks, "mcp_credential_kind").message).toContain("host config");
  });

  it("fails instead of grading the workspace when the host config has no Paybond entry", async () => {
    const cwd = await workspaceWithKey("paybond_rk_live_example");
    const configPath = path.join(cwd, "mcp.json");
    await writeFile(configPath, JSON.stringify({ mcpServers: {} }), "utf8");
    const checks = await runMcpDoctorChecks({
      envFile: ".env.local",
      cwd,
      home: cwd,
      host: "claude",
      configPath,
    });
    const kind = checkNamed(checks, "mcp_credential_kind");
    expect(kind.ok).toBe(false);
    expect(kind.message).toContain("no usable Paybond MCP server entry");
  });
});
