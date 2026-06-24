import { describe, expect, it } from "vitest";

import {
  defaultMcpInstallFormat,
  defaultMcpServerCommand,
  parseMcpInstallFormat,
  parseMcpInstallHost,
  planMcpInstall,
  resolvePackageLocalMcpServerCommand,
  serializeMcpInstallPayload,
  buildMcpServerEntry,
} from "../../src/cli/mcp-install.js";

describe("mcp install", () => {
  it("references PAYBOND_ENV_FILE instead of embedding raw keys", () => {
    const command = defaultMcpServerCommand();
    const entry = buildMcpServerEntry(".env.local", command);
    const generic = JSON.parse(serializeMcpInstallPayload("json", entry));
    expect(generic.mcpServers.paybond.env.PAYBOND_ENV_FILE).toBe(".env.local");
    expect(generic.mcpServers.paybond.env.PAYBOND_API_KEY).toBeUndefined();
  });

  it("uses the package-local canonical MCP server command", () => {
    const command = resolvePackageLocalMcpServerCommand();
    expect(command[0]).toBe(process.execPath);
    expect(command[1]).toMatch(/mcp-server\.js$/);
  });

  it("defaults codex installs to TOML and other hosts to JSON", () => {
    expect(defaultMcpInstallFormat("codex")).toBe("toml");
    expect(parseMcpInstallFormat(undefined, "codex")).toBe("toml");
    expect(parseMcpInstallFormat(undefined, "claude")).toBe("json");
  });

  it("rejects unknown host labels", () => {
    expect(() => parseMcpInstallHost("cursor")).toThrow(/invalid --host/);
    expect(() => parseMcpInstallHost(undefined)).toThrow(/missing --host/);
  });

  it("writes project-scoped host-neutral paths by default", () => {
    const plan = planMcpInstall({
      host: "claude",
      scope: "project",
      format: "json",
      envFile: ".env.local",
      cwd: "/tmp/project",
      home: "/home/user",
    });
    expect(plan.configPath).toBe("/tmp/project/.paybond/mcp.json");
    expect(plan.printed).toBe(false);
  });

  it("prints instead of writing for local scope", () => {
    const plan = planMcpInstall({
      host: "generic",
      scope: "local",
      format: "json",
      envFile: ".env.local",
      cwd: "/tmp/project",
      home: "/home/user",
    });
    expect(plan.configPath).toBeNull();
    expect(plan.printed).toBe(true);
    expect(plan.payload).toContain("mcpServers");
  });

  it("supports TOML for codex hosts", () => {
    const plan = planMcpInstall({
      host: "codex",
      scope: "project",
      format: "toml",
      envFile: ".env.local",
      cwd: "/tmp/project",
      home: "/home/user",
    });
    expect(plan.configPath).toBe("/tmp/project/.paybond/mcp.toml");
    expect(plan.payload).toContain("[mcp_servers.paybond]");
  });
});

declare const process: { execPath: string };
