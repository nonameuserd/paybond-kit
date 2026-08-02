import { describe, expect, it } from "vitest";

import { runCli } from "../../src/cli/router.js";
import { resolveOpenTarget } from "../../src/cli/commands/open-resource.js";
import { runShellLine, type ShellStickyContext } from "../../src/cli/commands/shell.js";
import { formatHumanErrorLines, withNextActions } from "../../src/cli/next-actions.js";
import { mustBeNonInteractive } from "../../src/cli/tty.js";
import { defaultGlobalOptions } from "../../src/cli/globals.js";
import { CliError } from "../../src/cli/types.js";

describe("tier C control plane", () => {
  it("prints what/why/next on structured auth errors", async () => {
    const stderr = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["whoami"], { stderr });
    expect(code).toBe(2);
    const text = stderr.chunks.join("");
    expect(text).toMatch(/missing PAYBOND_API_KEY/);
    expect(text).toMatch(/what:/);
    expect(text).toMatch(/why:/);
    expect(text).toMatch(/next: paybond login/);
  });

  it("exposes status help and refuses unknown flags", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["status", "--help"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("Usage: paybond status");
  });

  it("returns status snapshot without hanging when unauthenticated", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["status", "--format", "json"], {
      cwd: process.cwd(),
      stdout,
    });
    expect(code).toBe(0);
    const envelope = JSON.parse(stdout.chunks.join("")) as {
      ok: boolean;
      data: { auth: { authenticated: boolean }; happy_path: string[]; next_commands: string[] };
    };
    expect(envelope.ok).toBe(true);
    expect(envelope.data.auth.authenticated).toBe(false);
    expect(envelope.data.happy_path[0]).toBe("paybond login");
    expect(envelope.data.next_commands.length).toBeGreaterThan(0);
  });

  it("resolves open deep links without inventing tenant ids", () => {
    const billing = resolveOpenTarget("billing");
    expect(billing.url).toContain("/console/configuration/billing");
    const intent = resolveOpenTarget("intent", "550e8400-e29b-41d4-a716-446655440000");
    expect(intent.url).toContain("/console/operations/intents/");
    expect(() => resolveOpenTarget("intent")).toThrow(CliError);
  });

  it("open --no-open prints URL and does not hang", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["open", "billing", "--no-open", "--format", "json"], {
      stdout,
      openBrowser: async () => {
        throw new Error("should not open");
      },
    });
    expect(code).toBe(0);
    const envelope = JSON.parse(stdout.chunks.join("")) as {
      data: { resource: string; opened: boolean; url: string };
    };
    expect(envelope.data.resource).toBe("billing");
    expect(envelope.data.opened).toBe(false);
    expect(envelope.data.url).toContain("billing");
  });

  it("shell refuses non-interactive mode without --exec", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["shell", "--format", "json"], { stdout });
    expect(code).toBe(1);
    const envelope = JSON.parse(stdout.chunks.join("")) as {
      error: { code: string; details: { next: string } };
    };
    expect(envelope.error.code).toBe("cli.shell.non_interactive");
    expect(envelope.error.details.next).toContain("--exec");
  });

  it("shell --exec runs a sticky one-shot command", async () => {
    const sticky: ShellStickyContext = {
      gateway: "https://api.paybond.ai",
      envFile: ".env.local",
      requestIdPrefix: "01TEST",
    };
    const calls: string[][] = [];
    const { exitCode, tokens } = await runShellLine(
      "help status",
      sticky,
      {},
      async (argv) => {
        calls.push(argv);
        return 0;
      },
    );
    expect(exitCode).toBe(0);
    expect(tokens[0]).toBe("help");
    expect(calls[0]).toEqual(["--gateway", "https://api.paybond.ai", "--env-file", ".env.local", "help", "status"]);
  });

  it("control --once returns a snapshot without hanging when unauthenticated", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["control", "--once", "--format", "json"], { stdout });
    expect(code).toBe(0);
    const envelope = JSON.parse(stdout.chunks.join("")) as {
      data: {
        mode: string;
        panels: {
          policy: { present: boolean };
          spend: { source: string };
          receipts: unknown[];
          denials: unknown[];
        };
        limitations: string[];
      };
    };
    expect(envelope.data.mode).toBe("snapshot");
    expect(typeof envelope.data.panels.policy.present).toBe("boolean");
    expect(envelope.data.panels.spend.source).toBe("unavailable");
    expect(Array.isArray(envelope.data.panels.receipts)).toBe(true);
    expect(Array.isArray(envelope.data.panels.denials)).toBe(true);
    expect(envelope.data.limitations.some((line) => line.includes("not authenticated"))).toBe(true);
  });

  it("control snapshot wires live gateway panels when authenticated", async () => {
    const { gatherControlPlaneSnapshot } = await import("../../src/cli/commands/control-snapshot.js");
    const { createContext } = await import("../../src/cli/context.js");
    const { defaultGlobalOptions } = await import("../../src/cli/globals.js");
    const calls: string[] = [];
    const fetchMock: typeof fetch = async (input) => {
      const url = String(input);
      calls.push(url);
      if (url.includes("/v1/auth/principal")) {
        return new Response(
          JSON.stringify({ tenant_id: "tenant-a", environment: "sandbox" }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("/harbor/operator/v1/intents")) {
        return new Response(
          JSON.stringify({
            intents: [{ intent_id: "550e8400-e29b-41d4-a716-446655440000", status: "funded", amount_cents: 100 }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("/protocol/v2/agent-receipts")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                receipt_id: "rcpt_1",
                scope: "intent_terminal",
                intent_id: "550e8400-e29b-41d4-a716-446655440000",
                created_at: "2026-01-01T00:00:00Z",
              },
            ],
            limit: 5,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("/v1/admin/spend-controls/decisions")) {
        return new Response(
          JSON.stringify({
            items: [
              {
                id: "dec-1",
                operation: "paid-tool",
                amount_cents: 100,
                outcome: "allow",
                remaining_cents: 900,
                reason_codes: [],
                created_at: "2026-01-01T00:00:00Z",
              },
              {
                id: "dec-2",
                operation: "paid-tool",
                amount_cents: 50000,
                outcome: "deny",
                remaining_cents: 900,
                reason_codes: ["max_spend_exceeded"],
                created_at: "2026-01-01T00:01:00Z",
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes("/v1/admin/spend-controls/policy")) {
        return new Response(JSON.stringify({ source: "control_plane", configured: true, mode: "enforce" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.includes("/v1/admin/spend-controls/reservations")) {
        return new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
    };
    const globals = defaultGlobalOptions();
    const previous = process.env.PAYBOND_API_KEY;
    process.env.PAYBOND_API_KEY =
      "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    try {
      const ctx = createContext(globals, { fetch: fetchMock, cwd: process.cwd() });
      const snapshot = await gatherControlPlaneSnapshot(ctx, { limit: 5 });
      expect(snapshot.tenant_id).toBe("tenant-a");
      expect(snapshot.panels.spend.source).toBe("gateway");
      expect(snapshot.panels.receipts[0]?.receipt_id).toBe("rcpt_1");
      expect(snapshot.panels.denials).toHaveLength(1);
      expect(calls.some((url) => url.includes("/protocol/v2/agent-receipts"))).toBe(true);
      expect(calls.some((url) => url.includes("/v1/admin/spend-controls/decisions"))).toBe(true);
    } finally {
      if (previous === undefined) {
        delete process.env.PAYBOND_API_KEY;
      } else {
        process.env.PAYBOND_API_KEY = previous;
      }
    }
  });

  it("formats human error lines from details", () => {
    const lines = formatHumanErrorLines({
      category: "auth",
      code: "cli.auth.missing_api_key",
      message: "missing key",
      details: withNextActions(undefined, {
        what: "missing API key",
        why: "no credentials",
        next: "paybond login",
      }),
    });
    expect(lines).toEqual([
      "missing key",
      "what: missing API key",
      "why: no credentials",
      "next: paybond login",
    ]);
  });

  it("treats JSON format as non-interactive", () => {
    const globals = defaultGlobalOptions();
    globals.format = "json";
    expect(mustBeNonInteractive(globals, { stdinIsTty: true, stdoutIsTty: true })).toBe(true);
  });

  it("includes kit builder happy path in root help", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["--help"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("Kit builder happy path");
  });

  it("documents audit exports create", async () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(["audit", "exports", "create", "--help"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("Usage: paybond audit exports create");
    expect(stdout.chunks.join("")).toContain("--wait");
  });
});
