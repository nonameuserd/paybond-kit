import { mkdtemp, writeFile } from "node:fs/promises";
import { get } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { listDevTraceEvents } from "../../src/dev/trace-buffer.js";
import { startDevTraceServer } from "../../src/dev/trace-server.js";
import { runCli } from "../../src/cli/router.js";
import { createAgentGatewayFetch, LIVE_RAW_KEY, SANDBOX_RAW_KEY } from "./agent-gateway-mock.js";

function stdoutCollector() {
  return {
    chunks: [] as string[],
    write(chunk: string): boolean {
      this.chunks.push(chunk);
      return true;
    },
  };
}

async function runDevCli(
  argv: string[],
  options: { cwd?: string; fetch?: typeof fetch; env?: Record<string, string> } = {},
) {
  if (options.env) {
    for (const [key, value] of Object.entries(options.env)) {
      vi.stubEnv(key, value);
    }
  } else {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
  }
  const stdout = stdoutCollector();
  const code = await runCli(["--format", "json", ...argv], {
    cwd: options.cwd,
    fetch: options.fetch,
    stdout,
  });
  vi.unstubAllEnvs();
  return { code, payload: JSON.parse(stdout.chunks.join("")) };
}

describe("paybond dev commands", () => {
  it("dev smoke wraps agent sandbox smoke with travel preset defaults", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-smoke-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runDevCli(["dev", "smoke"], { cwd, fetch: fetch as typeof fetch });
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.operation).toBe("travel.book_hotel");
    const traceUrl = String(payload.data.trace_url);
    expect(traceUrl).toMatch(/\/runs\//);
    const runId = decodeURIComponent(traceUrl.split("/").pop() ?? "");
    const events = listDevTraceEvents();
    expect(events.some((event) => event.id === runId || event.run_id === runId)).toBe(true);
    expect(payload.data.audit_log).toMatch(/dev-audit\.jsonl$/);
    expect(payload.data.checklist_lines).toEqual([
      expect.stringContaining("Policy loaded (travel)"),
      "✓ Sandbox intent created",
      "✓ Tool call: travel.book_hotel",
      expect.stringContaining("Spend approved"),
      expect.stringContaining("Evidence validated"),
      "✓ Settlement simulated",
      expect.stringMatching(/^✓ Trace → /),
      expect.stringMatching(/^✓ Console → /),
      expect.stringMatching(/^✓ Replay → /),
      "Success",
    ]);
  });

  it("dev smoke renders checklist table output", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-smoke-table-"));
    const fetch = createAgentGatewayFetch();
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const stdout = stdoutCollector();
    const code = await runCli(["--no-color", "dev", "smoke"], {
      cwd,
      fetch: fetch as typeof fetch,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    expect(output).toContain("Policy loaded (travel)");
    expect(output).toContain("Tool call: travel.book_hotel");
    expect(output).toContain("Success");
    expect(output).not.toContain('"bind"');
  });

  it("dev loop runs login skip, policy init, validate-tools, and smoke", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-loop-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runDevCli(["dev", "loop", "--no-login"], {
      cwd,
      fetch: fetch as typeof fetch,
    });
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.steps.map((step: { name: string }) => step.name)).toEqual([
      "login",
      "policy_init",
      "validate_tools",
      "smoke",
    ]);
    expect(payload.data.steps[0].skipped).toBe(true);
    expect(payload.data.steps[2].ok).toBe(true);
    expect(payload.data.banner_lines).toEqual([
      "✓ Sandbox capability (or: offline mock)",
      "✓ Settlement simulator",
      expect.stringContaining("Trace dashboard → http://localhost:"),
      "✓ Audit log → .paybond/dev-audit.jsonl",
    ]);
    expect(payload.data.checklist_lines).toEqual(
      expect.arrayContaining([expect.stringContaining("Trace → http://localhost:")]),
    );
    expect(payload.data.smoke.bind.operation).toBe("travel.book_hotel");
  });

  it("dev loop renders startup banner before checklist in table output", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-loop-table-"));
    const fetch = createAgentGatewayFetch();
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const stdout = stdoutCollector();
    const stderr = stdoutCollector();
    const code = await runCli(["--no-color", "dev", "loop", "--no-login"], {
      cwd,
      fetch: fetch as typeof fetch,
      stdout,
      stderr,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    const bannerIndex = output.indexOf("Sandbox capability (or: offline mock)");
    const checklistIndex = output.indexOf("Policy loaded (travel)");
    const traceIndex = output.indexOf("Trace → http://localhost:");
    expect(bannerIndex).toBeGreaterThanOrEqual(0);
    expect(checklistIndex).toBeGreaterThan(bannerIndex);
    expect(traceIndex).toBeGreaterThan(checklistIndex);
    expect(stderr.chunks.join("")).toContain("Trace dashboard → http://localhost:");
  });

  it("dev smoke --offline runs without PAYBOND_API_KEY", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-offline-"));
    vi.unstubAllEnvs();
    delete process.env.PAYBOND_API_KEY;
    const { code, payload } = await runDevCli(["dev", "smoke", "--offline"], { cwd, env: {} });
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.offline).toBe(true);
    expect(payload.data.bind.operation).toBe("travel.book_hotel");
    expect(payload.data.checklist_lines).toEqual(
      expect.arrayContaining([expect.stringContaining("Settlement simulated"), "Success"]),
    );
  });

  it("dev loop --offline skips login and runs smoke", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-offline-loop-"));
    vi.unstubAllEnvs();
    delete process.env.PAYBOND_API_KEY;
    const { code, payload } = await runDevCli(["dev", "loop", "--offline"], { cwd, env: {} });
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.offline).toBe(true);
    expect(payload.data.steps[0]).toMatchObject({
      name: "login",
      skipped: true,
      message: expect.stringContaining("offline"),
    });
    expect(payload.data.banner_lines[0]).toBe("✓ Sandbox capability (or: offline mock)");
    expect(payload.data.checklist_lines).toEqual(
      expect.arrayContaining([expect.stringContaining("Trace → http://localhost:")]),
    );
  });

  it("dev smoke --offline rejects production API keys in PAYBOND_API_KEY", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-offline-live-env-"));
    const { code, payload } = await runDevCli(["dev", "smoke", "--offline"], {
      cwd,
      env: { PAYBOND_API_KEY: LIVE_RAW_KEY },
    });
    expect(code).not.toBe(0);
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.dev.offline_production_key");
  });

  it("dev loop --offline rejects production API keys in PAYBOND_API_KEY", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-offline-loop-live-env-"));
    const { code, payload } = await runDevCli(["dev", "loop", "--offline"], {
      cwd,
      env: { PAYBOND_API_KEY: LIVE_RAW_KEY },
    });
    expect(code).not.toBe(0);
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.dev.offline_production_key");
  });

  it("dev smoke --offline rejects production API keys from .env.local", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-offline-live-file-"));
    await writeFile(join(cwd, ".env.local"), `PAYBOND_API_KEY=${LIVE_RAW_KEY}\n`, "utf8");
    vi.unstubAllEnvs();
    delete process.env.PAYBOND_API_KEY;
    const { code, payload } = await runDevCli(["dev", "smoke", "--offline"], { cwd, env: {} });
    expect(code).not.toBe(0);
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.dev.offline_production_key");
  });

  it("dev trace server serves timeline steps from persisted smoke events", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-dev-trace-"));
    const fetch = createAgentGatewayFetch();
    await runDevCli(["dev", "smoke"], { cwd, fetch: fetch as typeof fetch });

    const server = await startDevTraceServer({ port: 0, cwd });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("expected bound TCP port");
    }

    const eventsPayload = await new Promise<string>((resolve, reject) => {
      get(`http://127.0.0.1:${address.port}/api/events`, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      }).on("error", reject);
    });
    const parsed = JSON.parse(eventsPayload) as {
      events: Array<{ operation: string; steps?: Array<{ phase: string }> }>;
    };
    expect(parsed.events.length).toBeGreaterThan(0);
    expect(parsed.events.at(-1)?.operation).toBe("travel.book_hotel");
    expect(parsed.events.at(-1)?.steps?.map((step) => step.phase)).toEqual(
      expect.arrayContaining(["tool", "authorize", "evidence"]),
    );

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
