import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { runCli } from "../../src/cli/router.js";

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GATEWAY = "https://gateway.test";
const OPERATOR_DID = "did:example:alice";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function runDiscoveryCli(
  argv: string[],
  options: { cwd?: string; fetch?: typeof fetch } = {},
) {
  vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
  const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
  const code = await runCli(["--gateway", GATEWAY, "--format", "json", ...argv], {
    cwd: options.cwd,
    fetch: options.fetch,
    stdout,
  });
  return { code, payload: JSON.parse(stdout.chunks.join("")) };
}

describe("discovery CLI gateway routes", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("signal portfolio uses auth-scoped /signal/v1/portfolio/summary", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-discovery-"));
    const requestedUrls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      requestedUrls.push(url);
      if (url.endsWith("/signal/v1/portfolio/summary")) {
        return jsonResponse({ tenant_id: "realm-z", operator_count: 2 });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const { code, payload } = await runDiscoveryCli(["signal", "portfolio"], { cwd, fetch: fetchMock });
    expect(code).toBe(0);
    expect(payload.data.operator_count).toBe(2);
    expect(requestedUrls.some((url) => url.endsWith("/signal/v1/portfolio/summary"))).toBe(true);
    expect(requestedUrls.some((url) => url.includes("/v1/auth/principal"))).toBe(false);
  });

  it("signal reputation uses /reputation/{did}", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-discovery-"));
    const requestedUrls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      requestedUrls.push(url);
      if (url.includes("/reputation/did%3Aexample%3Aalice")) {
        return jsonResponse({ receipt: { tenant_id: "realm-z", operator_did: OPERATOR_DID } });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const { code } = await runDiscoveryCli(["signal", "reputation", "--did", OPERATOR_DID], {
      cwd,
      fetch: fetchMock,
    });
    expect(code).toBe(0);
    expect(requestedUrls.some((url) => url.includes("/reputation/did%3Aexample%3Aalice"))).toBe(true);
  });

  it("signal fraud uses /signal/v1/operators/{did}/review-status", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-discovery-"));
    const requestedUrls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      requestedUrls.push(url);
      if (url.endsWith("/signal/v1/operators/did%3Aexample%3Aalice/review-status")) {
        return jsonResponse({ tenant_id: "realm-z", operator_did: OPERATOR_DID, review_state: "clear" });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });

    const { code } = await runDiscoveryCli(["signal", "fraud", "--did", OPERATOR_DID], {
      cwd,
      fetch: fetchMock,
    });
    expect(code).toBe(0);
    expect(
      requestedUrls.some((url) => url.endsWith("/signal/v1/operators/did%3Aexample%3Aalice/review-status")),
    ).toBe(true);
  });

  it("mandates import posts to /protocol/v2/mandates", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-cli-discovery-"));
    const bodyPath = join(cwd, "mandate.json");
    await writeFile(bodyPath, JSON.stringify({ mandate_id: "mandate-1", payload: { ok: true } }));

    const requestedUrls: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      requestedUrls.push(url);
      if (url.endsWith("/protocol/v2/mandates") && init?.method === "POST") {
        return jsonResponse({ mandate_id: "mandate-1", status: "imported" });
      }
      throw new Error(`unexpected fetch: ${url} ${init?.method ?? "GET"}`);
    });

    const { code } = await runDiscoveryCli(["mandates", "import", "--body", bodyPath], {
      cwd,
      fetch: fetchMock,
    });
    expect(code).toBe(0);
    expect(requestedUrls.some((url) => url.endsWith("/protocol/v2/mandates"))).toBe(true);
  });
});
