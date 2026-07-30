import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  assertPolicyReloadCompatibleWithHttp,
  createMcpHttpRequestListener,
  mcpHttpServerOptionsFromEnv,
  type McpHttpServerOptions,
} from "../src/mcp-http-server.js";

// Captured before any test stubs `globalThis.fetch` to mock outbound gateway
// calls. Requests this file sends to the in-process test server must always
// use the real network stack, never the stubbed gateway fetch.
const realFetch: typeof fetch = globalThis.fetch.bind(globalThis);

function apiKey(fill = "a"): string {
  return `paybond_sk_${fill.repeat(32)}_${fill.repeat(64)}`;
}

type TestServer = {
  baseUrl: string;
  close: () => Promise<void>;
};

function startTestServer(options: McpHttpServerOptions = {}): Promise<TestServer> {
  return new Promise((resolve, reject) => {
    const listener = createMcpHttpRequestListener({
      operatorSettings: { gatewayBaseUrl: "https://gateway.test" },
      ...options,
    });
    const server = createServer(listener);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        close: () => new Promise<void>((res) => server.close(() => res())),
      });
    });
  });
}

async function post(
  server: TestServer,
  path: string,
  init: { headers?: Record<string, string>; body?: unknown } = {},
): Promise<Response> {
  return realFetch(`${server.baseUrl}${path}`, {
    method: "POST",
    headers: init.headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

const openServers: TestServer[] = [];

async function server(options: McpHttpServerOptions = {}): Promise<TestServer> {
  const created = await startTestServer(options);
  openServers.push(created);
  return created;
}

describe("mcp-http-server", () => {
  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await Promise.all(openServers.splice(0).map((s) => s.close()));
  });

  describe("GET /healthz", () => {
    it("returns 200 without authentication", async () => {
      const s = await server();
      const res = await realFetch(`${s.baseUrl}/healthz`);
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ status: "ok", service: "paybond-mcp-http" });
    });

    it("rejects non-GET methods", async () => {
      const res = await post(await server(), "/healthz");
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("GET");
    });
  });

  describe("unknown routes", () => {
    it("returns 404 for paths other than /mcp and /healthz", async () => {
      const s = await server();
      const res = await realFetch(`${s.baseUrl}/other`);
      expect(res.status).toBe(404);
    });

    it("returns 405 with Allow: POST for non-POST /mcp", async () => {
      const s = await server();
      const res = await realFetch(`${s.baseUrl}/mcp`);
      expect(res.status).toBe(405);
      expect(res.headers.get("allow")).toBe("POST");
    });
  });

  describe("authentication", () => {
    it("returns 401 with WWW-Authenticate when Authorization is missing", async () => {
      const s = await server();
      const res = await post(s, "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "initialize" } });
      expect(res.status).toBe(401);
      expect(res.headers.get("www-authenticate")).toContain("Bearer");
      expect(await res.json()).toMatchObject({ error: "unauthorized" });
    });

    it("returns 401 when the bearer token does not look like a Paybond API key", async () => {
      const s = await server();
      const res = await post(s, "/mcp", {
        headers: { authorization: "Bearer not-a-real-key" },
        body: { jsonrpc: "2.0", id: 1, method: "initialize" },
      });
      expect(res.status).toBe(401);
    });

    it("never forwards a client-supplied tenant_id; tenant is derived only from the bearer key", async () => {
      const fetchMock = vi.fn(async (input: string | URL | Request) => {
        const url = String(input);
        if (url.endsWith("/v1/auth/principal")) {
          return new Response(JSON.stringify({ tenant_id: "tenant-from-key" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        throw new Error(`unexpected url ${url}`);
      });
      vi.stubGlobal("fetch", fetchMock);

      const s = await server();
      const key = apiKey();
      const res = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${key}` },
        body: {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "paybond_get_principal",
            // A malicious or buggy client tries to smuggle a tenant_id; the
            // server must ignore it entirely and scope only via the bearer key.
            arguments: { tenant_id: "attacker-supplied-tenant" },
          },
        },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { result?: { structuredContent?: unknown } };
      expect(body.result?.structuredContent).toEqual({ tenant_id: "tenant-from-key" });

      const principalCall = fetchMock.mock.calls.find(([url]) =>
        String(url).endsWith("/v1/auth/principal"),
      );
      expect(principalCall).toBeDefined();
      const requestInit = principalCall?.[1] as { headers?: Record<string, string> } | undefined;
      expect(requestInit?.headers?.authorization).toBe(`Bearer ${key}`);
    });

    it("scopes each request to its own bearer key with no cross-request state", async () => {
      const seenAuthHeaders: string[] = [];
      const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input);
        if (url.endsWith("/v1/auth/principal")) {
          const headers = init?.headers as Record<string, string> | undefined;
          seenAuthHeaders.push(String(headers?.authorization));
          return new Response(JSON.stringify({ tenant_id: "ok" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        throw new Error(`unexpected url ${url}`);
      });
      vi.stubGlobal("fetch", fetchMock);

      const s = await server();
      const keyA = apiKey("a");
      const keyB = apiKey("b");
      const callToolMessage = (id: number) => ({
        jsonrpc: "2.0",
        id,
        method: "tools/call",
        params: { name: "paybond_get_principal", arguments: {} },
      });

      const [resA, resB] = await Promise.all([
        post(s, "/mcp", { headers: { authorization: `Bearer ${keyA}` }, body: callToolMessage(1) }),
        post(s, "/mcp", { headers: { authorization: `Bearer ${keyB}` }, body: callToolMessage(2) }),
      ]);
      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);
      expect(seenAuthHeaders.sort()).toEqual([`Bearer ${keyA}`, `Bearer ${keyB}`].sort());
    });
  });

  describe("Origin validation", () => {
    it("allows requests with no Origin header regardless of allowlist", async () => {
      const s = await server({ allowedOrigins: ["https://allowed.example"] });
      const res = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${apiKey()}` },
        body: { jsonrpc: "2.0", method: "notifications/initialized" },
      });
      expect(res.status).toBe(202);
    });

    it("rejects a present Origin header that is not allowlisted", async () => {
      const s = await server({ allowedOrigins: ["https://allowed.example"] });
      const res = await post(s, "/mcp", {
        headers: {
          authorization: `Bearer ${apiKey()}`,
          origin: "https://evil.example",
        },
        body: { jsonrpc: "2.0", id: 1, method: "initialize" },
      });
      expect(res.status).toBe(403);
    });

    it("allows an allowlisted Origin header", async () => {
      const s = await server({ allowedOrigins: ["https://allowed.example"] });
      const res = await post(s, "/mcp", {
        headers: {
          authorization: `Bearer ${apiKey()}`,
          origin: "https://allowed.example",
        },
        body: { jsonrpc: "2.0", id: 1, method: "initialize" },
      });
      expect(res.status).toBe(200);
    });
  });

  describe("JSON-RPC request handling", () => {
    it("handles initialize and tools/list over HTTP like the stdio transport", async () => {
      const s = await server();
      const key = apiKey();
      const initRes = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${key}` },
        body: { jsonrpc: "2.0", id: 1, method: "initialize" },
      });
      expect(initRes.status).toBe(200);
      const initBody = (await initRes.json()) as { result?: { serverInfo?: { name?: string } } };
      expect(initBody.result?.serverInfo?.name).toBe("Paybond MCP");

      const listRes = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${key}` },
        body: { jsonrpc: "2.0", id: 2, method: "tools/list" },
      });
      expect(listRes.status).toBe(200);
      const listBody = (await listRes.json()) as { result?: { tools?: Array<{ name: string }> } };
      const names = new Set((listBody.result?.tools ?? []).map((t) => t.name));
      expect(names.has("paybond_get_principal")).toBe(true);
    });

    it("returns 202 with an empty body for notifications (no id)", async () => {
      const s = await server();
      const res = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${apiKey()}` },
        body: { jsonrpc: "2.0", method: "notifications/initialized" },
      });
      expect(res.status).toBe(202);
      expect(await res.text()).toBe("");
    });

    it("returns a JSON-RPC parse error for invalid JSON bodies", async () => {
      const s = await server();
      const res = await realFetch(`${s.baseUrl}/mcp`, {
        method: "POST",
        headers: { authorization: `Bearer ${apiKey()}`, "content-type": "application/json" },
        body: "{not json",
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error?: { code?: number } };
      expect(body.error?.code).toBe(-32700);
    });

    it("returns Invalid Request for a non-object JSON-RPC body", async () => {
      const s = await server();
      const res = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${apiKey()}` },
        body: [1, 2, 3],
      });
      expect(res.status).toBe(400);
      const body = (await res.json()) as { error?: { code?: number } };
      expect(body.error?.code).toBe(-32600);
    });

    it("rejects request bodies larger than the configured limit", async () => {
      const s = await server({ maxBodyBytes: 16 });
      const res = await post(s, "/mcp", {
        headers: { authorization: `Bearer ${apiKey()}` },
        body: { jsonrpc: "2.0", id: 1, method: "initialize", padding: "x".repeat(100) },
      });
      expect(res.status).toBe(413);
    });
  });

  describe("rate limiting", () => {
    it("returns 429 once the unauthenticated rate limit is exceeded", async () => {
      const s = await server({ unauthenticatedRateLimitPerMinute: 1 });
      const first = await post(s, "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "initialize" } });
      expect(first.status).toBe(401);
      const second = await post(s, "/mcp", { body: { jsonrpc: "2.0", id: 1, method: "initialize" } });
      expect(second.status).toBe(429);
      expect(second.headers.get("retry-after")).toBeTruthy();
    });

    it("returns 429 once the per-key rate limit is exceeded", async () => {
      const s = await server({ rateLimitPerMinute: 1 });
      const key = apiKey();
      const msg = { jsonrpc: "2.0", id: 1, method: "tools/list" };
      const first = await post(s, "/mcp", { headers: { authorization: `Bearer ${key}` }, body: msg });
      expect(first.status).toBe(200);
      const second = await post(s, "/mcp", { headers: { authorization: `Bearer ${key}` }, body: msg });
      expect(second.status).toBe(429);
    });

    it("tracks rate limits independently per API key", async () => {
      const s = await server({ rateLimitPerMinute: 1 });
      const msg = { jsonrpc: "2.0", id: 1, method: "tools/list" };
      const resA = await post(s, "/mcp", { headers: { authorization: `Bearer ${apiKey("a")}` }, body: msg });
      const resB = await post(s, "/mcp", { headers: { authorization: `Bearer ${apiKey("b")}` }, body: msg });
      expect(resA.status).toBe(200);
      expect(resB.status).toBe(200);
    });
  });
});

describe("assertPolicyReloadCompatibleWithHttp", () => {
  it("allows undefined and off reload modes", () => {
    expect(() => assertPolicyReloadCompatibleWithHttp({ policyReload: null })).not.toThrow();
    expect(() =>
      assertPolicyReloadCompatibleWithHttp({ policyReload: { reloadMode: "off" } as never }),
    ).not.toThrow();
  });

  it("rejects watch and poll reload modes", () => {
    expect(() =>
      assertPolicyReloadCompatibleWithHttp({ policyReload: { reloadMode: "watch" } as never }),
    ).toThrow(/PAYBOND_POLICY_RELOAD=watch is not supported/);
    expect(() =>
      assertPolicyReloadCompatibleWithHttp({ policyReload: { reloadMode: "poll" } as never }),
    ).toThrow(/PAYBOND_POLICY_RELOAD=poll is not supported/);
  });
});

describe("mcpHttpServerOptionsFromEnv", () => {
  it("applies documented defaults when no env vars are set", () => {
    const options = mcpHttpServerOptionsFromEnv({});
    expect(options.addr).toBe("0.0.0.0:8080");
    expect(options.allowedOrigins).toEqual([]);
    expect(options.maxBodyBytes).toBe(1_048_576);
    expect(options.rateLimitPerMinute).toBe(120);
    expect(options.unauthenticatedRateLimitPerMinute).toBe(30);
  });

  it("parses overrides from environment variables", () => {
    const options = mcpHttpServerOptionsFromEnv({
      PAYBOND_MCP_HTTP_ADDR: "0.0.0.0:9000",
      PAYBOND_MCP_HTTP_ALLOWED_ORIGINS: "https://a.example, https://b.example",
      PAYBOND_MCP_HTTP_MAX_BODY_BYTES: "2048",
      PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE: "60",
      PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE: "5",
      PAYBOND_GATEWAY_URL: "https://gateway.test",
    });
    expect(options.addr).toBe("0.0.0.0:9000");
    expect(options.allowedOrigins).toEqual(["https://a.example", "https://b.example"]);
    expect(options.maxBodyBytes).toBe(2048);
    expect(options.rateLimitPerMinute).toBe(60);
    expect(options.unauthenticatedRateLimitPerMinute).toBe(5);
  });

  it("throws when PAYBOND_POLICY_RELOAD is watch or poll", () => {
    expect(() =>
      mcpHttpServerOptionsFromEnv({
        PAYBOND_GATEWAY_URL: "https://gateway.test",
        PAYBOND_POLICY_RELOAD: "watch",
        PAYBOND_POLICY_FILE: "/tmp/paybond.policy.json",
      }),
    ).toThrow(/not supported by the Streamable HTTP transport/);
  });

  it("rejects a non-positive integer override", () => {
    expect(() =>
      mcpHttpServerOptionsFromEnv({
        PAYBOND_GATEWAY_URL: "https://gateway.test",
        PAYBOND_MCP_HTTP_MAX_BODY_BYTES: "0",
      }),
    ).toThrow(/invalid PAYBOND_MCP_HTTP_MAX_BODY_BYTES/);
  });
});
