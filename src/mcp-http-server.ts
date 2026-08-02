/**
 * Streamable HTTP transport for the tenant-bound Paybond MCP server.
 *
 * Not a standalone CLI entrypoint: `main()` here is invoked from
 * `paybond mcp serve --transport http` (see cli/commands/setup.ts). There is no
 * separate `paybond-mcp-http-server` binary — this keeps one canonical CLI
 * surface for both transports instead of a second legacy-alias binary.
 *
 * Unlike the stdio transport (`mcp-server.ts`), this transport is designed to be
 * reachable over the network and multi-tenant: the process holds no baked-in
 * `PAYBOND_API_KEY`. Every `POST /mcp` request supplies its own Paybond
 * credential as `Authorization: Bearer <paybond_rk_...|paybond_sk_...|paybond_oat_...>`,
 * and tenant scope is derived from that credential alone — never from a
 * client-supplied `tenant_id` or other request field. Each request is handled by
 * a fresh, short-lived `PaybondMCPServer` instance scoped to the presented
 * credential; nothing is cached or shared across requests, so a compromised or
 * misbehaving caller can never observe another tenant's state. That per-request
 * instance is also what keeps restricted (`paybond_rk_*`) keys and user-scoped
 * MCP OAuth (`paybond_oat_*`) tokens correct here: each request resolves its own
 * principal and therefore its own `mcp_scopes`, so two credentials hitting this
 * process see two different tool surfaces and no scope grant is ever reused.
 *
 * This statelessness has one deliberate trade-off versus stdio: the in-memory
 * capability-token convenience cache (see mcp-capability-token-cache.ts) and
 * `PAYBOND_POLICY_RELOAD=watch|poll` hot reload both depend on one long-lived
 * process instance and do not carry over between HTTP requests. Callers must
 * pass `capability_token` explicitly to `paybond_authorize_agent_spend` /
 * `paybond_verify_capability` (already the documented pattern). Policy hot
 * reload is rejected at startup in this transport — see
 * `assertPolicyReloadCompatibleWithHttp`.
 */

import { createHash } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import {
  mcpOperatorSettingsFromEnv,
  PaybondMCPServer,
  type PaybondMCPSettings,
} from "./mcp-server.js";
import {
  MCP_OAUTH_ACCESS_TOKEN_PREFIX,
  RESTRICTED_API_KEY_PREFIX,
  STANDARD_API_KEY_PREFIX,
} from "./mcp/scope-catalog.js";

const MCP_PATH = "/mcp";
const HEALTHZ_PATH = "/healthz";
/** Restricted keys, standard keys, and MCP OAuth access tokens are accepted. */
const API_KEY_PREFIXES: readonly string[] = [
  STANDARD_API_KEY_PREFIX,
  RESTRICTED_API_KEY_PREFIX,
  MCP_OAUTH_ACCESS_TOKEN_PREFIX,
];
const RATE_LIMIT_WINDOW_MS = 60_000;

const DEFAULT_ADDR = "0.0.0.0:8080";
const DEFAULT_MAX_BODY_BYTES = 1_048_576; // 1 MiB: JSON-RPC tool payloads, no file uploads.
const DEFAULT_RATE_LIMIT_PER_MINUTE = 120; // per authenticated API key
const DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE = 30; // per source IP, slows credential scanning

export type ResolvedMcpHttpServerOptions = {
  addr: string;
  allowedOrigins: string[];
  maxBodyBytes: number;
  rateLimitPerMinute: number;
  unauthenticatedRateLimitPerMinute: number;
  operatorSettings: Omit<PaybondMCPSettings, "apiKey">;
};

export type McpHttpServerOptions = Partial<
  Omit<ResolvedMcpHttpServerOptions, "operatorSettings">
> & {
  operatorSettings?: Omit<PaybondMCPSettings, "apiKey">;
};

/**
 * `PAYBOND_POLICY_RELOAD=watch|poll` opens a file watcher or poll timer that lives
 * for the lifetime of one `PaybondMCPRuntime` instance. The HTTP transport builds a
 * fresh instance per request (see module docstring), so enabling watch/poll reload
 * here would leak one watcher/timer per request forever. `off` (the default) is
 * safe because it only loads the policy file synchronously with no background
 * work. Fail closed at startup rather than leaking resources silently in production.
 */
export function assertPolicyReloadCompatibleWithHttp(
  operatorSettings: Pick<PaybondMCPSettings, "policyReload">,
): void {
  const mode = operatorSettings.policyReload?.reloadMode;
  if (mode && mode !== "off") {
    throw new Error(
      `PAYBOND_POLICY_RELOAD=${mode} is not supported by the Streamable HTTP transport ` +
        "(it would leak a file watcher/poll timer per request). Use PAYBOND_POLICY_RELOAD=off " +
        "(or unset it) for HTTP/hosted deployments, and reserve watch/poll for long-lived stdio processes.",
    );
  }
}

function optionalEnv(value: string | undefined): string | undefined {
  return value?.trim() ? value.trim() : undefined;
}

function parsePositiveInt(raw: string | undefined, fallback: number, name: string): number {
  const trimmed = optionalEnv(raw);
  if (!trimmed) {
    return fallback;
  }
  const value = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`invalid ${name}: ${raw} (expected a positive integer)`);
  }
  return value;
}

function parseOriginAllowlist(raw: string | undefined): string[] {
  const trimmed = optionalEnv(raw);
  if (!trimmed) {
    return [];
  }
  return trimmed
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export function mcpHttpServerOptionsFromEnv(
  env: Record<string, string | undefined> = process.env,
): ResolvedMcpHttpServerOptions {
  const operatorSettings = mcpOperatorSettingsFromEnv(env);
  assertPolicyReloadCompatibleWithHttp(operatorSettings);
  return {
    addr: optionalEnv(env.PAYBOND_MCP_HTTP_ADDR) ?? DEFAULT_ADDR,
    allowedOrigins: parseOriginAllowlist(env.PAYBOND_MCP_HTTP_ALLOWED_ORIGINS),
    maxBodyBytes: parsePositiveInt(
      env.PAYBOND_MCP_HTTP_MAX_BODY_BYTES,
      DEFAULT_MAX_BODY_BYTES,
      "PAYBOND_MCP_HTTP_MAX_BODY_BYTES",
    ),
    rateLimitPerMinute: parsePositiveInt(
      env.PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE,
      DEFAULT_RATE_LIMIT_PER_MINUTE,
      "PAYBOND_MCP_HTTP_RATE_LIMIT_PER_MINUTE",
    ),
    unauthenticatedRateLimitPerMinute: parsePositiveInt(
      env.PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE,
      DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE,
      "PAYBOND_MCP_HTTP_RATE_LIMIT_UNAUTH_PER_MINUTE",
    ),
    operatorSettings,
  };
}

/** Bounded-memory fixed-window rate limiter. Stale buckets are swept lazily. */
class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, { count: number; windowStartMs: number }>();
  private readonly sweepIntervalMs: number;
  private lastSweepMs = 0;

  constructor(
    private readonly limit: number,
    private readonly windowMs: number = RATE_LIMIT_WINDOW_MS,
  ) {
    this.sweepIntervalMs = windowMs * 5;
  }

  allow(key: string, nowMs: number = Date.now()): boolean {
    this.maybeSweep(nowMs);
    const bucket = this.buckets.get(key);
    if (!bucket || nowMs - bucket.windowStartMs >= this.windowMs) {
      this.buckets.set(key, { count: 1, windowStartMs: nowMs });
      return true;
    }
    if (bucket.count >= this.limit) {
      return false;
    }
    bucket.count += 1;
    return true;
  }

  private maybeSweep(nowMs: number): void {
    if (nowMs - this.lastSweepMs < this.sweepIntervalMs) {
      return;
    }
    this.lastSweepMs = nowMs;
    for (const [key, bucket] of this.buckets) {
      if (nowMs - bucket.windowStartMs >= this.windowMs) {
        this.buckets.delete(key);
      }
    }
  }
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex").slice(0, 16);
}

function firstHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

function clientIp(req: IncomingMessage): string {
  const cfConnectingIp = optionalEnv(firstHeader(req.headers["cf-connecting-ip"]));
  if (cfConnectingIp) {
    return cfConnectingIp;
  }
  const flyClientIp = optionalEnv(firstHeader(req.headers["fly-client-ip"]));
  if (flyClientIp) {
    return flyClientIp;
  }
  return req.socket.remoteAddress ?? "unknown";
}

function extractBearerToken(header: string | undefined): string | null {
  if (!header) {
    return null;
  }
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  const token = match?.[1]?.trim();
  return token && token.length > 0 ? token : null;
}

function looksLikeApiKey(value: string): boolean {
  return API_KEY_PREFIXES.some(
    (prefix) => value.startsWith(prefix) && value.length >= prefix.length + 8,
  );
}

function originAllowed(origin: string | undefined, allowedOrigins: readonly string[]): boolean {
  // Non-browser MCP clients (Cursor, Claude, Codex, curl, MCP Inspector in HTTP
  // mode) do not send an Origin header at all, so requests without one are the
  // expected common case. When an Origin is present, it must be explicitly
  // allowlisted — this endpoint is Bearer-token authenticated, not
  // cookie-authenticated, so it is not meant to be called from arbitrary
  // browser-hosted JavaScript in the first place.
  if (!origin) {
    return true;
  }
  return allowedOrigins.includes(origin);
}

function acceptHeaderCompatible(accept: string | undefined): boolean {
  if (!accept) {
    return true;
  }
  const normalized = accept.toLowerCase();
  return (
    normalized.includes("application/json") ||
    normalized.includes("text/event-stream") ||
    normalized.includes("*/*")
  );
}

type ReadBodyResult = { ok: true; text: string } | { ok: false; reason: "too_large" };

/**
 * Reads the request body, capped at `maxBytes`.
 *
 * When the cap is exceeded we stop *buffering* immediately (bounding memory
 * use) but deliberately keep draining the socket to `end` instead of calling
 * `req.destroy()`. `IncomingMessage#destroy()` tears down the underlying
 * TCP socket shared with the response; if the client is still writing its
 * (oversized) body when that happens, the OS sends a RST instead of letting
 * the in-flight `413` response reach the client, so callers see an opaque
 * connection reset rather than a clean error. Draining first is the standard
 * fix used by body-parsers like `raw-body` for this exact failure mode.
 */
function readBody(req: IncomingMessage, maxBytes: number): Promise<ReadBodyResult> {
  return new Promise((resolve, reject) => {
    let total = 0;
    let tooLarge = false;
    const chunks: Buffer[] = [];
    let settled = false;
    req.on("data", (chunk: Buffer) => {
      if (settled) {
        return;
      }
      total += chunk.length;
      if (total > maxBytes) {
        tooLarge = true;
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (settled) {
        return;
      }
      settled = true;
      if (tooLarge) {
        resolve({ ok: false, reason: "too_large" });
        return;
      }
      resolve({ ok: true, text: Buffer.concat(chunks).toString("utf8") });
    });
    req.on("error", (err) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(err);
    });
  });
}

function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  extraHeaders?: Record<string, string>,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    ...extraHeaders,
  });
  res.end(payload);
}

function logAccess(entry: Record<string, unknown>): void {
  process.stderr.write(`${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`);
}

type RequestContext = {
  allowedOrigins: readonly string[];
  maxBodyBytes: number;
  authLimiter: FixedWindowRateLimiter;
  unauthLimiter: FixedWindowRateLimiter;
  operatorSettings: Omit<PaybondMCPSettings, "apiKey">;
};

async function handleMcpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RequestContext,
): Promise<void> {
  const startedAtMs = Date.now();
  const method = req.method ?? "GET";
  const path = (req.url ?? "/").split("?")[0] || "/";
  const ip = clientIp(req);

  if (path === HEALTHZ_PATH) {
    if (method !== "GET") {
      sendJson(res, 405, { error: "method_not_allowed" }, { allow: "GET" });
      return;
    }
    sendJson(res, 200, { status: "ok", service: "paybond-mcp-http" });
    return;
  }

  if (path !== MCP_PATH) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  if (method !== "POST") {
    // No server-initiated notifications and no sessions are offered, so the
    // optional Streamable HTTP GET (SSE stream) and DELETE (session teardown)
    // methods are not implemented; 405 is the spec-sanctioned response.
    sendJson(res, 405, { error: "method_not_allowed" }, { allow: "POST" });
    return;
  }

  const origin = firstHeader(req.headers.origin);
  if (!originAllowed(origin, ctx.allowedOrigins)) {
    sendJson(res, 403, { error: "origin_not_allowed" });
    logAccess({ path, method, status: 403, ip, reason: "origin", origin });
    return;
  }

  if (!acceptHeaderCompatible(firstHeader(req.headers.accept))) {
    sendJson(res, 406, {
      error: "not_acceptable",
      message: "Accept header must include application/json",
    });
    return;
  }

  const bearer = extractBearerToken(firstHeader(req.headers.authorization));
  if (!bearer || !looksLikeApiKey(bearer)) {
    if (!ctx.unauthLimiter.allow(ip)) {
      sendJson(res, 429, { error: "rate_limited" }, { "retry-after": "60" });
      logAccess({ path, method, status: 429, ip, reason: "unauthenticated_rate_limit" });
      return;
    }
    res.setHeader("www-authenticate", 'Bearer realm="paybond-mcp", error="invalid_token"');
    sendJson(res, 401, {
      error: "unauthorized",
      message:
        "Authorization: Bearer <paybond_rk_..., paybond_sk_..., or paybond_oat_...> is required",
    });
    logAccess({ path, method, status: 401, ip });
    return;
  }

  const tokenHash = hashToken(bearer);
  if (!ctx.authLimiter.allow(tokenHash)) {
    sendJson(res, 429, { error: "rate_limited" }, { "retry-after": "60" });
    logAccess({ path, method, status: 429, ip, tokenHash, reason: "rate_limit" });
    return;
  }

  const bodyResult = await readBody(req, ctx.maxBodyBytes);
  if (!bodyResult.ok) {
    sendJson(res, 413, { error: "payload_too_large" });
    logAccess({ path, method, status: 413, ip, tokenHash });
    return;
  }

  let parsed: unknown;
  try {
    parsed = bodyResult.text.trim() ? JSON.parse(bodyResult.text) : {};
  } catch {
    sendJson(res, 400, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32700, message: "Parse error" },
    });
    logAccess({ path, method, status: 400, ip, tokenHash, reason: "parse_error" });
    return;
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    sendJson(res, 400, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid Request" },
    });
    logAccess({ path, method, status: 400, ip, tokenHash, reason: "invalid_request" });
    return;
  }

  let server: PaybondMCPServer;
  try {
    server = new PaybondMCPServer({ ...ctx.operatorSettings, apiKey: bearer });
  } catch (err) {
    sendJson(res, 401, {
      error: "unauthorized",
      message: err instanceof Error ? err.message : String(err),
    });
    logAccess({ path, method, status: 401, ip, tokenHash, reason: "invalid_key" });
    return;
  }

  const rpcMethod = typeof (parsed as { method?: unknown }).method === "string"
    ? (parsed as { method: string }).method
    : undefined;

  let response: Awaited<ReturnType<PaybondMCPServer["handleMessage"]>>;
  try {
    response = await server.handleMessage(
      parsed as Parameters<PaybondMCPServer["handleMessage"]>[0],
    );
  } catch (err) {
    sendJson(res, 500, {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32000, message: "internal error" },
    });
    logAccess({
      path,
      method,
      status: 500,
      ip,
      tokenHash,
      rpcMethod,
      error: err instanceof Error ? err.message : String(err),
    });
    return;
  }

  if (response === null) {
    // Notification (no `id`): Streamable HTTP requires 202 Accepted, empty body.
    res.writeHead(202);
    res.end();
    logAccess({
      path,
      method,
      status: 202,
      ip,
      tokenHash,
      rpcMethod,
      ms: Date.now() - startedAtMs,
    });
    return;
  }

  sendJson(res, 200, response);
  logAccess({
    path,
    method,
    status: 200,
    ip,
    tokenHash,
    rpcMethod,
    ms: Date.now() - startedAtMs,
  });
}

/**
 * Build a Node `http.Server` request listener for the Streamable HTTP MCP
 * transport. Exposed separately from `main()` so tests and embedders can bind
 * it to an ephemeral port without going through the CLI/env plumbing.
 */
export function createMcpHttpRequestListener(
  options: McpHttpServerOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const operatorSettings = options.operatorSettings ?? mcpOperatorSettingsFromEnv();
  assertPolicyReloadCompatibleWithHttp(operatorSettings);
  const ctx: RequestContext = {
    allowedOrigins: options.allowedOrigins ?? [],
    maxBodyBytes: options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES,
    authLimiter: new FixedWindowRateLimiter(
      options.rateLimitPerMinute ?? DEFAULT_RATE_LIMIT_PER_MINUTE,
    ),
    unauthLimiter: new FixedWindowRateLimiter(
      options.unauthenticatedRateLimitPerMinute ?? DEFAULT_UNAUTHENTICATED_RATE_LIMIT_PER_MINUTE,
    ),
    operatorSettings,
  };

  return (req, res) => {
    handleMcpRequest(req, res, ctx).catch((err: unknown) => {
      if (!res.headersSent) {
        sendJson(res, 500, { error: "internal_error" });
      }
      logAccess({
        path: req.url,
        method: req.method,
        status: 500,
        error: err instanceof Error ? err.message : String(err),
      });
    });
  };
}

function parseAddr(addr: string): { host: string; port: number } {
  const trimmed = addr.trim();
  const bracketMatch = /^\[(.*)\]:(\d+)$/.exec(trimmed);
  if (bracketMatch) {
    const port = Number(bracketMatch[2]);
    return { host: bracketMatch[1] || "::", port };
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error(`invalid address (expected host:port): ${addr}`);
  }
  const host = trimmed.slice(0, lastColon) || "0.0.0.0";
  const port = Number(trimmed.slice(lastColon + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`invalid port in address: ${addr}`);
  }
  return { host, port };
}

function formatError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Start the Streamable HTTP MCP server and keep it running until the process
 * is terminated. Returns the underlying `http.Server` so callers (tests,
 * embedders) can close it; the CLI entrypoint below ignores the return value
 * and lets the process stay alive on the open listening socket.
 */
export function startMcpHttpServer(options: ResolvedMcpHttpServerOptions): Server {
  const listener = createMcpHttpRequestListener(options);
  const { host, port } = parseAddr(options.addr);
  const server = createServer(listener);
  server.listen(port, host);
  return server;
}

export function main(argv: string[] = process.argv.slice(2)): number {
  if (argv.includes("--help")) {
    process.stderr.write(
      "Usage: paybond-mcp-http-server\n\n" +
        "Runs the tenant-bound Paybond MCP server over Streamable HTTP (POST /mcp).\n" +
        "Each request supplies its own PAYBOND_API_KEY as `Authorization: Bearer <key>`.\n" +
        "See docs/kit/mcp-server.md for the full environment variable reference.\n",
    );
    return 0;
  }
  if (argv.length > 0) {
    process.stderr.write("paybond-mcp-http-server does not accept positional arguments\n");
    return 1;
  }
  let options: ResolvedMcpHttpServerOptions;
  try {
    options = mcpHttpServerOptionsFromEnv();
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`);
    return 1;
  }
  const { host, port } = parseAddr(options.addr);
  const server = startMcpHttpServer(options);
  server.on("error", (err) => {
    process.stderr.write(`paybond-mcp-http-server: ${formatError(err)}\n`);
    process.exitCode = 1;
  });
  server.on("listening", () => {
    process.stderr.write(
      `Paybond MCP Streamable HTTP server listening on http://${host}:${port}${MCP_PATH} ` +
        `(health check: ${HEALTHZ_PATH})\n`,
    );
  });
  return 0;
}
