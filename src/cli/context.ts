import { resolveApiKeyWithMeta } from "./credentials.js";
import { requireSecureGatewayUrl } from "../gateway-url.js";
import {
  CliError,
  exitCodeForHttpStatus,
  type CliDependencies,
  type CommandResult,
  type GlobalOptions,
  type Writable,
} from "./types.js";

export type GatewayJson = Record<string, unknown>;

export type GatewayClient = {
  getJson(path: string): Promise<GatewayJson>;
  postJson(path: string, body?: GatewayJson): Promise<GatewayJson>;
  deleteJson(path: string): Promise<GatewayJson>;
};

export function gatewayUrl(base: string, path: string): string {
  return `${requireSecureGatewayUrl(base)}${path.startsWith("/") ? path : `/${path}`}`;
}

function parseGatewayErrorBody(body: GatewayJson, status: number): CliError {
  const nested = body.error;
  const gatewayCode =
    nested && typeof nested === "object" && !Array.isArray(nested)
      ? String((nested as GatewayJson).code ?? "")
      : String(body.code ?? "");
  const gatewayMessage =
    nested && typeof nested === "object" && !Array.isArray(nested)
      ? String((nested as GatewayJson).message ?? "")
      : String(body.message ?? body.error_description ?? "gateway request failed");
  const mapped = exitCodeForHttpStatus(status);
  return new CliError(gatewayMessage || `Gateway HTTP ${status}`, {
    category: mapped.category,
    code: gatewayCode || `cli.gateway.http_${status}`,
    exitCode: mapped.exitCode,
    details: {
      gateway_status: status,
      gateway_code: gatewayCode || undefined,
    },
  });
}

async function parseJsonResponse(response: Response): Promise<GatewayJson> {
  const text = await response.text();
  if (!text.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as GatewayJson;
    }
  } catch {
    // fall through
  }
  throw new CliError(`Gateway returned non-JSON response (${response.status}).`, {
    category: "gateway",
    code: "cli.gateway.non_json",
    exitCode: 5,
    details: { gateway_status: response.status },
  });
}

export function createGatewayClient(
  globals: GlobalOptions,
  apiKey: string,
  fetchFn: typeof fetch,
  extraHeaders: Record<string, string> = {},
): GatewayClient {
  const headers = {
    authorization: `Bearer ${apiKey}`,
    "content-type": "application/json",
    "x-request-id": globals.requestId,
    ...extraHeaders,
  };
  async function request(method: string, path: string, body?: GatewayJson): Promise<GatewayJson> {
    let response: Response;
    try {
      response = await fetchFn(gatewayUrl(globals.gateway, path), {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch (err) {
      throw new CliError(err instanceof Error ? err.message : String(err), {
        category: "network",
        code: "cli.network.request_failed",
        exitCode: 5,
      });
    }
    const parsed = await parseJsonResponse(response);
    if (!response.ok) {
      throw parseGatewayErrorBody(parsed, response.status);
    }
    return parsed;
  }
  return {
    getJson: (path) => request("GET", path),
    postJson: (path, body) => request("POST", path, body),
    deleteJson: (path) => request("DELETE", path),
  };
}

export type CliContext = {
  globals: GlobalOptions;
  cwd: string;
  stdout: Writable;
  stderr: Writable;
  fetch: typeof fetch;
  deps: CliDependencies;
  gateway?: GatewayClient;
};

export async function withGateway(
  ctx: CliContext,
  handler: (gateway: GatewayClient, apiKey: string) => Promise<CommandResult>,
  extraHeaders: Record<string, string> = {},
): Promise<CommandResult> {
  const resolved = await resolveApiKeyWithMeta(ctx.globals, ctx.cwd);
  const gateway = createGatewayClient(ctx.globals, resolved.apiKey, ctx.fetch, extraHeaders);
  const result = await handler(gateway, resolved.apiKey);
  const warnings = [...(result.warnings ?? []), ...resolved.warnings];
  return warnings.length ? { ...result, warnings } : result;
}

export function requireConfirmation(globals: GlobalOptions, action: string): void {
  if (!globals.yes) {
    throw new CliError(`confirmation required; re-run with --yes to ${action}`, {
      category: "confirmation_required",
      code: "cli.confirmation.required",
      exitCode: 4,
    });
  }
}

export function commandPath(parts: string[]): string {
  return parts.join(" ");
}

declare const process: {
  cwd(): string;
  stdout: Writable;
  stderr: Writable;
};

export function createContext(globals: GlobalOptions, deps: CliDependencies = {}): CliContext {
  return {
    globals,
    cwd: deps.cwd ?? process.cwd(),
    stdout: deps.stdout ?? process.stdout,
    stderr: deps.stderr ?? process.stderr,
    fetch: deps.fetch ?? fetch,
    deps,
  };
}
