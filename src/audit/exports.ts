import {
  parseAuditExportJobGet,
  parseAuditExportList,
  type AuditExportCreateFilter,
  type AuditExportJobGetResponse,
  type AuditExportListPage,
  type AuditVerifyResult,
} from "./wire.js";
import { auditVerifyResult, verifyAuditBundleLocal } from "./verify.js";
import process from "node:process";

export type AuditExportsGateway = {
  getJson(path: string): Promise<Record<string, unknown>>;
  postJson?(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>>;
  deleteJson?(path: string): Promise<Record<string, unknown>>;
};

export type GatewayAuditExportsClientOptions = {
  staticGatewayBearerToken: string;
  maxRetries?: number;
};

function normalizeBase(url: string): string {
  return url.replace(/\/+$/, "");
}

function backoffMs(attempt: number): number {
  return Math.min(1000 * 2 ** attempt, 8000);
}

function parseRetryAfterSeconds(value: string | null): number | null {
  if (!value?.trim()) {
    return null;
  }
  const seconds = Number.parseInt(value.trim(), 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Gateway-backed compliance audit export client for `GET /v1/compliance/audit-exports`.
 */
export class GatewayAuditExportsClient implements AuditExportsGateway {
  private readonly base: string;
  private readonly bearerToken: string;
  private readonly maxRetries: number;

  constructor(
    gatewayBaseUrl: string,
    private readonly tenantId: string,
    options: GatewayAuditExportsClientOptions,
  ) {
    this.base = `${normalizeBase(gatewayBaseUrl)}/`;
    this.bearerToken = options.staticGatewayBearerToken.trim();
    this.maxRetries = Math.max(1, options.maxRetries ?? 3);
  }

  async getJson(path: string): Promise<Record<string, unknown>> {
    return this.requestJSON("GET", path);
  }

  async postJson(path: string, body: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.requestJSON("POST", path, body);
  }

  async deleteJson(path: string): Promise<Record<string, unknown>> {
    return this.requestJSON("DELETE", path);
  }

  private async requestJSON(
    method: "GET" | "POST" | "DELETE",
    path: string,
    body?: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    const url = `${this.base}${path.replace(/^\//, "")}`;
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers: Record<string, string> = {
          accept: "application/json",
          authorization: `Bearer ${this.bearerToken}`,
        };
        const init: RequestInit = { method, headers };
        if (method === "POST") {
          headers["content-type"] = "application/json";
          init.body = JSON.stringify(body ?? {});
        }
        res = await fetch(url, init);
      } catch (err) {
        lastErr = err;
        if (attempt + 1 >= this.maxRetries) {
          throw err;
        }
        await delay(backoffMs(attempt));
        continue;
      }

      if ([429, 500, 502, 503, 504].includes(res.status) && attempt + 1 < this.maxRetries) {
        const retryAfter = parseRetryAfterSeconds(res.headers.get("retry-after"));
        await delay(retryAfter != null ? retryAfter * 1000 : backoffMs(attempt));
        continue;
      }

      const text = await res.text();
      if (!res.ok) {
        throw new Error(`Gateway ${method} ${path} HTTP ${res.status}: ${text}`);
      }
      if (!text.trim()) {
        return {};
      }
      const parsed = JSON.parse(text) as unknown;
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error(`Gateway ${method} ${path} returned non-object JSON`);
      }
      return parsed as Record<string, unknown>;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }
}

export type PaybondAuditExportsListParams = {
  limit?: number;
  cursor?: string;
};

export type PaybondAuditExportsGetParams = {
  issueDownload?: boolean;
};

export type PaybondAuditExportsCreateParams = {
  filter: AuditExportCreateFilter;
  /** Defaults to `standard` when omitted. */
  disclosureTier?: "standard" | "extended";
  /** Bundle retention in hours (gateway default 168, max 720). */
  retentionHours?: number;
};

function buildAuditExportCreateBody(params: PaybondAuditExportsCreateParams): Record<string, unknown> {
  const filter: Record<string, unknown> = {};
  const f = params.filter;
  if (f.time_start?.trim()) {
    filter.time_start = f.time_start.trim();
  }
  if (f.time_end?.trim()) {
    filter.time_end = f.time_end.trim();
  }
  if (f.intent_id?.trim()) {
    filter.intent_id = f.intent_id.trim();
  }
  if (f.case_id?.trim()) {
    filter.case_id = f.case_id.trim();
  }
  if (f.operator_did?.trim()) {
    filter.operator_did = f.operator_did.trim();
  }
  if (f.includes && f.includes.length > 0) {
    filter.includes = [...f.includes];
  }
  const body: Record<string, unknown> = {
    filter,
    disclosure_tier: params.disclosureTier ?? "standard",
  };
  if (params.retentionHours != null && params.retentionHours > 0) {
    body.retention_hours = params.retentionHours;
  }
  return body;
}

/**
 * SDK surface for compliance audit export jobs and local bundle verification.
 */
export class PaybondAuditExports {
  constructor(private readonly gateway: AuditExportsGateway) {}

  /** Wrap an existing gateway client (CLI, tests, or custom transport). */
  static fromGateway(gateway: AuditExportsGateway): PaybondAuditExports {
    return new PaybondAuditExports(gateway);
  }

  /** Open a tenant-bound audit exports client from gateway credentials. */
  static open(
    gatewayBaseUrl: string,
    tenantId: string,
    options: GatewayAuditExportsClientOptions,
  ): PaybondAuditExports {
    return new PaybondAuditExports(new GatewayAuditExportsClient(gatewayBaseUrl, tenantId, options));
  }

  async list(params?: PaybondAuditExportsListParams): Promise<AuditExportListPage> {
    const search = new URLSearchParams();
    const limit = params?.limit ?? 50;
    search.set("limit", String(Math.max(1, Math.min(limit, 200))));
    if (params?.cursor?.trim()) {
      search.set("cursor", params.cursor.trim());
    }
    const body = await this.gateway.getJson(`/v1/compliance/audit-exports?${search.toString()}`);
    return parseAuditExportList(body);
  }

  async get(jobId: string, params?: PaybondAuditExportsGetParams): Promise<AuditExportJobGetResponse> {
    const query = params?.issueDownload ? "?issue_download=1" : "";
    const body = await this.gateway.getJson(
      `/v1/compliance/audit-exports/${encodeURIComponent(jobId)}${query}`,
    );
    return parseAuditExportJobGet(body);
  }

  /**
   * Create a compliance audit export job (`POST /v1/compliance/audit-exports`).
   * Tenant scope comes from the API key — never pass a tenant id.
   */
  async create(params: PaybondAuditExportsCreateParams): Promise<AuditExportJobGetResponse> {
    if (!this.gateway.postJson) {
      throw new Error("audit export create is not supported by this gateway adapter");
    }
    const body = await this.gateway.postJson(
      "/v1/compliance/audit-exports",
      buildAuditExportCreateBody(params),
    );
    return parseAuditExportJobGet(body);
  }

  async delete(jobId: string): Promise<{ job_id: string; deleted: true }> {
    if (!this.gateway.deleteJson) {
      throw new Error("audit export delete is not supported by this gateway adapter");
    }
    await this.gateway.deleteJson(`/v1/compliance/audit-exports/${encodeURIComponent(jobId)}`);
    return { job_id: jobId, deleted: true };
  }

  /**
   * Verify a signed audit export manifest object or a local bundle path.
   * Bundle verification requires filesystem access; use SDK/CLI rather than MCP.
   */
  async verify(
    manifestOrPath: Record<string, unknown> | string,
    options?: { cwd?: string },
  ): Promise<AuditVerifyResult> {
    if (typeof manifestOrPath === "string") {
      return verifyAuditBundleLocal(manifestOrPath, options?.cwd ?? process.cwd());
    }
    return auditVerifyResult(manifestOrPath);
  }
}

/** Namespace wrapper attached to {@link Paybond} as `paybond.audit.exports`. */
export class PaybondAudit {
  readonly exports: PaybondAuditExports;

  constructor(exports: PaybondAuditExports) {
    this.exports = exports;
  }
}
