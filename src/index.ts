/**
 * Paybond Kit — TypeScript Harbor client with tenant binding, retries, optional upstream JWT,
 * and gateway service-account token exchange (`POST /v1/auth/harbor-access`).
 */

import { buildSignedCreateIntentBody, type BuildSignedCreateIntentParams } from "./principal-intent.js";
import { signPayeeEvidenceBinding, type SignPayeeEvidenceParams } from "./payee-evidence.js";

export type VerifyCapabilityResult = {
  allow: boolean;
  auditId: string;
  tenant: string;
  intentId: string;
  code?: string;
  message?: string;
};

export type SubmitEvidenceResult = {
  intentId: string;
  tenant: string;
  state: string;
  predicatePassed?: boolean;
};

/** Async supplier for short-lived Harbor JWTs minted by the Paybond gateway. */
export type HarborBearerSupplier = () => Promise<string | null | undefined>;

/**
 * Structured HTTP failure from Harbor with operator-facing diagnostics.
 */
export class HarborHttpError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;

  constructor(message: string, init: { statusCode: number; url: string; bodyText: string }) {
    super(message);
    this.name = "HarborHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
  }
}

/**
 * Gateway rejected the service-account exchange or returned an unusable harbor-access payload.
 */
export class GatewayAuthError extends Error {
  readonly statusCode: number | undefined;
  readonly bodyText: string | undefined;

  constructor(
    message: string,
    init?: { statusCode?: number; bodyText?: string },
  ) {
    super(message);
    this.name = "GatewayAuthError";
    this.statusCode = init?.statusCode;
    this.bodyText = init?.bodyText;
  }
}

function normalizeBase(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

function backoffMs(attempt: number): number {
  const base = 200 * 2 ** attempt;
  const jitter = Math.random() * 100;
  return Math.min(base + jitter, 5000);
}

function parseRetryAfterSeconds(v: string | null): number | null {
  if (!v) return null;
  const n = Number.parseFloat(v.trim());
  if (!Number.isFinite(n)) return null;
  return Math.min(n, 30);
}

const DEFAULT_HARBOR_ACCESS_PATH = "/v1/auth/harbor-access";

/**
 * Exchanges a `paybond_sk_` API key for short-lived Harbor JWTs and caches tenant realm from the
 * gateway response (no separate tenant env var for the default path).
 */
export class GatewayHarborTokenProvider {
  private readonly gatewayBase: string;
  private readonly apiKey: string;
  private readonly path: string;
  private readonly skewMs: number;
  private readonly clock: () => number;
  private token: string | null = null;
  private tenantIdValue: string | null = null;
  private notAfterMonotonic = 0;
  private refreshTail: Promise<void> = Promise.resolve();

  constructor(init: {
    gatewayBaseUrl: string;
    apiKey: string;
    harborAccessPath?: string;
    clockSkewSeconds?: number;
    /** Injectable monotonic clock (milliseconds) for tests. */
    clock?: () => number;
  }) {
    this.gatewayBase = normalizeBase(init.gatewayBaseUrl);
    this.apiKey = init.apiKey.trim();
    const rawPath = (init.harborAccessPath ?? DEFAULT_HARBOR_ACCESS_PATH).trim();
    this.path = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;
    this.skewMs = Math.max(0, (init.clockSkewSeconds ?? 90) * 1000);
    this.clock = init.clock ?? (() => performance.now());
  }

  get tenantId(): string | null {
    return this.tenantIdValue;
  }

  /**
   * First exchange; returns tenant realm echoed by the gateway.
   */
  async ensureInitial(): Promise<string> {
    await this.refresh(true);
    if (!this.tenantIdValue) {
      throw new GatewayAuthError(
        "harbor-access response missing tenant_id; upgrade gateway (PAYBOND-V1-008)",
      );
    }
    return this.tenantIdValue;
  }

  /** Return a valid Harbor JWT, refreshing when near expiry. */
  async bearer(): Promise<string> {
    await this.refresh(false);
    if (!this.token) {
      throw new GatewayAuthError("harbor-access did not return access_token");
    }
    return this.token;
  }

  /** Force rotation (credential rotation drills). */
  async forceRotate(): Promise<void> {
    await this.refresh(true);
  }

  private async refresh(force: boolean): Promise<void> {
    const job = this.refreshTail.then(() => this.refreshInner(force));
    this.refreshTail = job.then(
      () => undefined,
      () => undefined,
    );
    await job;
  }

  private async refreshInner(force: boolean): Promise<void> {
    const now = this.clock();
    if (!force && this.token && now < this.notAfterMonotonic) {
      return;
    }
    const url = `${this.gatewayBase}${this.path}`;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        accept: "application/json",
      },
    });
    const text = await res.text();
    if (!res.ok) {
      throw new GatewayAuthError(`harbor-access HTTP ${res.status}`, {
        statusCode: res.status,
        bodyText: text,
      });
    }
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new GatewayAuthError("harbor-access response was not JSON", { bodyText: text });
    }
    const access = String(body.access_token ?? "").trim();
    if (!access) {
      throw new GatewayAuthError("harbor-access JSON missing access_token", { bodyText: text });
    }
    const expIn = Number(body.expires_in ?? 0);
    if (!Number.isFinite(expIn) || expIn <= 0) {
      throw new GatewayAuthError("harbor-access JSON missing expires_in", { bodyText: text });
    }
    const tidRaw = body.tenant_id;
    if (typeof tidRaw === "string" && tidRaw.trim()) {
      this.tenantIdValue = tidRaw.trim();
    }
    if (!this.tenantIdValue) {
      throw new GatewayAuthError(
        "harbor-access response missing tenant_id; upgrade gateway (PAYBOND-V1-008)",
        { bodyText: text },
      );
    }
    this.token = access;
    this.notAfterMonotonic = now + Math.max(1000, expIn * 1000 - this.skewMs);
  }
}

/**
 * Tenant-scoped Harbor binding for one funded intent and one Biscuit capability token.
 */
export class PaybondCapabilityBinding {
  constructor(
    public readonly harbor: HarborClient,
    public readonly intentId: string,
    public readonly capabilityToken: string,
  ) {}
}

export type ServiceAccountHarborSessionInit = {
  gatewayBaseUrl: string;
  apiKey: string;
  harborBaseUrl: string;
  harborAccessPath?: string;
  clockSkewSeconds?: number;
  maxRetries?: number;
};

/**
 * Harbor client plus gateway token lifecycle for one service account.
 */
export class ServiceAccountHarborSession {
  readonly harbor: HarborClient;
  private readonly tokens: GatewayHarborTokenProvider;

  private constructor(harbor: HarborClient, tokens: GatewayHarborTokenProvider) {
    this.harbor = harbor;
    this.tokens = tokens;
  }

  /**
   * Build a tenant-bound {@link HarborClient} using gateway-derived tenant id and JWT supplier.
   */
  static async open(init: ServiceAccountHarborSessionInit): Promise<ServiceAccountHarborSession> {
    const tokens = new GatewayHarborTokenProvider({
      gatewayBaseUrl: init.gatewayBaseUrl,
      apiKey: init.apiKey,
      harborAccessPath: init.harborAccessPath,
      clockSkewSeconds: init.clockSkewSeconds,
    });
    const tenant = await tokens.ensureInitial();
    const harbor = new HarborClient(init.harborBaseUrl, tenant, {
      harborBearerSupplier: () => tokens.bearer(),
      maxRetries: init.maxRetries ?? 3,
    });
    return new ServiceAccountHarborSession(harbor, tokens);
  }

  async rotateHarborToken(): Promise<void> {
    await this.tokens.forceRotate();
  }

  /** Reserved for future HTTP client cleanup; safe to call after work completes. */
  async aclose(): Promise<void> {
    await Promise.resolve();
  }
}

type HarborClientOptions = {
  harborBearerSupplier?: HarborBearerSupplier;
  staticHarborBearerToken?: string;
  maxRetries?: number;
};

/**
 * HTTP client for Harbor: capability verify, intents, evidence, and tenant-scoped ledger reads
 * (`GET /ledger/v1/*`, PAYBOND-007).
 */
export class HarborClient {
  private readonly base: string;
  /** Tenant realm from the gateway exchange; sent as `x-tenant-id` on every Harbor request. */
  readonly tenantId: string;
  private readonly bearerSupplier?: HarborBearerSupplier;
  private readonly staticBearer?: string;
  private readonly maxRetries: number;

  /**
   * @param harborBase - Harbor origin, e.g. `https://harbor.example.com` (trailing slash optional)
   * @param tenantId - Tenant realm; sent as `x-tenant-id` on every request
   */
  constructor(harborBase: string, tenantId: string, options?: HarborClientOptions) {
    if (options?.harborBearerSupplier && options?.staticHarborBearerToken) {
      throw new Error("pass at most one of harborBearerSupplier or staticHarborBearerToken");
    }
    this.base = normalizeBase(harborBase) + "/";
    this.tenantId = tenantId.trim();
    this.bearerSupplier = options?.harborBearerSupplier;
    this.staticBearer = options?.staticHarborBearerToken?.trim();
    this.maxRetries = Math.max(1, options?.maxRetries ?? 3);
  }

  private async authHeader(): Promise<Record<string, string>> {
    if (this.staticBearer) {
      return { authorization: `Bearer ${this.staticBearer}` };
    }
    if (this.bearerSupplier) {
      const tok = await this.bearerSupplier();
      if (tok && String(tok).trim()) {
        return { authorization: `Bearer ${String(tok).trim()}` };
      }
    }
    return {};
  }

  /**
   * Ledger JSON responses include `tenant_id`; reject if it drifts from the bound client tenant.
   */
  private assertLedgerTenant(body: Record<string, unknown>, url: string): void {
    const tid = String(body.tenant_id ?? "");
    if (tid !== this.tenantId) {
      throw new Error(
        `ledger tenant mismatch: client=${this.tenantId} harbor=${tid} url=${url}`,
      );
    }
  }

  /** GET with the same 429/5xx retry behavior as {@link HarborClient.fetchWithRetries}. */
  private async fetchGetWithRetries(url: string): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers = new Headers({
          accept: "application/json",
          "x-tenant-id": this.tenantId,
        });
        const auth = await this.authHeader();
        for (const [k, v] of Object.entries(auth)) {
          headers.set(k, v);
        }
        res = await fetch(url, { method: "GET", headers });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  private async fetchWithRetries(
    url: string,
    init: RequestInit,
    { retryBody }: { retryBody: unknown },
  ): Promise<Response> {
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        const headers = new Headers(init.headers);
        const auth = await this.authHeader();
        for (const [k, v] of Object.entries(auth)) {
          headers.set(k, v);
        }
        res = await fetch(url, { ...init, headers });
      } catch (e) {
        lastErr = e;
        if (attempt + 1 >= this.maxRetries) throw e;
        await new Promise((r) => setTimeout(r, backoffMs(attempt)));
        continue;
      }
      if ([429, 500, 502, 503, 504].includes(res.status)) {
        if (attempt + 1 >= this.maxRetries) {
          return res;
        }
        const raSec = parseRetryAfterSeconds(res.headers.get("retry-after"));
        const delayMs = raSec != null ? raSec * 1000 : backoffMs(attempt);
        await new Promise((r) => setTimeout(r, delayMs));
        init = {
          ...init,
          body: JSON.stringify(retryBody),
        };
        continue;
      }
      return res;
    }
    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }

  /**
   * POST `/verify` with a Biscuit capability token (PAYBOND-006).
   *
   * @throws HarborHttpError when HTTP fails
   * @throws Error when Harbor echoes a different tenant / intent than requested
   */
  async verifyCapability(input: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<VerifyCapabilityResult> {
    const url = `${this.base}verify`;
    const payload = {
      intent_id: input.intentId,
      token: input.token,
      operation: input.operation,
      requested_spend_cents: input.requestedSpendCents ?? 0,
    };
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-tenant-id": this.tenantId,
        },
        body: JSON.stringify(payload),
      },
      { retryBody: payload },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor verify HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as {
      allow: boolean;
      audit_id: string;
      tenant: string;
      intent_id: string;
      code?: string;
      message?: string;
    };
    if (body.tenant !== this.tenantId) {
      throw new Error(
        `verify tenant mismatch: client=${this.tenantId} harbor=${body.tenant}`,
      );
    }
    if (body.intent_id !== input.intentId) {
      throw new Error(
        `verify intent mismatch: requested=${input.intentId} harbor=${body.intent_id}`,
      );
    }
    return {
      allow: body.allow,
      auditId: body.audit_id,
      tenant: body.tenant,
      intentId: body.intent_id,
      code: body.code,
      message: body.message,
    };
  }

  /**
   * POST `/intents` with a principal-signed `CreateIntentRequest` JSON body.
   *
   * @throws HarborHttpError when HTTP fails
   */
  async createIntent(
    body: Record<string, unknown>,
    options?: { idempotencyKey?: string },
  ): Promise<Record<string, unknown>> {
    const url = `${this.base}intents`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-tenant-id": this.tenantId,
    };
    if (options?.idempotencyKey?.trim()) {
      headers["idempotency-key"] = options.idempotencyKey.trim();
    }
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      },
      { retryBody: body },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor create intent HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return JSON.parse(text) as Record<string, unknown>;
  }

  /**
   * POST `/intents/{intentId}/evidence` with a signed evidence JSON body.
   *
   * @param idempotencyKey - Optional Harbor idempotency header for safe retries
   */
  async submitEvidence(
    intentId: string,
    evidenceBody: Record<string, unknown>,
    options?: { idempotencyKey?: string },
  ): Promise<SubmitEvidenceResult> {
    const url = `${this.base}intents/${intentId}/evidence`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-tenant-id": this.tenantId,
    };
    if (options?.idempotencyKey?.trim()) {
      headers["idempotency-key"] = options.idempotencyKey.trim();
    }
    const res = await this.fetchWithRetries(
      url,
      {
        method: "POST",
        headers,
        body: JSON.stringify(evidenceBody),
      },
      { retryBody: evidenceBody },
    );
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor evidence HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as {
      intent_id: string;
      tenant: string;
      state: string;
      predicate_passed?: boolean;
    };
    return {
      intentId: body.intent_id,
      tenant: body.tenant,
      state: body.state,
      predicatePassed: body.predicate_passed,
    };
  }

  /**
   * `GET /ledger/v1/tip` — latest sequence and entry commitment for the authenticated tenant.
   *
   * @throws HarborHttpError on HTTP failure
   * @throws Error when JSON `tenant_id` does not match the bound client tenant
   */
  async getLedgerTip(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/tip`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger tip HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/authority` — hex-encoded Ed25519 verifying key for this Harbor deployment.
   */
  async getLedgerAuthority(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/authority`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger authority HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/events` — paginated append-only history; `afterSeq` is an exclusive cursor.
   * `limit` is clamped to 1…256 to match Harbor.
   */
  async getLedgerEvents(options?: { afterSeq?: number; limit?: number }): Promise<Record<string, unknown>> {
    const afterSeq = Math.max(0, Math.floor(options?.afterSeq ?? 0));
    const rawLimit = options?.limit ?? 64;
    const limit = Math.max(1, Math.min(Math.floor(rawLimit), 256));
    const qs = new URLSearchParams({
      after_seq: String(afterSeq),
      limit: String(limit),
    });
    const url = `${this.base}ledger/v1/events?${qs.toString()}`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger events HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }

  /**
   * `GET /ledger/v1/merkle/latest` — last Merkle checkpoint envelope for the tenant (checkpoint may be null).
   */
  async getLedgerMerkleLatest(): Promise<Record<string, unknown>> {
    const url = `${this.base}ledger/v1/merkle/latest`;
    const res = await this.fetchGetWithRetries(url);
    const text = await res.text();
    if (!res.ok) {
      throw new HarborHttpError(`Harbor ledger merkle HTTP ${res.status}: ${text}`, {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const body = JSON.parse(text) as Record<string, unknown>;
    this.assertLedgerTenant(body, url);
    return body;
  }
}

/** Parameters for {@link PaybondIntents.create} (tenant is taken from the bound Harbor client). */
export type PaybondCreateIntentParams = Omit<BuildSignedCreateIntentParams, "tenantId" | "intentId"> & {
  intentId?: string;
};

/** Parameters for {@link PaybondIntents.submitEvidence} (tenant is taken from the bound Harbor client). */
export type PaybondSubmitEvidenceParams = Omit<SignPayeeEvidenceParams, "tenantId">;

/**
 * Ergonomic intent helpers: principal-signed intent create and payee-signed evidence.
 */
export class PaybondIntents {
  constructor(private readonly harbor: HarborClient) {}

  /**
   * Build a principal-signed `POST /intents` body and submit it. `principalSigningSeed` must be 32 bytes.
   */
  async create(
    params: PaybondCreateIntentParams & { idempotencyKey?: string },
  ): Promise<Record<string, unknown>> {
    const { idempotencyKey, intentId: maybeIntentId, ...fields } = params;
    const intentId = maybeIntentId ?? globalThis.crypto.randomUUID();
    const body = buildSignedCreateIntentBody({
      tenantId: this.harbor.tenantId,
      intentId,
      ...fields,
    });
    return this.harbor.createIntent(body, { idempotencyKey });
  }

  /**
   * Sign payee evidence and POST it. `payeeSigningSeed` must be 32 bytes.
   */
  async submitEvidence(
    params: PaybondSubmitEvidenceParams & { idempotencyKey?: string },
  ): Promise<SubmitEvidenceResult> {
    const { idempotencyKey, ...rest } = params;
    const wire = signPayeeEvidenceBinding({
      tenantId: this.harbor.tenantId,
      ...rest,
    });
    return this.harbor.submitEvidence(rest.intentId, wire, { idempotencyKey });
  }
}

/**
 * High-level Kit entrypoint: same session lifecycle as {@link ServiceAccountHarborSession}, plus {@link PaybondIntents}.
 */
export class Paybond {
  readonly harbor: HarborClient;
  readonly intents: PaybondIntents;
  private readonly session: ServiceAccountHarborSession;

  private constructor(session: ServiceAccountHarborSession) {
    this.session = session;
    this.harbor = session.harbor;
    this.intents = new PaybondIntents(session.harbor);
  }

  /** Open a tenant-bound session via gateway `harbor-access` exchange. */
  static async open(init: ServiceAccountHarborSessionInit): Promise<Paybond> {
    const session = await ServiceAccountHarborSession.open(init);
    return new Paybond(session);
  }

  async rotateHarborToken(): Promise<void> {
    await this.session.rotateHarborToken();
  }

  /** Release HTTP resources (Harbor client + gateway token provider). */
  async aclose(): Promise<void> {
    await this.session.aclose();
  }
}

export { normalizeJson, jsonValueDigest } from "./json-digest.js";
export {
  buildSignedCreateIntentBody,
  intentCreationSignBytesRaw,
  type BuildSignedCreateIntentParams,
} from "./principal-intent.js";
export { artifactsDigest, signPayeeEvidenceBinding, type SignPayeeEvidenceParams } from "./payee-evidence.js";
