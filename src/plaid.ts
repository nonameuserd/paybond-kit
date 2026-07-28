/**
 * Operator/backend-only Plaid Auth bank helpers. **Not for agents.**
 *
 * Plaid Auth is a tenant-scoped *bank-verification input* to the existing
 * `stripe_ach_debit` settlement rail. Stripe moves the money and Harbor controls
 * funding; Plaid never becomes a settlement rail here. See
 * `docs/operations/plaid-account-verification-setup.md` and the Python twin at
 * `kit/python/src/paybond_kit/plaid.py`.
 *
 * Boundary this module deliberately preserves:
 *
 * - **Operators link and fund. Agents spend only on already funded intents.**
 *   These helpers are backend/service code you call from your own trusted server
 *   with an operator or service-account credential — never from agent
 *   middleware, an MCP tool, an agent template, or anything reachable by
 *   model-authored input.
 * - Nothing here is re-exported from `@paybond/kit/agent`, registered as an MCP
 *   tool, or wired into the agent tool registry. `tests/plaid.test.ts` asserts
 *   that boundary so it cannot regress silently.
 * - There is no Link flow in Kit. This module never accepts or emits
 *   `link_token`, `public_token`, `access_token`, Stripe processor tokens
 *   (`btok_`/`processor-`), Plaid Identity details, or raw balances. Link and
 *   token exchange happen server-side in the Gateway only.
 * - Every call derives tenant scope from the authenticated credential via
 *   `GET /v1/auth/principal`. No helper accepts a caller-supplied tenant ID, and
 *   the Gateway independently re-derives tenant and role from the bearer token,
 *   so a cross-tenant bank or intent is rejected server-side (404/403) even if a
 *   caller guesses an ID.
 *
 * Typical backend use:
 *
 * ```ts
 * import { fundAchWithPlaidBank, listPlaidBanks } from "@paybond/kit";
 *
 * const inventory = await listPlaidBanks({ apiKey: OPERATOR_API_KEY, readyOnly: true });
 * const bank = inventory.bankAccounts[0]!;
 * const result = await fundAchWithPlaidBank({
 *   intentId,
 *   plaidBankAccountId: bank.id,
 *   apiKey: OPERATOR_API_KEY,
 * });
 * ```
 *
 * Readiness reason codes are the stable strings shared by Gateway, Admin
 * console, and CLI (`go/gateway/internal/rails/plaid/reasons.go`).
 */

import { fetchWithGatewayRetries } from "./gateway-retry.js";
import { requireSecureGatewayUrl } from "./gateway-url.js";

const DEFAULT_PLAID_PRINCIPAL_PATH = "/v1/auth/principal";
const BANK_ACCOUNTS_PATH = "v1/admin/plaid/bank-accounts";

/** Gateway origin used when a caller does not pass one explicitly. */
export const DEFAULT_PAYBOND_PLAID_GATEWAY_BASE_URL = "https://api.paybond.ai";

/** Deployment environment an operator credential is bound to. */
export type PlaidPaybondEnvironment = "live" | "sandbox";

/**
 * Stable readiness / fund-block reason codes shared with the Gateway, Admin
 * console, and `paybond plaid` CLI. Prefer these over free-form messages.
 */
export const PLAID_READINESS_REASONS = [
  "ready",
  "pending_automatic_verification",
  "attach_pending",
  "attach_retryable",
  "attach_failed",
  "relink_required",
  "revoked",
  "verification_expired",
  "error",
  "not_ready",
  "risk_check_required",
  "risk_check_failed",
  "feature_disabled",
  "production_not_allowlisted",
  "plaid_bank_not_found",
  "plaid_bank_not_ready",
  "plaid_bank_relink_required",
  "stripe_bank_token_pi_not_enabled",
] as const;

export type PlaidReadinessReason = (typeof PLAID_READINESS_REASONS)[number];

/** Too generic to identify a Plaid failure inside free-form error prose. */
const GENERIC_REASON_CODES = new Set<string>(["ready", "error", "not_ready"]);

const READINESS_MESSAGES: Readonly<Record<string, string>> = {
  ready: "Bank is ready for ACH debit.",
  pending_automatic_verification:
    "Pending micro-deposit verification; ACH debit is blocked until Plaid verifies.",
  attach_pending: "Stripe attach is in progress; refresh shortly.",
  attach_retryable: "Stripe attach incomplete; retry attach or refresh.",
  attach_failed: "Stripe attach failed; relink the bank or use Financial Connections.",
  relink_required: "Bank login required; use Relink (Plaid Link update mode).",
  plaid_bank_relink_required: "Bank login required; use Relink (Plaid Link update mode).",
  revoked: "Revoked; link a new bank or use Financial Connections.",
  verification_expired: "Verification expired; relink required.",
  error: "Bank link error; relink or use Financial Connections.",
  risk_check_required: "Additional risk checks are required before ACH debit.",
  risk_check_failed: "Risk checks failed; use Financial Connections or contact support.",
  feature_disabled: "Plaid Auth is disabled on this deployment.",
  production_not_allowlisted: "Plaid Auth is not enabled for this tenant.",
  plaid_bank_not_found: "Linked bank not found.",
  plaid_bank_not_ready: "Linked bank is not ready for ACH debit.",
  stripe_bank_token_pi_not_enabled:
    "Stripe Payment Intents for Plaid bank tokens are not enabled on this platform account.",
};

/**
 * Wire fields this module is allowed to surface for a linked bank. Acts as a
 * closed allowlist: if the Gateway response ever grows a secret-bearing field,
 * it is dropped here instead of reaching caller code, logs, or storage.
 */
const SAFE_BANK_FIELDS = [
  "id",
  "environment",
  "institution_id",
  "verification_status",
  "auth_method",
  "bank_name",
  "bank_mask",
  "bank_last4",
  "account_type",
  "account_subtype",
  "status",
  "ready",
  "readiness_reason",
  "stripe_attach_status",
  "stripe_attach_error_code",
  "relink_required",
  "bank_link_source",
  "created_at",
  "updated_at",
] as const;

/**
 * Field names that must never appear in a public representation produced by
 * this module. Enforced by {@link assertNoPlaidSecretFields} on every public
 * object.
 */
export const FORBIDDEN_PLAID_PUBLIC_FIELDS: ReadonlySet<string> = new Set([
  "access_token",
  "public_token",
  "link_token",
  "processor_token",
  "bank_account_token",
  "stripe_bank_account_token",
  "capability_token",
  "client_secret",
  "item_access_token",
  "account_number",
  "routing_number",
  "wire_routing_number",
  "identity",
  "identity_match",
  "owners",
  "balances",
  "available_balance",
  "current_balance",
]);

/**
 * Value prefixes that indicate Plaid Link / Stripe processor material. Rejected
 * on input so a caller can never smuggle a token through an ID parameter.
 */
const SECRET_VALUE_PREFIXES = [
  "public-",
  "access-",
  "link-",
  "processor-",
  "btok_",
  "pk_",
  "sk_",
] as const;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Base class for operator-facing Plaid helper failures. */
export class PlaidOperatorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlaidOperatorError";
  }
}

/**
 * Thrown when Plaid Link / token material is passed to a helper argument.
 *
 * Kit has no Link or token-exchange surface. Link tokens, public tokens, access
 * tokens, and Stripe processor tokens are handled server-side by the Gateway
 * only, so receiving one here means the caller is on the wrong code path.
 */
export class PlaidSecretMaterialError extends PlaidOperatorError {
  constructor(message: string) {
    super(message);
    this.name = "PlaidSecretMaterialError";
  }
}

/**
 * Thrown when the Gateway rejects the operator credential or returns an
 * unusable tenant principal. The TypeScript analog of the Python helpers'
 * `GatewayAuthError`, scoped to this module so it carries no import cycle.
 */
export class PlaidCredentialError extends PlaidOperatorError {
  readonly statusCode: number | undefined;
  readonly bodyText: string | undefined;

  constructor(message: string, init?: { statusCode?: number; bodyText?: string }) {
    super(message);
    this.name = "PlaidCredentialError";
    this.statusCode = init?.statusCode;
    this.bodyText = init?.bodyText;
  }
}

/**
 * Thrown for non-success HTTP responses from Gateway Plaid/ACH operator routes.
 *
 * `reasonCode` carries the stable Gateway reason string when one is present
 * (see {@link PLAID_READINESS_REASONS}); otherwise it is `undefined`.
 */
export class PlaidOperatorHttpError extends PlaidOperatorError {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;
  readonly reasonCode: string | undefined;

  constructor(
    message: string,
    init: { statusCode: number; url: string; bodyText: string; reasonCode?: string },
  ) {
    super(message);
    this.name = "PlaidOperatorHttpError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
    this.reasonCode = init.reasonCode;
  }
}

/**
 * Thrown when no bank with the requested id is visible to the caller's tenant.
 *
 * The Gateway answers unknown, foreign-tenant, and revoked banks identically so
 * a caller cannot probe another tenant's inventory. Treat this as "not yours or
 * not there", never as proof the bank does not exist somewhere else.
 */
export class PlaidBankNotFoundError extends PlaidOperatorError {
  readonly bankAccountId: string;
  readonly reasonCode = "plaid_bank_not_found";

  constructor(bankAccountId: string) {
    super(`linked bank not found: ${bankAccountId}`);
    this.name = "PlaidBankNotFoundError";
    this.bankAccountId = bankAccountId;
  }
}

/** Thrown before funding when a linked bank is not in a debitable `ready` state. */
export class PlaidBankNotReadyError extends PlaidOperatorError {
  readonly bankAccountId: string;
  readonly readinessReason: string;
  readonly reasonCode = "plaid_bank_not_ready";

  constructor(bankAccountId: string, readinessReason: string) {
    const reason = readinessReason || "not_ready";
    super(
      `linked bank ${bankAccountId} is not ready for ACH debit (${reason}): ` +
        plaidReadinessMessage(reason),
    );
    this.name = "PlaidBankNotReadyError";
    this.bankAccountId = bankAccountId;
    this.readinessReason = reason;
  }
}

/**
 * Thrown when a Gateway response claims a different tenant, intent, or bank than
 * the one the client is bound to. Never downgrade this to a warning: it means
 * the response cannot be attributed to the caller's tenant.
 */
export class PlaidTenantBindingError extends PlaidOperatorError {
  constructor(message: string) {
    super(message);
    this.name = "PlaidTenantBindingError";
  }
}

/**
 * Return a short operator-safe description for a readiness reason code.
 *
 * Mirrors `plaid.ReasonMessage` in `go/gateway/internal/rails/plaid/reasons.go` so
 * backend callers render the same wording as the console and CLI.
 */
export function plaidReadinessMessage(reasonCode?: string | null): string {
  const key = (reasonCode ?? "").trim();
  return READINESS_MESSAGES[key] ?? "Not ready for ACH debit.";
}

/**
 * Fail closed if a public representation carries a forbidden secret field.
 *
 * This is a runtime backstop for the allowlist projections below: public
 * objects are built from the safe-field allowlist, so a violation means a code
 * change broke the boundary rather than a caller doing something wrong.
 */
export function assertNoPlaidSecretFields(
  payload: Record<string, unknown>,
  source: string,
): void {
  const leaked = Object.keys(payload)
    .filter((key) => FORBIDDEN_PLAID_PUBLIC_FIELDS.has(key))
    .sort();
  if (leaked.length > 0) {
    throw new PlaidSecretMaterialError(
      `${source} public representation would leak forbidden field(s): ${leaked.join(", ")}`,
    );
  }
}

function assertNoSecretMaterial(value: string, field: string): void {
  const lowered = value.trim().toLowerCase();
  for (const prefix of SECRET_VALUE_PREFIXES) {
    if (lowered.startsWith(prefix)) {
      throw new PlaidSecretMaterialError(
        `${field} looks like Plaid Link or Stripe token material (${prefix}…); ` +
          "Paybond never accepts Link tokens, public tokens, access tokens, or " +
          "processor tokens outside the server-side Gateway exchange",
      );
    }
  }
}

function coerceUuid(value: string, field: string): string {
  const candidate = String(value ?? "").trim();
  if (!candidate) {
    throw new PlaidOperatorError(`${field} is required`);
  }
  assertNoSecretMaterial(candidate, field);
  if (!UUID_RE.test(candidate)) {
    throw new PlaidOperatorError(`${field} must be a canonical UUID`);
  }
  return candidate.toLowerCase();
}

/**
 * Safe operator view of one tenant-scoped Plaid-linked bank.
 *
 * Contains only what the Admin console already renders for the same operator:
 * institution, masked account, verification/attach state, and a stable
 * readiness reason. Internal Plaid Item IDs, Plaid account IDs, Stripe
 * customer/bank-account IDs, access tokens, and processor tokens are
 * intentionally absent.
 */
export type PlaidBankAccount = {
  readonly id: string;
  readonly environment: string;
  readonly ready: boolean;
  readonly status: string;
  readonly verificationStatus: string;
  readonly readinessReason?: string;
  readonly institutionId?: string;
  readonly authMethod?: string;
  readonly bankName?: string;
  readonly bankMask?: string;
  readonly bankLast4?: string;
  readonly accountType?: string;
  readonly accountSubtype?: string;
  readonly stripeAttachStatus?: string;
  readonly stripeAttachErrorCode?: string;
  readonly relinkRequired: boolean;
  readonly bankLinkSource?: string;
  readonly createdAt?: string;
  readonly updatedAt?: string;
};

/** Tenant-scoped inventory of linked Plaid banks visible to the caller. */
export type PlaidBankInventory = {
  readonly tenantId: string;
  readonly environment: string;
  readonly bankAccounts: readonly PlaidBankAccount[];
};

/**
 * Safe operator view of an ACH fund attempt that used a Plaid-verified bank.
 *
 * Deliberately omits `capability_token` (an agent spend credential the Gateway
 * may echo on this route), Stripe `client_secret`, Stripe customer/payment
 * method IDs, and every Plaid token. Funding is only final when Harbor observes
 * the Stripe PaymentIntent terminal event; `funded` reflects Harbor state at
 * response time, not settlement.
 */
export type PlaidAchFundingResult = {
  readonly tenantId: string;
  readonly intentId: string;
  readonly plaidBankAccountId: string;
  readonly state: string;
  readonly funded: boolean;
  readonly settlementRail: string;
  readonly currency: string;
  readonly amountCents: number;
  readonly statusCode: number;
  readonly stripePaymentIntentId?: string;
  readonly expectedDebitDate?: string;
};

/** Banks currently debitable through `stripe_ach_debit`. */
export function readyPlaidBankAccounts(
  inventory: PlaidBankInventory,
): readonly PlaidBankAccount[] {
  return inventory.bankAccounts.filter((bank) => bank.ready);
}

/** Operator-safe description of a bank's readiness state. */
export function plaidBankReadinessMessage(bank: PlaidBankAccount): string {
  return plaidReadinessMessage(bank.ready ? "ready" : bank.readinessReason);
}

/** Serialize a bank to a JSON-safe object containing only allowlisted, non-secret fields. */
export function plaidBankAccountToPublicJSON(bank: PlaidBankAccount): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    id: bank.id,
    environment: bank.environment,
    ready: bank.ready,
    status: bank.status,
    verification_status: bank.verificationStatus,
    readiness_reason: bank.readinessReason ?? null,
    readiness_message: plaidBankReadinessMessage(bank),
    institution_id: bank.institutionId ?? null,
    auth_method: bank.authMethod ?? null,
    bank_name: bank.bankName ?? null,
    bank_mask: bank.bankMask ?? null,
    bank_last4: bank.bankLast4 ?? null,
    account_type: bank.accountType ?? null,
    account_subtype: bank.accountSubtype ?? null,
    stripe_attach_status: bank.stripeAttachStatus ?? null,
    stripe_attach_error_code: bank.stripeAttachErrorCode ?? null,
    relink_required: bank.relinkRequired,
    bank_link_source: bank.bankLinkSource ?? null,
    created_at: bank.createdAt ?? null,
    updated_at: bank.updatedAt ?? null,
  };
  assertNoPlaidSecretFields(payload, "PlaidBankAccount");
  return payload;
}

/** Serialize an inventory to a JSON-safe object containing only allowlisted fields. */
export function plaidBankInventoryToPublicJSON(
  inventory: PlaidBankInventory,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    tenant_id: inventory.tenantId,
    environment: inventory.environment,
    bank_accounts: inventory.bankAccounts.map(plaidBankAccountToPublicJSON),
    count: inventory.bankAccounts.length,
  };
  assertNoPlaidSecretFields(payload, "PlaidBankInventory");
  return payload;
}

/** Serialize a funding result to a JSON-safe object containing only allowlisted fields. */
export function plaidAchFundingResultToPublicJSON(
  result: PlaidAchFundingResult,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    tenant_id: result.tenantId,
    intent_id: result.intentId,
    plaid_bank_account_id: result.plaidBankAccountId,
    state: result.state,
    funded: result.funded,
    settlement_rail: result.settlementRail,
    currency: result.currency,
    amount_cents: result.amountCents,
    status_code: result.statusCode,
    stripe_payment_intent_id: result.stripePaymentIntentId ?? null,
    expected_debit_date: result.expectedDebitDate ?? null,
  };
  assertNoPlaidSecretFields(payload, "PlaidAchFundingResult");
  return payload;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function isJSONObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Project a Gateway bank-account wire object onto the safe allowlist. */
function parseBankAccount(raw: Record<string, unknown>): PlaidBankAccount {
  const safe: Record<string, unknown> = {};
  for (const key of SAFE_BANK_FIELDS) {
    if (key in raw) {
      safe[key] = raw[key];
    }
  }
  const id = optionalString(safe.id);
  if (id === undefined) {
    throw new PlaidOperatorError("gateway bank-account entry missing id");
  }
  return {
    id,
    environment: optionalString(safe.environment) ?? "unknown",
    ready: safe.ready === true,
    status: optionalString(safe.status) ?? "unknown",
    verificationStatus: optionalString(safe.verification_status) ?? "unknown",
    readinessReason: optionalString(safe.readiness_reason),
    institutionId: optionalString(safe.institution_id),
    authMethod: optionalString(safe.auth_method),
    bankName: optionalString(safe.bank_name),
    bankMask: optionalString(safe.bank_mask),
    bankLast4: optionalString(safe.bank_last4),
    accountType: optionalString(safe.account_type),
    accountSubtype: optionalString(safe.account_subtype),
    stripeAttachStatus: optionalString(safe.stripe_attach_status),
    stripeAttachErrorCode: optionalString(safe.stripe_attach_error_code),
    relinkRequired: safe.relink_required === true,
    bankLinkSource: optionalString(safe.bank_link_source),
    createdAt: optionalString(safe.created_at),
    updatedAt: optionalString(safe.updated_at),
  };
}

/**
 * Extract a stable Gateway reason code from an error body, or `undefined`.
 *
 * Matches whole tokens only, and skips the generic `ready`/`error`/`not_ready`
 * codes, so prose like "already funded" or "internal error" is not misreported
 * as a Plaid readiness reason.
 */
function reasonCodeFromErrorBody(bodyText: string): string | undefined {
  const lowered = bodyText.trim().toLowerCase();
  if (!lowered) {
    return undefined;
  }
  for (const reason of PLAID_READINESS_REASONS) {
    if (GENERIC_REASON_CODES.has(reason)) {
      continue;
    }
    if (new RegExp(`(?<![a-z0-9_])${reason}(?![a-z0-9_])`).test(lowered)) {
      return reason;
    }
  }
  return undefined;
}

/** Construction options for {@link OperatorPlaidBankClient}. */
export type OperatorPlaidBankClientOptions = {
  /** Operator or service-account Gateway API key. Never an agent capability token. */
  staticGatewayBearerToken: string;
  /** Retry budget for transient 429/5xx responses. */
  maxRetries?: number;
};

/** Input for {@link OperatorPlaidBankClient.fundAchIntentWithBank}. */
export type FundAchIntentWithPlaidBankInput = {
  intentId: string;
  plaidBankAccountId: string;
  /**
   * Pre-check readiness client-side and throw {@link PlaidBankNotReadyError}
   * before any funding call. Defaults to `true`. The pre-check costs one
   * tenant-scoped `GET` for this bank, not a full inventory listing. Pass
   * `false` when you already hold a fresh {@link OperatorPlaidBankClient.listBankAccounts}
   * result, or want the Gateway's own reason code instead.
   */
  requireReady?: boolean;
  /** Optional `idempotency-key` header for duplicate-safe retries. */
  idempotencyKey?: string;
};

/**
 * Tenant-bound Gateway client for operator Plaid bank inventory and ACH funding.
 *
 * **Backend/operator use only.** Construct it in trusted server code with an
 * operator or service-account bearer token; never hand an instance (or its
 * token) to an agent, an MCP tool, or model-authored code.
 *
 * The `tenantId` argument is a *binding assertion*, not an authorization input:
 * the Gateway re-derives tenant and role from the bearer token on every request,
 * and responses that echo a different tenant throw
 * {@link PlaidTenantBindingError}. Prefer {@link ServiceAccountPlaidSession.open}
 * (or the module-level helpers), which resolve the tenant from
 * `GET /v1/auth/principal` instead of trusting a caller-supplied value.
 */
export class OperatorPlaidBankClient {
  private readonly base: string;
  private readonly bearerToken: string;
  private readonly maxRetries: number;

  /** Tenant this client is bound to (derived from the authenticated credential). */
  readonly tenantId: string;

  constructor(gatewayBaseUrl: string, tenantId: string, options: OperatorPlaidBankClientOptions) {
    this.base = requireSecureGatewayUrl(gatewayBaseUrl) + "/";
    this.tenantId = tenantId.trim();
    this.bearerToken = options.staticGatewayBearerToken.trim();
    this.maxRetries = Math.max(1, options.maxRetries ?? 3);
  }

  private headers(extra?: Record<string, string>): Headers {
    const headers = new Headers(extra);
    headers.set("accept", "application/json");
    headers.set("authorization", `Bearer ${this.bearerToken}`);
    return headers;
  }

  private async get(path: string): Promise<{ res: Response; text: string; url: string }> {
    const url = `${this.base}${path.replace(/^\/+/, "")}`;
    const res = await fetchWithGatewayRetries(
      url,
      { method: "GET", headers: this.headers() },
      this.maxRetries,
    );
    return { res, text: await res.text(), url };
  }

  /**
   * List Plaid-linked banks owned by this tenant.
   *
   * Returns safe metadata (institution, masked account, readiness reason) and
   * never any Plaid or Stripe token.
   *
   * @throws {PlaidOperatorHttpError} The Gateway rejected the call (403 role,
   *   404 `feature_disabled` / `production_not_allowlisted`, and so on).
   */
  async listBankAccounts(options?: { readyOnly?: boolean }): Promise<PlaidBankInventory> {
    const { res, text, url } = await this.get(BANK_ACCOUNTS_PATH);
    if (!res.ok) {
      throw new PlaidOperatorHttpError(`Gateway Plaid bank-accounts HTTP ${res.status}`, {
        statusCode: res.status,
        url,
        bodyText: text,
        reasonCode: reasonCodeFromErrorBody(text),
      });
    }
    const body: unknown = JSON.parse(text);
    if (!isJSONObject(body)) {
      throw new PlaidOperatorHttpError("Gateway Plaid bank-accounts response was not a JSON object", {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const entries = Array.isArray(body.bank_accounts) ? body.bank_accounts : [];
    let banks = entries.filter(isJSONObject).map(parseBankAccount);
    if (options?.readyOnly === true) {
      banks = banks.filter((bank) => bank.ready);
    }
    return {
      tenantId: this.tenantId,
      environment: optionalString(body.environment) ?? "unknown",
      bankAccounts: banks,
    };
  }

  /**
   * Fetch one tenant-owned bank by id.
   *
   * Issues a single tenant-scoped `GET /v1/admin/plaid/bank-accounts/{id}`
   * rather than downloading the whole inventory, so readiness checks stay O(1)
   * for tenants with many linked banks.
   *
   * @throws {PlaidBankNotFoundError} The id is unknown to this tenant. Unknown
   *   and cross-tenant ids are indistinguishable by design.
   * @throws {PlaidOperatorHttpError} Any other non-success Gateway response.
   */
  async getBankAccount(bankAccountId: string): Promise<PlaidBankAccount> {
    const resolved = coerceUuid(bankAccountId, "bankAccountId");
    const { res, text, url } = await this.get(
      `${BANK_ACCOUNTS_PATH}/${encodeURIComponent(resolved)}`,
    );
    if (res.status === 404) {
      // Distinguish "no such bank for this tenant" from a feature/rollout gate,
      // which also answers 404 but with its own reason code.
      const reasonCode = reasonCodeFromErrorBody(text);
      if (reasonCode === undefined || reasonCode === "plaid_bank_not_found") {
        throw new PlaidBankNotFoundError(resolved);
      }
      throw new PlaidOperatorHttpError(`Gateway Plaid bank-account HTTP ${res.status}`, {
        statusCode: res.status,
        url,
        bodyText: text,
        reasonCode,
      });
    }
    if (!res.ok) {
      throw new PlaidOperatorHttpError(`Gateway Plaid bank-account HTTP ${res.status}`, {
        statusCode: res.status,
        url,
        bodyText: text,
        reasonCode: reasonCodeFromErrorBody(text),
      });
    }
    const body: unknown = JSON.parse(text);
    if (!isJSONObject(body)) {
      throw new PlaidOperatorHttpError("Gateway Plaid bank-account response was not a JSON object", {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    const bank = parseBankAccount(body);
    if (bank.id.toLowerCase() !== resolved) {
      throw new PlaidTenantBindingError(
        `plaid bank id mismatch: requested=${resolved} gateway=${bank.id}`,
      );
    }
    return bank;
  }

  /**
   * Fund a `stripe_ach_debit` intent using a tenant-owned, ready Plaid bank.
   *
   * The Gateway is the authorization boundary: it re-derives tenant and role
   * from the bearer token, verifies the bank *and* the intent belong to that
   * tenant, refuses pending/attach-failed/relink/revoked/risk-blocked banks, and
   * forwards only the resolved Stripe customer/payment-method reference to
   * Harbor. This helper adds a client-side pre-check and response binding
   * checks; it never widens what the Gateway allows.
   *
   * Any capability token echoed by the Gateway is discarded, not returned.
   *
   * @throws {PlaidSecretMaterialError} An argument carried Link/token material.
   * @throws {PlaidBankNotFoundError} The bank id is not visible to this tenant.
   * @throws {PlaidBankNotReadyError} `requireReady` and the bank is not ready.
   * @throws {PlaidOperatorHttpError} The Gateway or Harbor rejected the call.
   * @throws {PlaidTenantBindingError} The response echoed a different tenant or intent.
   */
  async fundAchIntentWithBank(
    input: FundAchIntentWithPlaidBankInput,
  ): Promise<PlaidAchFundingResult> {
    const intentId = coerceUuid(input.intentId, "intentId");
    const bankAccountId = coerceUuid(input.plaidBankAccountId, "plaidBankAccountId");

    if (input.requireReady !== false) {
      const bank = await this.getBankAccount(bankAccountId);
      if (!bank.ready) {
        throw new PlaidBankNotReadyError(bank.id, bank.readinessReason ?? "not_ready");
      }
    }

    const url =
      `${this.base}v1/admin/settlement/stripe/ach/intents/` +
      `${encodeURIComponent(intentId)}/fund`;
    const extraHeaders: Record<string, string> = { "content-type": "application/json" };
    if (input.idempotencyKey?.trim()) {
      extraHeaders["idempotency-key"] = input.idempotencyKey.trim();
    }
    const res = await fetchWithGatewayRetries(
      url,
      {
        method: "POST",
        headers: this.headers(extraHeaders),
        body: JSON.stringify({ plaid_bank_account_id: bankAccountId }),
      },
      this.maxRetries,
    );
    const text = await res.text();
    if (!res.ok) {
      throw new PlaidOperatorHttpError(`Gateway Plaid ACH fund HTTP ${res.status}`, {
        statusCode: res.status,
        url,
        bodyText: text,
        reasonCode: reasonCodeFromErrorBody(text),
      });
    }
    const body: unknown = JSON.parse(text);
    if (!isJSONObject(body)) {
      throw new PlaidOperatorHttpError("Gateway Plaid ACH fund response was not a JSON object", {
        statusCode: res.status,
        url,
        bodyText: text,
      });
    }
    return this.parseFundingResult(body, {
      intentId,
      bankAccountId,
      statusCode: res.status,
      url,
      bodyText: text,
    });
  }

  private parseFundingResult(
    body: Record<string, unknown>,
    init: {
      intentId: string;
      bankAccountId: string;
      statusCode: number;
      url: string;
      bodyText: string;
    },
  ): PlaidAchFundingResult {
    const tenant = String(body.tenant ?? "").trim();
    if (tenant !== this.tenantId) {
      throw new PlaidTenantBindingError(
        `plaid ach fund tenant mismatch: client=${this.tenantId} gateway=${tenant}`,
      );
    }
    const echoedIntentId = String(body.intent_id ?? "").trim();
    if (!echoedIntentId) {
      throw new PlaidOperatorHttpError("Gateway Plaid ACH fund response missing intent_id", {
        statusCode: init.statusCode,
        url: init.url,
        bodyText: init.bodyText,
      });
    }
    if (echoedIntentId.toLowerCase() !== init.intentId) {
      throw new PlaidTenantBindingError(
        `plaid ach fund intent mismatch: requested=${init.intentId} gateway=${echoedIntentId}`,
      );
    }

    const state = optionalString(body.state);
    const settlementRail = optionalString(body.settlement_rail);
    const currency = optionalString(body.currency);
    if (state === undefined || settlementRail === undefined || currency === undefined) {
      throw new PlaidOperatorHttpError(
        "Gateway Plaid ACH fund response missing state/settlement_rail/currency",
        { statusCode: init.statusCode, url: init.url, bodyText: init.bodyText },
      );
    }
    const amountCents = body.amount_cents;
    if (typeof amountCents !== "number" || !Number.isFinite(amountCents)) {
      throw new PlaidOperatorHttpError("Gateway Plaid ACH fund response missing amount_cents", {
        statusCode: init.statusCode,
        url: init.url,
        bodyText: init.bodyText,
      });
    }

    const funding = isJSONObject(body.funding) ? body.funding : {};
    return {
      tenantId: tenant,
      intentId: echoedIntentId,
      plaidBankAccountId: init.bankAccountId,
      state,
      funded: body.funded === true,
      settlementRail,
      currency,
      amountCents,
      statusCode: init.statusCode,
      stripePaymentIntentId: optionalString(funding.stripe_payment_intent_id),
      expectedDebitDate: optionalString(funding.expected_debit_date),
    };
  }
}

/** Init for {@link ServiceAccountPlaidSession.open} and the module-level helpers. */
export type ServiceAccountPlaidSessionInit = {
  /** Operator or service-account Gateway API key. Never a Plaid token. */
  apiKey: string;
  /** Gateway origin (HTTPS, or loopback for local dev). */
  gatewayBaseUrl?: string;
  principalPath?: string;
  /** Assert the credential's environment before issuing any Plaid call. */
  expectedEnvironment?: PlaidPaybondEnvironment;
  maxRetries?: number;
};

/**
 * Operator/backend Plaid session bound to one authenticated credential.
 *
 * The tenant is resolved from `GET /v1/auth/principal` using the supplied API
 * key, so tenant scope always comes from the credential and never from caller
 * input. Backend use only — do not expose this session to agents or MCP tools.
 */
export class ServiceAccountPlaidSession {
  readonly plaid: OperatorPlaidBankClient;

  private constructor(plaid: OperatorPlaidBankClient) {
    this.plaid = plaid;
  }

  /** Open a tenant-bound session for an operator/service-account API key. */
  static async open(init: ServiceAccountPlaidSessionInit): Promise<ServiceAccountPlaidSession> {
    const gatewayBaseUrl = requireSecureGatewayUrl(
      init.gatewayBaseUrl?.trim() || DEFAULT_PAYBOND_PLAID_GATEWAY_BASE_URL,
    );
    const maxRetries = Math.max(1, init.maxRetries ?? 3);
    const tenantId = await resolvePlaidGatewayTenantId({
      gatewayBaseUrl,
      apiKey: init.apiKey,
      principalPath: init.principalPath ?? DEFAULT_PLAID_PRINCIPAL_PATH,
      expectedEnvironment: init.expectedEnvironment,
      maxRetries,
    });
    return new ServiceAccountPlaidSession(
      new OperatorPlaidBankClient(gatewayBaseUrl, tenantId, {
        staticGatewayBearerToken: init.apiKey,
        maxRetries,
      }),
    );
  }

  /** Release session resources. Present for symmetry with the Python session. */
  async aclose(): Promise<void> {
    await Promise.resolve();
  }
}

async function resolvePlaidGatewayTenantId(init: {
  gatewayBaseUrl: string;
  apiKey: string;
  principalPath: string;
  expectedEnvironment?: PlaidPaybondEnvironment;
  maxRetries: number;
}): Promise<string> {
  const path = init.principalPath.startsWith("/") ? init.principalPath : `/${init.principalPath}`;
  const url = `${init.gatewayBaseUrl}${path}`;
  const res = await fetchWithGatewayRetries(
    url,
    {
      method: "GET",
      headers: { accept: "application/json", authorization: `Bearer ${init.apiKey.trim()}` },
    },
    init.maxRetries,
  );
  const text = await res.text();
  if (!res.ok) {
    throw new PlaidCredentialError(`gateway principal HTTP ${res.status}`, {
      statusCode: res.status,
      bodyText: text,
    });
  }
  const body: unknown = JSON.parse(text);
  if (!isJSONObject(body)) {
    throw new PlaidCredentialError("gateway principal response was not a JSON object", {
      bodyText: text,
    });
  }
  const tenantId = String(body.tenant_id ?? "").trim();
  if (!tenantId) {
    throw new PlaidCredentialError("gateway principal JSON missing tenant_id", { bodyText: text });
  }
  if (init.expectedEnvironment !== undefined) {
    if (init.expectedEnvironment !== "live" && init.expectedEnvironment !== "sandbox") {
      throw new PlaidCredentialError(
        `expectedEnvironment must be "live" or "sandbox", got ${JSON.stringify(init.expectedEnvironment)}`,
      );
    }
    const actual = typeof body.environment === "string" ? body.environment.trim() : "";
    if (!actual) {
      throw new PlaidCredentialError("gateway principal response missing environment", {
        bodyText: text,
      });
    }
    if (actual !== init.expectedEnvironment) {
      throw new PlaidCredentialError(
        `gateway principal environment mismatch: expected=${init.expectedEnvironment} gateway=${actual}`,
        { bodyText: text },
      );
    }
  }
  return tenantId;
}

/** Options for {@link listPlaidBanks}. */
export type ListPlaidBanksInit = ServiceAccountPlaidSessionInit & {
  /** Return only banks currently debitable through `stripe_ach_debit`. */
  readyOnly?: boolean;
};

/**
 * List the calling tenant's Plaid-linked banks (operator/backend only).
 *
 * Tenant scope is derived from `apiKey` via `GET /v1/auth/principal`; there is
 * no tenant parameter to spoof. Returns safe metadata only — no Link tokens,
 * public tokens, access tokens, Stripe processor tokens, identity details, or
 * balances.
 *
 * @throws {PlaidCredentialError} The credential is rejected or the environment mismatches.
 * @throws {PlaidOperatorHttpError} The Gateway rejected the bank-inventory call.
 */
export async function listPlaidBanks(init: ListPlaidBanksInit): Promise<PlaidBankInventory> {
  const session = await ServiceAccountPlaidSession.open(init);
  try {
    return await session.plaid.listBankAccounts({ readyOnly: init.readyOnly === true });
  } finally {
    await session.aclose();
  }
}

/** Options for {@link fundAchWithPlaidBank}. */
export type FundAchWithPlaidBankInit = ServiceAccountPlaidSessionInit & {
  /** Harbor intent to fund. Must belong to the caller's tenant. */
  intentId: string;
  /** Bank id from {@link listPlaidBanks}. Never a Plaid or Stripe token. */
  plaidBankAccountId: string;
  /**
   * Pre-check bank readiness before attempting to fund (default `true`). Costs
   * one `GET` for the single bank; callers that already hold inventory from
   * {@link listPlaidBanks} can reuse {@link OperatorPlaidBankClient} with
   * `requireReady: false` to skip the extra round trip.
   */
  requireReady?: boolean;
  idempotencyKey?: string;
};

/**
 * Fund a `stripe_ach_debit` intent with a ready Plaid bank (operator/backend only).
 *
 * This is the operator half of the funding boundary: an authorized human or
 * backend service funds the intent, and agents may then spend against it through
 * the normal capability path. Agents must never call this helper, and it is not
 * exported from `@paybond/kit/agent` or exposed as an MCP tool.
 *
 * Both the bank and the intent must belong to the tenant behind `apiKey`. The
 * Gateway enforces that server-side and answers foreign ids the same way it
 * answers unknown ones, so this helper cannot be used to probe another tenant.
 *
 * @throws {PlaidSecretMaterialError} An argument carried Plaid/Stripe token material.
 * @throws {PlaidBankNotFoundError} The bank is not visible to this tenant.
 * @throws {PlaidBankNotReadyError} The bank is not debitable yet.
 * @throws {PlaidOperatorHttpError} The Gateway or Harbor rejected the funding call.
 * @throws {PlaidTenantBindingError} The response echoed a different tenant or intent.
 */
export async function fundAchWithPlaidBank(
  init: FundAchWithPlaidBankInit,
): Promise<PlaidAchFundingResult> {
  const session = await ServiceAccountPlaidSession.open(init);
  try {
    return await session.plaid.fundAchIntentWithBank({
      intentId: init.intentId,
      plaidBankAccountId: init.plaidBankAccountId,
      requireReady: init.requireReady,
      idempotencyKey: init.idempotencyKey,
    });
  } finally {
    await session.aclose();
  }
}
