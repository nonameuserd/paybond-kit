/**
 * Boundary tests for the operator/backend-only Plaid helpers (TS parity with
 * `kit/python/tests/test_plaid_backend_helpers.py`).
 *
 * Three invariants matter more than behaviour here:
 *
 * 1. Public representations cannot serialize Plaid Link / Stripe token material,
 *    even when the Gateway wire object contains extra fields.
 * 2. Tenant scope comes from the authenticated credential, and a response that
 *    claims a different tenant or intent is rejected rather than trusted.
 * 3. The helpers are unreachable from agent middleware, MCP, and templates.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import * as kit from "../src/index.js";
import * as agentSurface from "../src/agent/index.js";
import {
  FORBIDDEN_PLAID_PUBLIC_FIELDS,
  OperatorPlaidBankClient,
  PlaidBankNotFoundError,
  PlaidBankNotReadyError,
  PlaidOperatorError,
  PlaidOperatorHttpError,
  PlaidSecretMaterialError,
  PlaidTenantBindingError,
  ServiceAccountPlaidSession,
  assertNoPlaidSecretFields,
  fundAchWithPlaidBank,
  listPlaidBanks,
  plaidAchFundingResultToPublicJSON,
  plaidBankAccountToPublicJSON,
  plaidBankInventoryToPublicJSON,
} from "../src/plaid.js";

const GATEWAY = "https://gateway.test";
const API_KEY = `paybond_sk_${"a".repeat(32)}_${"b".repeat(64)}`;
const TENANT_A = "tenant-a";
const TENANT_B = "tenant-b";

const READY_BANK_ID = "11111111-1111-4111-8111-111111111111";
const PENDING_BANK_ID = "22222222-2222-4222-8222-222222222222";
const FOREIGN_BANK_ID = "33333333-3333-4333-8333-333333333333";
const INTENT_ID = "44444444-4444-4444-8444-444444444444";

/** Values a compromised or buggy Gateway response might carry. */
const LEAKY_SECRETS = {
  access_token: "access-sandbox-leaked-token",
  public_token: "public-sandbox-leaked-token",
  link_token: "link-sandbox-leaked-token",
  processor_token: "processor-sandbox-leaked-token",
  stripe_bank_account_token: "btok_leakedbanktoken",
  account_number: "000123456789",
  routing_number: "110000000",
  balances: { available: 4200.0, current: 4200.0 },
  identity: { owners: [{ names: ["Ada Lovelace"] }] },
};

function readyBankWire(): Record<string, unknown> {
  return {
    id: READY_BANK_ID,
    environment: "sandbox",
    item_id: "item-internal-id",
    account_id: "plaid-account-id",
    institution_id: "ins_109508",
    verification_status: "automatically_verified",
    auth_method: "INSTANT_AUTH",
    bank_name: "First Platypus Bank",
    bank_mask: "0000",
    bank_last4: "0000",
    account_type: "depository",
    account_subtype: "checking",
    status: "active",
    ready: true,
    readiness_reason: "ready",
    stripe_attach_status: "attached",
    stripe_customer_id: "cus_leaked",
    stripe_bank_account_id: "ba_leaked",
    relink_required: false,
    bank_link_source: "plaid_auth",
    created_at: "2026-07-01T00:00:00Z",
    updated_at: "2026-07-02T00:00:00Z",
    ...LEAKY_SECRETS,
  };
}

function pendingBankWire(): Record<string, unknown> {
  return {
    id: PENDING_BANK_ID,
    environment: "sandbox",
    institution_id: "ins_109508",
    verification_status: "pending_automatic_verification",
    bank_name: "First Platypus Bank",
    bank_mask: "1111",
    status: "active",
    ready: false,
    readiness_reason: "pending_automatic_verification",
    stripe_attach_status: "attach_pending",
  };
}

function fundResponseBody(options?: {
  tenant?: string;
  intentId?: string;
  funded?: boolean;
}): Record<string, unknown> {
  return {
    tenant: options?.tenant ?? TENANT_A,
    intent_id: options?.intentId ?? INTENT_ID,
    state: options?.funded === false ? "funding_pending" : "funded",
    settlement_rail: "stripe_ach_debit",
    currency: "usd",
    amount_cents: 5000,
    funded: options?.funded !== false,
    // The Gateway may echo an agent spend credential and Stripe secrets on this
    // route; the helper must never surface them to backend callers.
    capability_token: "cap_leaked_token",
    funding: {
      stripe_payment_intent_id: "pi_123",
      client_secret: "pi_123_secret_leaked",
      stripe_customer_id: "cus_leaked",
      payment_method_id: "pm_leaked",
      expected_debit_date: "2026-07-29",
      bank_last4: "0000",
    },
  };
}

type RouteHandler = (req: { url: string; init: RequestInit }) => Response;

type GatewayMock = {
  fetchMock: ReturnType<typeof vi.fn>;
  calls: Array<{ method: string; url: string; init: RequestInit }>;
  countFor: (predicate: (url: string) => boolean) => number;
  lastRequestFor: (predicate: (url: string) => boolean) =>
    | { method: string; url: string; init: RequestInit }
    | undefined;
};

/**
 * Install a fetch stub that answers only explicitly declared routes. Any
 * unexpected call fails the test rather than silently returning a 404, so
 * "which route did the helper hit" is an assertion, not a guess.
 */
function mockGateway(routes: Array<{ match: (url: string) => boolean; handle: RouteHandler }>): GatewayMock {
  const calls: Array<{ method: string; url: string; init: RequestInit }> = [];
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    calls.push({ method: String(init.method ?? "GET").toUpperCase(), url, init });
    for (const route of routes) {
      if (route.match(url)) {
        return route.handle({ url, init });
      }
    }
    throw new Error(`unexpected gateway call: ${String(init.method ?? "GET")} ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return {
    fetchMock,
    calls,
    countFor: (predicate) => calls.filter((call) => predicate(call.url)).length,
    lastRequestFor: (predicate) => [...calls].reverse().find((call) => predicate(call.url)),
  };
}

const isListUrl = (url: string): boolean => url === `${GATEWAY}/v1/admin/plaid/bank-accounts`;
const isGetUrl = (bankId: string) => (url: string): boolean =>
  url === `${GATEWAY}/v1/admin/plaid/bank-accounts/${bankId}`;
const isAnyGetUrl = (url: string): boolean =>
  /\/v1\/admin\/plaid\/bank-accounts\/[0-9a-f-]+$/i.test(url);
const isFundUrl = (url: string): boolean =>
  url === `${GATEWAY}/v1/admin/settlement/stripe/ach/intents/${INTENT_ID}/fund`;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const principalRoute = (tenantId = TENANT_A, environment = "sandbox") => ({
  match: (url: string) => url === `${GATEWAY}/v1/auth/principal`,
  handle: () => jsonResponse({ tenant_id: tenantId, environment }),
});

const listRoute = (...banks: Array<Record<string, unknown>>) => ({
  match: isListUrl,
  handle: () => jsonResponse({ environment: "sandbox", bank_accounts: banks }),
});

/**
 * Mirror `getPlaidBankAccountHandler`: known ids answer 200, and every other id
 * — including another tenant's — answers the same 404 reason code.
 */
const bankGetRoute = (...banks: Array<Record<string, unknown>>) => ({
  match: isAnyGetUrl,
  handle: ({ url }: { url: string }) => {
    const id = url.split("/").pop() ?? "";
    const bank = banks.find((candidate) => String(candidate.id) === id);
    return bank
      ? jsonResponse(bank)
      : jsonResponse({ error: "plaid_bank_not_found", message: "Linked bank not found." }, 404);
  },
});

const fundRoute = (body?: Record<string, unknown>, status = 200) => ({
  match: isFundUrl,
  handle: () => jsonResponse(body ?? fundResponseBody(), status),
});

function client(tenantId = TENANT_A): OperatorPlaidBankClient {
  return new OperatorPlaidBankClient(GATEWAY, tenantId, {
    staticGatewayBearerToken: API_KEY,
    maxRetries: 1,
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// --- secret-serialization boundary -------------------------------------------------

describe("plaid public representations", () => {
  it("cannot serialize secrets even when the gateway wire object carries them", async () => {
    mockGateway([listRoute(readyBankWire())]);
    const inventory = await client().listBankAccounts();
    const bank = inventory.bankAccounts[0]!;
    const publicBank = plaidBankAccountToPublicJSON(bank);

    for (const forbidden of FORBIDDEN_PLAID_PUBLIC_FIELDS) {
      expect(publicBank).not.toHaveProperty(forbidden);
    }
    // Internal Plaid/Stripe identifiers are dropped alongside outright secrets.
    for (const dropped of ["item_id", "account_id", "stripe_customer_id", "stripe_bank_account_id"]) {
      expect(publicBank).not.toHaveProperty(dropped);
      expect(bank).not.toHaveProperty(dropped);
    }

    const serialized = JSON.stringify(plaidBankInventoryToPublicJSON(inventory));
    for (const secret of ["access-sandbox", "public-sandbox", "link-sandbox", "btok_", "cus_", "ba_"]) {
      expect(serialized).not.toContain(secret);
    }
    expect(serialized).not.toContain("000123456789");
    expect(serialized).not.toContain("Ada Lovelace");
    // JSON.stringify of the parsed object is the most common accidental-logging path.
    expect(JSON.stringify(bank)).not.toContain("access-sandbox");

    expect(publicBank.bank_last4).toBe("0000");
    expect(publicBank.readiness_reason).toBe("ready");
    expect(publicBank.readiness_message).toBe("Bank is ready for ACH debit.");
    // Display-only account metadata must survive the allowlist so operators can
    // tell a checking account apart from a savings account when funding.
    expect(publicBank.account_type).toBe("depository");
    expect(publicBank.account_subtype).toBe("checking");
  });

  it("fails closed when a public object would carry a forbidden field", () => {
    expect(() =>
      assertNoPlaidSecretFields({ id: READY_BANK_ID, access_token: "x" }, "test"),
    ).toThrow(PlaidSecretMaterialError);
  });

  it("drops the capability token and Stripe client secret from funding results", async () => {
    mockGateway([bankGetRoute(readyBankWire()), fundRoute()]);
    const result = await client().fundAchIntentWithBank({
      intentId: INTENT_ID,
      plaidBankAccountId: READY_BANK_ID,
    });

    const publicResult = plaidAchFundingResultToPublicJSON(result);
    for (const forbidden of FORBIDDEN_PLAID_PUBLIC_FIELDS) {
      expect(publicResult).not.toHaveProperty(forbidden);
    }
    expect(result).not.toHaveProperty("capabilityToken");
    const serialized = JSON.stringify(publicResult);
    expect(serialized).not.toContain("cap_leaked_token");
    expect(serialized).not.toContain("secret_leaked");
    expect(serialized).not.toContain("pm_leaked");
    expect(JSON.stringify(result)).not.toContain("cap_leaked_token");

    expect(result.funded).toBe(true);
    expect(result.settlementRail).toBe("stripe_ach_debit");
    expect(result.plaidBankAccountId).toBe(READY_BANK_ID);
    expect(result.stripePaymentIntentId).toBe("pi_123");
  });
});

// --- credential-derived tenant scope -----------------------------------------------

describe("plaid credential-scoped tenant binding", () => {
  it("derives the tenant from the credential, not caller input", async () => {
    mockGateway([principalRoute("realm-from-credential")]);
    const session = await ServiceAccountPlaidSession.open({
      apiKey: API_KEY,
      gatewayBaseUrl: GATEWAY,
      expectedEnvironment: "sandbox",
    });
    try {
      expect(session.plaid.tenantId).toBe("realm-from-credential");
    } finally {
      await session.aclose();
    }
  });

  it("sends only the bearer credential and no tenant header", async () => {
    const gateway = mockGateway([principalRoute(), listRoute(readyBankWire(), pendingBankWire())]);

    const inventory = await listPlaidBanks({
      apiKey: API_KEY,
      gatewayBaseUrl: GATEWAY,
      readyOnly: true,
    });

    expect(inventory.tenantId).toBe(TENANT_A);
    expect(inventory.bankAccounts.map((bank) => bank.id)).toEqual([READY_BANK_ID]);
    const request = gateway.lastRequestFor(isListUrl)!;
    const headers = new Headers(request.init.headers);
    expect(headers.get("authorization")).toBe(`Bearer ${API_KEY}`);
    // No tenant is asserted on the wire: the Gateway derives it from the token.
    expect(headers.has("x-tenant-id")).toBe(false);
  });

  it("rejects a funding response echoing a different tenant", async () => {
    mockGateway([bankGetRoute(readyBankWire()), fundRoute(fundResponseBody({ tenant: TENANT_B }))]);
    await expect(
      client(TENANT_A).fundAchIntentWithBank({
        intentId: INTENT_ID,
        plaidBankAccountId: READY_BANK_ID,
      }),
    ).rejects.toThrow(PlaidTenantBindingError);
  });

  it("rejects a funding response echoing a different intent", async () => {
    mockGateway([
      bankGetRoute(readyBankWire()),
      fundRoute(fundResponseBody({ intentId: "55555555-5555-4555-8555-555555555555" })),
    ]);
    await expect(
      client().fundAchIntentWithBank({ intentId: INTENT_ID, plaidBankAccountId: READY_BANK_ID }),
    ).rejects.toThrow(/intent mismatch/);
  });

  it("rejects a bank response echoing a different bank id", async () => {
    mockGateway([
      {
        match: isGetUrl(PENDING_BANK_ID),
        handle: () => jsonResponse(readyBankWire()),
      },
    ]);
    await expect(client().getBankAccount(PENDING_BANK_ID)).rejects.toThrow(/bank id mismatch/);
  });

  it("stops before funding when the bank id is not visible to this tenant", async () => {
    const gateway = mockGateway([bankGetRoute(readyBankWire()), fundRoute()]);

    await expect(
      client().fundAchIntentWithBank({ intentId: INTENT_ID, plaidBankAccountId: FOREIGN_BANK_ID }),
    ).rejects.toBeInstanceOf(PlaidBankNotFoundError);

    expect(gateway.countFor(isFundUrl)).toBe(0);
    // Readiness is resolved by the per-id GET, never by listing the tenant's banks.
    expect(gateway.countFor(isListUrl)).toBe(0);
  });

  it("surfaces the gateway's own cross-tenant rejection when the pre-check is off", async () => {
    mockGateway([
      {
        match: isFundUrl,
        handle: () =>
          new Response("linked bank not found: plaid_bank_not_found", { status: 404 }),
      },
    ]);
    try {
      await client().fundAchIntentWithBank({
        intentId: INTENT_ID,
        plaidBankAccountId: FOREIGN_BANK_ID,
        requireReady: false,
      });
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PlaidOperatorHttpError);
      const httpErr = err as PlaidOperatorHttpError;
      expect(httpErr.statusCode).toBe(404);
      expect(httpErr.reasonCode).toBe("plaid_bank_not_found");
    }
  });

  it("does not report generic error prose as a readiness reason", async () => {
    mockGateway([
      { match: isFundUrl, handle: () => new Response("intent is already funded", { status: 409 }) },
    ]);
    try {
      await client().fundAchIntentWithBank({
        intentId: INTENT_ID,
        plaidBankAccountId: READY_BANK_ID,
        requireReady: false,
      });
      expect.fail("expected throw");
    } catch (err) {
      expect((err as PlaidOperatorHttpError).reasonCode).toBeUndefined();
    }
  });

  it("maps a risk-policy rejection to its reason code", async () => {
    mockGateway([
      {
        match: isFundUrl,
        handle: () => new Response("risk_check_required for this amount", { status: 422 }),
      },
    ]);
    try {
      await client().fundAchIntentWithBank({
        intentId: INTENT_ID,
        plaidBankAccountId: READY_BANK_ID,
        requireReady: false,
      });
      expect.fail("expected throw");
    } catch (err) {
      expect((err as PlaidOperatorHttpError).reasonCode).toBe("risk_check_required");
    }
  });

  it("surfaces a forbidden role instead of retrying into success", async () => {
    mockGateway([
      {
        match: isListUrl,
        handle: () => new Response("Harbor intent mutation access required", { status: 403 }),
      },
    ]);
    try {
      await client().listBankAccounts();
      expect.fail("expected throw");
    } catch (err) {
      expect((err as PlaidOperatorHttpError).statusCode).toBe(403);
    }
  });
});

// --- per-id GET and readiness ------------------------------------------------------

describe("plaid readiness lookups", () => {
  it("uses the dedicated per-id route instead of listing the inventory", async () => {
    const gateway = mockGateway([listRoute(readyBankWire(), pendingBankWire()), bankGetRoute(readyBankWire())]);

    const bank = await client().getBankAccount(READY_BANK_ID);

    expect(bank.id).toBe(READY_BANK_ID);
    expect(bank.ready).toBe(true);
    expect(gateway.countFor(isListUrl)).toBe(0);
    expect(gateway.countFor(isGetUrl(READY_BANK_ID))).toBe(1);
  });

  it("costs exactly one GET and no list when requireReady is on", async () => {
    const gateway = mockGateway([listRoute(readyBankWire()), bankGetRoute(readyBankWire()), fundRoute()]);

    await client().fundAchIntentWithBank({
      intentId: INTENT_ID,
      plaidBankAccountId: READY_BANK_ID,
      requireReady: true,
    });

    expect(gateway.countFor(isGetUrl(READY_BANK_ID))).toBe(1);
    expect(gateway.countFor(isListUrl)).toBe(0);
    expect(gateway.countFor(isFundUrl)).toBe(1);
  });

  it("skips the readiness lookup entirely when the caller already holds inventory", async () => {
    const gateway = mockGateway([listRoute(readyBankWire()), bankGetRoute(readyBankWire()), fundRoute()]);

    await client().fundAchIntentWithBank({
      intentId: INTENT_ID,
      plaidBankAccountId: READY_BANK_ID,
      requireReady: false,
    });

    expect(gateway.countFor(isAnyGetUrl)).toBe(0);
    expect(gateway.countFor(isListUrl)).toBe(0);
    expect(gateway.countFor(isFundUrl)).toBe(1);
  });

  it("blocks funding a pending bank before any funding call", async () => {
    const gateway = mockGateway([bankGetRoute(pendingBankWire()), fundRoute()]);

    try {
      await client().fundAchIntentWithBank({
        intentId: INTENT_ID,
        plaidBankAccountId: PENDING_BANK_ID,
      });
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PlaidBankNotReadyError);
      expect((err as PlaidBankNotReadyError).readinessReason).toBe(
        "pending_automatic_verification",
      );
    }
    expect(gateway.countFor(isFundUrl)).toBe(0);
  });

  it("keeps a rollout-gate 404 distinct from bank-not-found", async () => {
    mockGateway([
      {
        match: isGetUrl(READY_BANK_ID),
        handle: () =>
          jsonResponse({ error: "production_not_allowlisted", message: "not enabled" }, 404),
      },
    ]);
    try {
      await client().getBankAccount(READY_BANK_ID);
      expect.fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(PlaidOperatorHttpError);
      expect((err as PlaidOperatorHttpError).reasonCode).toBe("production_not_allowlisted");
    }
  });

  it("posts only the bank id and forwards the idempotency key", async () => {
    const gateway = mockGateway([principalRoute(), bankGetRoute(readyBankWire()), fundRoute()]);

    const result = await fundAchWithPlaidBank({
      apiKey: API_KEY,
      gatewayBaseUrl: GATEWAY,
      intentId: INTENT_ID,
      plaidBankAccountId: READY_BANK_ID,
      idempotencyKey: "fund-once",
    });

    expect(result.tenantId).toBe(TENANT_A);
    const request = gateway.lastRequestFor(isFundUrl)!;
    expect(JSON.parse(String(request.init.body))).toEqual({
      plaid_bank_account_id: READY_BANK_ID,
    });
    expect(new Headers(request.init.headers).get("idempotency-key")).toBe("fund-once");
  });
});

// --- input guards ------------------------------------------------------------------

describe("plaid input guards", () => {
  it.each([
    "access-sandbox-1234",
    "public-sandbox-1234",
    "link-sandbox-1234",
    "processor-sandbox-1234",
    "btok_1234",
  ])("rejects Plaid Link / processor material passed as an id (%s)", async (token) => {
    mockGateway([]);
    const c = client();
    await expect(
      c.fundAchIntentWithBank({ intentId: INTENT_ID, plaidBankAccountId: token }),
    ).rejects.toBeInstanceOf(PlaidSecretMaterialError);
    await expect(c.getBankAccount(token)).rejects.toBeInstanceOf(PlaidSecretMaterialError);
  });

  it("rejects a non-UUID bank id before any request", async () => {
    const gateway = mockGateway([]);
    await expect(client().getBankAccount("not-a-uuid")).rejects.toThrow(/canonical UUID/);
    expect(gateway.fetchMock).not.toHaveBeenCalled();
    await expect(client().getBankAccount("not-a-uuid")).rejects.toBeInstanceOf(PlaidOperatorError);
  });
});

// --- agent / MCP boundary ----------------------------------------------------------

const PLAID_HELPER_NAMES = [
  "listPlaidBanks",
  "fundAchWithPlaidBank",
  "OperatorPlaidBankClient",
  "ServiceAccountPlaidSession",
] as const;

const kitSrcRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "src");

function collectSourceFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (entry === "node_modules") {
        continue;
      }
      const full = path.join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (/\.(ts|tsx|js|mjs)$/.test(entry)) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

describe("plaid operator/agent boundary", () => {
  it("is reachable from the backend surface but not from @paybond/kit/agent", () => {
    for (const name of PLAID_HELPER_NAMES) {
      expect(kit).toHaveProperty(name);
      expect(agentSurface).not.toHaveProperty(name);
    }
  });

  it("is not imported by agent middleware, the MCP server, or MCP adapters", () => {
    const surfaces = [
      ...collectSourceFiles(path.join(kitSrcRoot, "agent")),
      ...collectSourceFiles(path.join(kitSrcRoot, "mcp")),
      path.join(kitSrcRoot, "mcp-server.ts"),
    ];
    const offenders = surfaces.filter((file) => {
      const text = readFileSync(file, "utf8");
      return /from\s+"(\.\.\/)+plaid\.js"|from\s+"\.\/plaid\.js"/.test(text);
    });
    expect(offenders).toEqual([]);
  });

  it("is not referenced by any shipped agent template", () => {
    const templatesRoot = path.join(kitSrcRoot, "..", "templates");
    let files: string[] = [];
    try {
      files = collectSourceFiles(templatesRoot);
    } catch {
      return; // templates are generated at build time and may be absent
    }
    const offenders = files.filter((file) => {
      const text = readFileSync(file, "utf8");
      return text.includes("listPlaidBanks") || text.includes("fundAchWithPlaidBank");
    });
    expect(offenders).toEqual([]);
  });
});
