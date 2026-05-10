import { afterEach, describe, expect, it, vi } from "vitest";
import {
  GatewayAuthError,
  GatewayHarborTokenProvider,
  GatewaySignalClient,
  HarborClient,
  HarborHttpError,
  ServiceAccountSignalSession,
} from "./index.js";

describe("HarborClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("rejects tenant echo mismatch", async () => {
    const intent = "550e8400-e29b-41d4-a716-446655440000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            allow: true,
            audit_id: "550e8400-e29b-41d4-a716-446655440001",
            tenant: "other",
            intent_id: intent,
            code: null,
            message: null,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const c = new HarborClient("https://harbor.test", "tenant-a");
    await expect(
      c.verifyCapability({
        intentId: intent,
        token: "Cg==",
        operation: "demo.tool",
      }),
    ).rejects.toThrow(/tenant mismatch/);
  });

  it("surfaces HarborHttpError with status for 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("nope", { status: 401 })),
    );
    const c = new HarborClient("https://harbor.test", "tenant-a");
    try {
      await c.verifyCapability({
        intentId: "550e8400-e29b-41d4-a716-446655440000",
        token: "Cg==",
        operation: "demo.tool",
      });
      expect.fail("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(HarborHttpError);
      const h = e as HarborHttpError;
      expect(h.statusCode).toBe(401);
      expect(h.bodyText).toBe("nope");
    }
  });

  it("returns structured x402 fund challenge on 402", async () => {
    const intent = "550e8400-e29b-41d4-a716-446655440010";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            intent_id: intent,
            tenant: "tenant-a",
            state: "open",
            settlement_rail: "x402_usdc_base",
            currency: "usd",
            amount_cents: 2000,
            funded: false,
            funding: {
              settlement_rail: "x402_usdc_base",
              harbor_fund_endpoint: `/intents/${intent}/fund`,
              status: "authorization_pending",
              payment_session_id: "paymentSession_test",
              payment_url: "https://pay.coinbase.com/payment-sessions/paymentSession_test",
              asset: "usdc",
              network: "base",
            },
          }),
          {
            status: 402,
            headers: {
              "content-type": "application/json",
              "payment-required": "x402-requirements",
            },
          },
        ),
      ),
    );
    const c = new HarborClient("https://harbor.test", "tenant-a");
    await expect(c.fundIntent(intent)).resolves.toMatchObject({
      statusCode: 402,
      paymentRequired: "x402-requirements",
      settlementRail: "x402_usdc_base",
      funded: false,
      funding: {
        settlementRail: "x402_usdc_base",
        paymentSessionId: "paymentSession_test",
      },
    });
  });

  it("getLedgerTip rejects ledger tenant echo mismatch", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "other",
            seq: 0,
            entry_commitment_hex: "00".repeat(32),
            empty: true,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const c = new HarborClient("https://harbor.test", "tenant-a");
    await expect(c.getLedgerTip()).rejects.toThrow(/ledger tenant mismatch/);
  });

  it("getLedgerEvents requests after_seq and clamps limit", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const u = typeof input === "string" ? input : input.toString();
      expect(u).toContain("after_seq=7");
      expect(u).toContain("limit=256");
      return new Response(
        JSON.stringify({
          schema_version: 1,
          tenant_id: "tenant-a",
          entries: [],
          next_after_seq: null,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const c = new HarborClient("https://harbor.test", "tenant-a");
    await c.getLedgerEvents({ afterSeq: 7, limit: 999 });
    expect(fetchMock).toHaveBeenCalled();
  });
});

describe("GatewayHarborTokenProvider", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("parses tenant_id and access_token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            access_token: "jwt-here",
            token_type: "Bearer",
            expires_in: 3600,
            tenant_id: "realm-z",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const mono = { t: 0 };
    const p = new GatewayHarborTokenProvider({
      gatewayBaseUrl: "https://gw.test",
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
      clock: () => {
        mono.t += 1_000_000;
        return mono.t;
      },
    });
    const tenant = await p.ensureInitial();
    expect(tenant).toBe("realm-z");
    const tok = await p.bearer();
    expect(tok).toBe("jwt-here");
  });

  it("raises when tenant_id missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            access_token: "jwt-here",
            token_type: "Bearer",
            expires_in: 3600,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const p = new GatewayHarborTokenProvider({
      gatewayBaseUrl: "https://gw.test",
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(p.ensureInitial()).rejects.toBeInstanceOf(GatewayAuthError);
  });
});

describe("GatewaySignalClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("rejects tenant drift on portfolio summary", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "other",
            score_model_version: "1.0",
            scoring_model: "paybond.signal.v1",
            checkpoint_last_ledger_seq: 1,
            operator_count: 0,
            average_score: 0,
            total_terminal_intents: 0,
            total_receipted_volume_cents: 0,
            operators_under_review: 0,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const c = new GatewaySignalClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(c.getPortfolioSummary()).rejects.toThrow(/signal tenant mismatch/);
  });
});

describe("ServiceAccountSignalSession", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("binds the tenant from gateway principal", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            tenant_id: "realm-z",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const session = await ServiceAccountSignalSession.open({
      gatewayBaseUrl: "https://gw.test",
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    expect(session.signal.tenantId).toBe("realm-z");
  });
});
