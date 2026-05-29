import { afterEach, describe, expect, it, vi } from "vitest";
import {
  GatewayA2AClient,
  GatewayAuthError,
  GatewayFraudClient,
  GatewayProtocolClient,
  GatewaySignalClient,
  HarborClient,
  HarborHttpError,
  Paybond,
  PaybondIntents,
  PaybondSpendDeniedError,
  PaybondSpendGuard,
  ProtocolHttpError,
  ServiceAccountFraudSession,
  ServiceAccountSignalSession,
  guardTool,
  paybondAgentToolSpendGuard,
  paybondRuntimeNeutralToolSpendGuard,
  paybondRuntimeToolCallAdapter,
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

describe("PaybondIntents", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("defaults evidence artifacts and submitted-at timestamp", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    const submitEvidence = vi.spyOn(harbor, "submitEvidence").mockResolvedValue({
      intentId,
      tenant: "tenant-a",
      state: "evidence_submitted",
      predicatePassed: true,
    });

    const intents = new PaybondIntents(harbor);
    await intents.submitEvidence({
      intentId,
      payeeDid: "did:web:example.com#payee",
      payeeSigningSeed: new Uint8Array(32),
      recognitionProof: {},
      payload: { ok: true },
    });

    expect(submitEvidence).toHaveBeenCalledTimes(1);
    const [calledIntentId, body] = submitEvidence.mock.calls[0]!;
    expect(calledIntentId).toBe(intentId);
    expect(body.artifacts).toEqual([]);
    expect(body.submitted_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  });

  it("exposes createSpendIntent as an alias for create", async () => {
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    const create = vi.spyOn(PaybondIntents.prototype, "create").mockResolvedValue({
      intent_id: "550e8400-e29b-41d4-a716-446655440000",
    });
    const intents = new PaybondIntents(harbor);
    await expect(
      intents.createSpendIntent({
        principalDid: "did:web:example.com#principal",
        principalSigningSeed: new Uint8Array(32),
        recognitionProof: {},
        payeeDid: "did:web:example.com#payee",
        budget: { currency: "usd", max_spend_usd: 200 },
        predicate: { version: 1, root: { op: "true" } },
        currency: "usd",
        amountCents: 20_000,
        evidenceSchema: { type: "object" },
        deadlineRfc3339: "2030-12-31T23:59:59Z",
        allowedTools: ["travel.book_hotel"],
        settlementRail: "stripe_connect",
      }),
    ).resolves.toMatchObject({
      intent_id: "550e8400-e29b-41d4-a716-446655440000",
    });
    expect(create).toHaveBeenCalledTimes(1);
  });
});

describe("PaybondSpendGuard", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("guards a tool after spend authorization allows", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    vi.spyOn(harbor, "verifyCapability").mockResolvedValue({
      allow: true,
      auditId: "550e8400-e29b-41d4-a716-446655440001",
      tenant: "tenant-a",
      intentId,
    });
    const guard = new PaybondSpendGuard({ harbor, intentId, capabilityToken: "cap-token" });
    const tool = vi.fn(async (city: string) => ({ city }));
    await expect(
      guard.guardTool(
        { operation: "travel.book_hotel", requestedSpendCents: 20_000 },
        tool,
      )("NYC"),
    ).resolves.toEqual({ city: "NYC" });
    expect(tool).toHaveBeenCalledWith("NYC");
  });

  it("does not call the tool when spend authorization denies", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    vi.spyOn(harbor, "verifyCapability").mockResolvedValue({
      allow: false,
      auditId: "550e8400-e29b-41d4-a716-446655440001",
      tenant: "tenant-a",
      intentId,
      code: "policy_mismatch",
      message: "budget exceeded",
    });
    const guard = new PaybondSpendGuard({ harbor, intentId, capabilityToken: "cap-token" });
    const tool = vi.fn(async () => "ok");
    await expect(
      guard.guardTool({ operation: "travel.book_hotel" }, tool)(),
    ).rejects.toBeInstanceOf(PaybondSpendDeniedError);
    expect(tool).not.toHaveBeenCalled();
  });

  it("exports runtime-neutral guard aliases", () => {
    expect(paybondAgentToolSpendGuard).toBe(guardTool);
    expect(paybondRuntimeNeutralToolSpendGuard).toBe(guardTool);
  });

  it("adapts generic runtime tool-call objects", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    const verify = vi.spyOn(harbor, "verifyCapability").mockResolvedValue({
      allow: true,
      auditId: "550e8400-e29b-41d4-a716-446655440001",
      tenant: "tenant-a",
      intentId,
    });
    const execute = vi.fn(async (call: { name: string; spend: number; city: string }) => ({
      confirmation: `demo-${call.city}`,
    }));
    const run = paybondRuntimeToolCallAdapter({
      source: { harbor, intentId, capabilityToken: "cap-token" },
      operation: (call: { name: string }) => call.name,
      requestedSpendCents: (call: { spend: number }) => call.spend,
      execute,
    });

    await expect(
      run({ name: "travel.book_hotel", spend: 20_000, city: "NYC" }),
    ).resolves.toEqual({ confirmation: "demo-NYC" });
    expect(verify).toHaveBeenCalledWith({
      intentId,
      token: "cap-token",
      operation: "travel.book_hotel",
      requestedSpendCents: 20_000,
    });
    expect(execute).toHaveBeenCalledOnce();
  });

  it("lets runtime adapters map denial to framework-specific output", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const harbor = new HarborClient("https://harbor.test", "tenant-a");
    vi.spyOn(harbor, "verifyCapability").mockResolvedValue({
      allow: false,
      auditId: "550e8400-e29b-41d4-a716-446655440001",
      tenant: "tenant-a",
      intentId,
      code: "policy_mismatch",
      message: "budget exceeded",
    });
    const execute = vi.fn(async () => ({ status: "ok" }));
    const run = paybondRuntimeToolCallAdapter({
      source: { harbor, intentId, capabilityToken: "cap-token" },
      operation: "travel.book_hotel",
      execute,
      onDeny: (result) => ({ status: "blocked", reason: result.message }),
    });

    await expect(run({})).resolves.toEqual({ status: "blocked", reason: "budget exceeded" });
    expect(execute).not.toHaveBeenCalled();
  });
});

describe("Paybond", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("opens with only an API key and uses the hosted gateway", async () => {
    const intent = "550e8400-e29b-41d4-a716-446655440000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input.toString();
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(
          "Bearer paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
        );
        if (url === "https://api.paybond.ai/v1/auth/principal") {
          return new Response(
            JSON.stringify({ tenant_id: "realm-z", environment: "sandbox" }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        expect(url).toBe("https://api.paybond.ai/verify");
        expect(headers.get("x-tenant-id")).toBe("realm-z");
        return new Response(
          JSON.stringify({
            allow: true,
            audit_id: "550e8400-e29b-41d4-a716-446655440001",
            tenant: "realm-z",
            intent_id: intent,
            code: null,
            message: null,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const paybond = await Paybond.open({
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
      expectedEnvironment: "sandbox",
    });
    expect(paybond.harbor.tenantId).toBe("realm-z");
    await expect(
      paybond.harbor.verifyCapability({
        intentId: intent,
        token: "Cg==",
        operation: "demo.tool",
      }),
    ).resolves.toMatchObject({ allow: true, tenant: "realm-z" });
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

  it("fetches the signed portfolio artifact", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        expect(input.toString()).toBe("https://gw.test/signal/v1/portfolio/signed-export");
        return new Response(
          JSON.stringify({
            schema_version: 1,
            artifact_version: "1",
            kind: "paybond.signal.portfolio_snapshot",
            tenant_id: "tenant-a",
            score_model_version: "1.0",
            scoring_model: "paybond.signal.v1",
            checkpoint_last_ledger_seq: 77,
            operators: [
              {
                operator_did: "did:example:alpha",
                receipt_version: "3",
                score: 801,
                ledger_watermark_seq: 77,
                receipt_message_digest_hex: "ab".repeat(32),
              },
            ],
            signing_algorithm: "ed25519-sha256-json-v1",
            message_digest_hex: "cd".repeat(32),
            signing_public_key_hex: "ef".repeat(32),
            signature_hex: "01".repeat(64),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );
    const c = new GatewaySignalClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(c.getSignedPortfolioArtifact()).resolves.toMatchObject({
      tenant_id: "tenant-a",
      checkpoint_last_ledger_seq: 77,
      operators: [
        {
          operator_did: "did:example:alpha",
          score: 801,
        },
      ],
    });
  });
});

describe("GatewayFraudClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("fetches a tenant-bound fraud assessment from review status", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        expect(input.toString()).toBe(
          "https://gw.test/signal/v1/operators/did%3Aexample%3Aalpha/review-status?score_version=1.0",
        );
        return new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "tenant-a",
            operator_did: "did:example:alpha",
            score_model_version: "1.0",
            review_state: "open",
            review_reasons: ["FRAUD_REVIEW"],
            fraud_signals: [
              {
                code: "REPEATED_FAILED_PREDICATES",
                severity: "high",
                category: "manipulation",
                window: "7d",
                evidence_count: 3,
                summary: "failed predicates clustered",
                affects_score: false,
                signal_source: "signal_model",
                first_seen_at: "2026-05-23T17:00:00Z",
                last_seen_at: "2026-05-23T18:00:00Z",
                evidence_binding_strength: "intent_bound",
                intent_refs: ["intent-1"],
              },
            ],
            fraud_assessment: {
              fraud_signal_version: "1.0.4",
              level: "high",
              highest_severity: "high",
              review_priority: "high",
              signal_count: 1,
              severe_signal_count: 1,
              summary: "level=high",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(c.getFraudAssessment("did:example:alpha", "1.0")).resolves.toMatchObject({
      tenant_id: "tenant-a",
      operator_did: "did:example:alpha",
      fraud_assessment: { level: "high" },
      fraud_signals: [{ signal_source: "signal_model", intent_refs: ["intent-1"] }],
    });
  });

  it("rejects fraud assessment tenant drift", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "other",
            operator_did: "did:example:alpha",
            score_model_version: "1.0",
            review_state: "open",
            review_reasons: [],
            fraud_signals: [],
            fraud_assessment: {
              fraud_signal_version: "1.0.4",
              level: "none",
              highest_severity: "none",
              review_priority: "normal",
              signal_count: 0,
              severe_signal_count: 0,
              summary: "level=none",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(c.getFraudAssessment("did:example:alpha")).rejects.toThrow(/fraud tenant mismatch/);
  });

  it("lists the fraud-filtered review queue", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        expect(input.toString()).toBe(
          "https://gw.test/signal/v1/review-queue?state=all&fraud_severity=high&limit=25&score_version=1.0",
        );
        return new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "tenant-a",
            score_model_version: "1.0",
            items: [],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(
      c.listFraudReviewQueue({ state: "all", severity: "high", limit: 25, scoreVersion: "1.0" }),
    ).resolves.toMatchObject({ tenant_id: "tenant-a", items: [] });
  });

  it("fetches tenant-bound fraud metrics", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        expect(input.toString()).toBe("https://gw.test/signal/v1/fraud/metrics?window=7d");
        return new Response(
          JSON.stringify({
            schema_version: 1,
            tenant_id: "tenant-a",
            score_model_version: "1.0",
            fraud_signal_version: "1.0.4",
            window: "7d",
            window_started_at: "2026-05-16T00:00:00Z",
            window_ended_at: "2026-05-23T00:00:00Z",
            generated_at: "2026-05-23T00:00:00Z",
            flagged_operator_count: 2,
            critical_signal_count: 1,
            high_signal_count: 1,
            elevated_signal_count: 0,
            review_open_count: 1,
            review_load_count: 1,
            reviewed_count: 2,
            labeled_outcome_count: 1,
            confirmed_risk_count: 1,
            false_positive_count: 0,
            needs_more_evidence_count: 1,
            review_precision_bps: 10000,
            false_positive_rate_bps: 0,
            confirmed_risk_rate_bps: 5000,
            labeled_coverage_bps: 5000,
            median_time_to_review_seconds: 300,
            refund_burst_count: 1,
            dispute_cluster_count: 0,
            replay_appeal_abuse_count: 0,
            critical_signal_hold_candidate_count: 1,
            provider_signal_count: 0,
            stale_label_gap_seconds: 900,
            stale_signal_family_label_gap_count: 0,
            backtest_summary: "precision_bps=10000",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(c.getFraudMetrics({ window: "7d" })).resolves.toMatchObject({
      tenant_id: "tenant-a",
      flagged_operator_count: 2,
    });
  });

  it("reads and updates the fraud release gate mode", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (init?.method === "PUT") {
        expect(url).toBe("https://gw.test/signal/v1/fraud/release-gate");
        expect(init.body).toBe(JSON.stringify({ mode: "critical_hold" }));
      } else {
        expect(url).toBe("https://gw.test/signal/v1/fraud/release-gate?score_version=1.0");
      }
      return new Response(
        JSON.stringify({
          schema_version: 1,
          tenant_id: "tenant-a",
          score_model_version: "1.0",
          fraud_signal_version: "1.0.7",
          generated_at: "2026-05-23T00:00:00Z",
          config: { mode: init?.method === "PUT" ? "critical_hold" : "review_only" },
          metrics_reliability: {
            reliable: true,
            reviewed_count: 10,
            labeled_outcome_count: 5,
            review_precision_bps: 9000,
            min_reviewed_count: 10,
            min_labeled_outcome_count: 5,
            min_review_precision_bps: 8000,
            reasons: [],
            summary: "reliable",
          },
        }),
        { status: init?.method === "PUT" ? 202 : 200, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });

    await expect(c.getFraudReleaseGateConfig("1.0")).resolves.toMatchObject({
      tenant_id: "tenant-a",
      config: { mode: "review_only" },
    });
    await expect(c.setFraudReleaseGateMode("critical_hold")).resolves.toMatchObject({
      tenant_id: "tenant-a",
      config: { mode: "critical_hold" },
    });
    await expect(c.setFraudReleaseGateMode("enforce_all")).rejects.toThrow(/release gate mode/);
  });

  it("records only supported fraud review event types", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(input.toString()).toBe("https://gw.test/signal/v1/operators/did%3Aexample%3Aalpha/review-events");
      expect(init?.method).toBe("POST");
      expect(init?.body).toBe(
        JSON.stringify({
          event_type: "review_outcome_recorded",
          review_outcome: "confirmed_risk",
          signal_code: "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
          intent_id: "00000000-0000-4000-8000-000000000123",
          provider_event_id: "evt_review_signal",
          summary: "Developer supplied appeal context",
        }),
      );
      return new Response(
        JSON.stringify({
          schema_version: 1,
          tenant_id: "tenant-a",
          operator_did: "did:example:alpha",
          score_model_version: "1.0",
          requested_event_type: "review_outcome_recorded",
          recorded_event_type: "review_outcome_recorded",
          review_outcome: "confirmed_risk",
          signal_code: "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
          intent_id: "00000000-0000-4000-8000-000000000123",
          provider_event_id: "evt_review_signal",
          accepted: true,
          friction: { band: "normal" },
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const c = new GatewayFraudClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(
      c.recordFraudReviewEvent("did:example:alpha", {
        eventType: "confirmed_risk",
        signalCode: "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
        intentId: "00000000-0000-4000-8000-000000000123",
        providerEventId: "evt_review_signal",
        summary: "Developer supplied appeal context",
      }),
    ).resolves.toMatchObject({
      tenant_id: "tenant-a",
      accepted: true,
      signal_code: "PROVIDER_STRIPE_EARLY_FRAUD_WARNING",
      intent_id: "00000000-0000-4000-8000-000000000123",
      provider_event_id: "evt_review_signal",
    });
    await expect(
      c.recordFraudReviewEvent("did:example:alpha", {
        eventType: "settlement_refunded",
        summary: "not a review event",
      }),
    ).rejects.toThrow(/fraud review eventType/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("GatewayA2AClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("fetches the published A2A agent card", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe("Bearer paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64));
        expect(input.toString()).toBe("https://gw.test/.well-known/agent-card.json");
        return new Response(
          JSON.stringify({
            name: "Paybond Protocol Trust Delegation",
            description: "discovery",
            supportedInterfaces: [],
            version: "2.0.0-preview",
            capabilities: {},
            defaultInputModes: ["application/json"],
            defaultOutputModes: ["application/json"],
            skills: [],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );
    const client = new GatewayA2AClient("https://gw.test", {
      staticGatewayBearerToken: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    await expect(client.getAgentCard()).resolves.toMatchObject({
      name: "Paybond Protocol Trust Delegation",
      version: "2.0.0-preview",
    });
  });

  it("fetches a specific task contract", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) =>
        new Response(
          JSON.stringify({
            schemaVersion: 1,
            kind: "paybond.a2a.settlement_task_contract_v1",
            id: "paybond.settlement.intent.create.v1",
            name: "Create delegated commercial intent",
            description: "desc",
            url: input.toString(),
            routeBindings: ["https://gw.test/harbor/intents"],
            requiredTrustArtifacts: ["paybond.agent_mandate_v1"],
            settlementPhases: ["authorize"],
            participants: [],
            inputModes: ["application/json"],
            outputModes: ["application/json"],
            inputFields: [],
            resultFields: [],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const client = new GatewayA2AClient("https://gw.test");
    await expect(client.getTaskContract("paybond.settlement.intent.create.v1")).resolves.toMatchObject({
      id: "paybond.settlement.intent.create.v1",
      routeBindings: ["https://gw.test/harbor/intents"],
    });
  });
});

describe("GatewayProtocolClient", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("imports a signed mandate with tenant binding", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe("Bearer gateway-token");
        expect(headers.get("x-tenant-id")).toBe("tenant-a");
        expect(input.toString()).toBe("https://gw.test/protocol/v2/mandates");
        expect(init?.body).toBe(
          JSON.stringify({
            signed_mandate: {
              schema_version: 1,
              kind: "paybond.agent_mandate_v1",
              authorization: {
                kind: "principal",
                tenant_id: "tenant-a",
                principal_subject: "user-123",
                principal_type: "user",
              },
              agent: { subject: "did:agent:test" },
              allowed_actions: ["intent.create"],
              allowed_tools: ["travel.book"],
              spend_ceiling: { amount_minor: 1000, currency: "usd" },
              settlement: { default_rail: "stripe_connect", allowed_rails: ["stripe_connect"] },
              constraint: { kind: "policy", id: "travel_hold" },
              expires_at: "2030-01-01T00:00:00Z",
              nonce: "nonce-123",
              human_presence_mode: "human_present",
              signing_algorithm: "ed25519-sha256-json-v1",
              message_digest_sha256_hex: "ab".repeat(32),
              signing_public_key_ed25519_hex: "cd".repeat(32),
              ed25519_signature_hex: "ef".repeat(64),
            },
            intent_id: "550e8400-e29b-41d4-a716-446655440000",
            transport_binding: {},
            recognition_proof: {
              key_id: "kid-1",
              issued_at: "2030-01-01T00:00:00Z",
              expires_at: "2030-01-01T00:05:00Z",
              nonce: "nonce-proof",
              purpose: "protocol.mandate.import",
              verifier_context: {
                tenant_id: "tenant-a",
                verifier_id: "paybond-gateway",
              },
              request_envelope: {
                method: "POST",
                path: "/protocol/v2/mandates",
                body_digest_sha256_hex: "01".repeat(32),
              },
            },
          }),
        );
        return new Response(
          JSON.stringify({
            valid: true,
            intent_id: "550e8400-e29b-41d4-a716-446655440000",
            mandate_digest_sha256_hex: "ab".repeat(32),
            mandate: {
              schema_version: 1,
              kind: "paybond.agent_mandate_v1",
              authorization: {
                kind: "principal",
                tenant_id: "tenant-a",
                principal_subject: "user-123",
                principal_type: "user",
              },
              agent: { subject: "did:agent:test" },
              allowed_actions: ["intent.create"],
              allowed_tools: ["travel.book"],
              spend_ceiling: { amount_minor: 1000, currency: "usd" },
              settlement: { default_rail: "stripe_connect", allowed_rails: ["stripe_connect"] },
              constraint: { kind: "policy", id: "travel_hold" },
              expires_at: "2030-01-01T00:00:00Z",
              nonce: "nonce-123",
              human_presence_mode: "human_present",
            },
            authorization_receipt: {
              schema_version: 1,
              kind: "paybond.protocol_authorization_receipt_v1",
              receipt_version: "1",
              receipt_id: "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
              issued_at: "2030-01-01T00:00:00Z",
              status: "authorized",
              intent_id: "550e8400-e29b-41d4-a716-446655440000",
              tenant_id: "tenant-a",
              verifier_id: "paybond-gateway",
              transport_binding: { source_protocol: "ap2" },
              mandate_digest_sha256_hex: "ab".repeat(32),
              imported_mandate_signing_public_key_ed25519_hex: "cd".repeat(32),
              authorization: {
                kind: "principal",
                tenant_id: "tenant-a",
                principal_subject: "user-123",
                principal_type: "user",
              },
              agent: { subject: "did:agent:test" },
              allowed_actions: ["intent.create"],
              allowed_tools: ["travel.book"],
              spend_ceiling: { amount_minor: 1000, currency: "usd" },
              settlement: { default_rail: "stripe_connect", allowed_rails: ["stripe_connect"] },
              constraint: { kind: "policy", id: "travel_hold" },
              expires_at: "2030-01-01T00:00:00Z",
              nonce: "nonce-123",
              human_presence_mode: "human_present",
              signing_algorithm: "ed25519-sha256-json-v1",
              message_digest_sha256_hex: "ef".repeat(32),
              signing_public_key_ed25519_hex: "01".repeat(32),
              ed25519_signature_hex: "02".repeat(64),
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const client = new GatewayProtocolClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "gateway-token",
    });
    await expect(
      client.importAgentMandateV1({
        signedMandate: {
          schema_version: 1,
          kind: "paybond.agent_mandate_v1",
          authorization: {
            kind: "principal",
            tenant_id: "tenant-a",
            principal_subject: "user-123",
            principal_type: "user",
          },
          agent: { subject: "did:agent:test" },
          allowed_actions: ["intent.create"],
          allowed_tools: ["travel.book"],
          spend_ceiling: { amount_minor: 1000, currency: "usd" },
          settlement: { default_rail: "stripe_connect", allowed_rails: ["stripe_connect"] },
          constraint: { kind: "policy", id: "travel_hold" },
          expires_at: "2030-01-01T00:00:00Z",
          nonce: "nonce-123",
          human_presence_mode: "human_present",
          signing_algorithm: "ed25519-sha256-json-v1",
          message_digest_sha256_hex: "ab".repeat(32),
          signing_public_key_ed25519_hex: "cd".repeat(32),
          ed25519_signature_hex: "ef".repeat(64),
        },
        intentId: "550e8400-e29b-41d4-a716-446655440000",
        recognitionProof: {
          key_id: "kid-1",
          issued_at: "2030-01-01T00:00:00Z",
          expires_at: "2030-01-01T00:05:00Z",
          nonce: "nonce-proof",
          purpose: "protocol.mandate.import",
          verifier_context: {
            tenant_id: "tenant-a",
            verifier_id: "paybond-gateway",
          },
          request_envelope: {
            method: "POST",
            path: "/protocol/v2/mandates",
            body_digest_sha256_hex: "01".repeat(32),
          },
        },
      }),
    ).resolves.toMatchObject({
      valid: true,
      authorization_receipt: {
        kind: "paybond.protocol_authorization_receipt_v1",
      },
    });
  });

  it("fetches a signed settlement receipt", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        expect(headers.get("x-tenant-id")).toBe("tenant-a");
        expect(input.toString()).toBe("https://gw.test/protocol/v2/receipts/550e8400-e29b-41d4-a716-446655440000");
        return new Response(
          JSON.stringify({
            schema_version: 1,
            kind: "paybond.protocol_settlement_receipt_v1",
            receipt_version: "1",
            receipt_id: "550e8400-e29b-41d4-a716-446655440000",
            issued_at: "2030-01-01T00:00:00Z",
            intent_id: "550e8400-e29b-41d4-a716-446655440000",
            tenant_id: "tenant-a",
            verifier_id: "paybond-gateway",
            transport_binding: { source_protocol: "ap2" },
            authorization_receipt_id: "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
            mandate_digest_sha256_hex: "ab".repeat(32),
            harbor_state: "released",
            predicate_passed: true,
            settlement_rail: "stripe_connect",
            settlement_mode: "managed",
            principal_did: "did:principal:alice",
            payee_did: "did:payee:hotel",
            currency: "usd",
            amount_cents: 250000,
            terminal_observed_at: "2030-01-01T00:00:00Z",
            signing_algorithm: "ed25519-sha256-json-v1",
            message_digest_sha256_hex: "ef".repeat(32),
            signing_public_key_ed25519_hex: "01".repeat(32),
            ed25519_signature_hex: "02".repeat(64),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const client = new GatewayProtocolClient("https://gw.test", "tenant-a");
    await expect(client.getSettlementReceiptV1("550e8400-e29b-41d4-a716-446655440000")).resolves.toMatchObject({
      kind: "paybond.protocol_settlement_receipt_v1",
      harbor_state: "released",
    });
  });

  it("surfaces ProtocolHttpError for failed receipt verification", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            error: "protocol_binding_mismatch",
            message: "harbor mandate digest does not match the stored gateway import binding",
          }),
          { status: 409, headers: { "content-type": "application/json" } },
        )),
    );
    const client = new GatewayProtocolClient("https://gw.test", "tenant-a");
    try {
      await client.verifyProtocolReceiptV1({ kind: "bad" });
      expect.fail("expected protocol receipt verification to fail");
    } catch (err) {
      expect(err).toBeInstanceOf(ProtocolHttpError);
      const protocolErr = err as ProtocolHttpError;
      expect(protocolErr.errorCode).toBe("protocol_binding_mismatch");
      expect(protocolErr.errorMessage).toMatch(/harbor mandate digest/);
      expect(protocolErr.message).toContain("protocol_binding_mismatch");
    }
  });

  it("parses explicit protocol gateway error envelopes", () => {
    const cases = [
      "unregistered_key",
      "revoked_key",
      "mandate_agent_key_mismatch",
      "protocol_binding_mismatch",
    ] as const;

    for (const code of cases) {
      const err = new ProtocolHttpError("protocol failure", {
        statusCode: 409,
        url: "https://gw.test/protocol/v2/mandates",
        bodyText: JSON.stringify({
          error: code,
          message: `${code} detail`,
        }),
      });
      expect(err.errorCode).toBe(code);
      expect(err.errorMessage).toBe(`${code} detail`);
    }
  });

  it("creates Harbor intents through the gateway with a recognition proof header", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        expect(input.toString()).toBe("https://gw.test/harbor/intents");
        const headers = new Headers(init?.headers);
        expect(headers.get("x-tenant-id")).toBe("tenant-a");
        expect(headers.get("idempotency-key")).toBe("intent:intent-123");
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeTruthy();
        expect(init?.body).toBe(
          JSON.stringify({
            intent_id: "intent-123",
            principal_did: "did:web:example.com#principal",
          }),
        );
        return new Response(
          JSON.stringify({
            intent_id: "intent-123",
            state: "open",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }),
    );

    const client = new GatewayProtocolClient("https://gw.test", "tenant-a", {
      staticGatewayBearerToken: "gateway-token",
    });
    await expect(
      client.createHarborIntent({
        body: {
          intent_id: "intent-123",
          principal_did: "did:web:example.com#principal",
        },
        recognitionProof: {
          key_id: "kid-1",
          issued_at: "2030-01-01T00:00:00Z",
          expires_at: "2030-01-01T00:05:00Z",
          nonce: "nonce-proof",
          purpose: "harbor.intent.create",
          verifier_context: {
            tenant_id: "tenant-a",
            verifier_id: "paybond-gateway",
          },
          request_envelope: {
            method: "POST",
            path: "/harbor/intents",
            body_digest_sha256_hex: "01".repeat(32),
          },
        },
        idempotencyKey: "intent:intent-123",
      }),
    ).resolves.toMatchObject({
      intent_id: "intent-123",
      state: "open",
    });
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
            environment: "sandbox",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const session = await ServiceAccountSignalSession.open({
      gatewayBaseUrl: "https://gw.test",
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
      expectedEnvironment: "sandbox",
    });
    expect(session.signal.tenantId).toBe("realm-z");
  });
});

describe("ServiceAccountFraudSession", () => {
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
    const session = await ServiceAccountFraudSession.open({
      gatewayBaseUrl: "https://gw.test",
      apiKey: "paybond_sk_" + "a".repeat(32) + "_" + "b".repeat(64),
    });
    expect(session.fraud.tenantId).toBe("realm-z");
  });
});
