import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PaybondMCPServer, formatMcpStdioFrame, settingsFromEnv } from "../src/mcp-server.js";

const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
};

function apiKey(): string {
  return `paybond_sk_${"a".repeat(32)}_${"b".repeat(64)}`;
}

describe("PaybondMCPServer", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("exposes gateway-first mutation tools even when harbor URL is absent", () => {
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const tools = server.listTools();
    const names = new Set(tools.map((tool) => String(tool.name)));
    const toolByName = new Map(tools.map((tool) => [String(tool.name), tool]));
    expect(names.has("paybond_get_a2a_agent_card")).toBe(true);
    expect(names.has("paybond_get_principal")).toBe(true);
    expect(names.has("paybond_get_signed_portfolio_artifact")).toBe(true);
    expect(names.has("paybond_get_fraud_assessment")).toBe(true);
    expect(names.has("paybond_get_fraud_metrics")).toBe(true);
    expect(names.has("paybond_verify_agent_mandate_v1")).toBe(true);
    expect(names.has("paybond_import_agent_mandate_v1")).toBe(true);
    expect(names.has("paybond_get_settlement_receipt_v1")).toBe(true);
    expect(names.has("paybond_verify_protocol_receipt_v1")).toBe(true);
    expect(names.has("paybond_authorize_agent_spend")).toBe(true);
    expect(names.has("paybond_bootstrap_sandbox_guardrail")).toBe(true);
    expect(names.has("paybond_submit_sandbox_guardrail_evidence")).toBe(true);
    expect(names.has("paybond_create_intent")).toBe(true);
    expect(names.has("paybond_create_spend_intent")).toBe(true);
    expect(names.has("paybond_submit_evidence")).toBe(true);
    expect(names.has("paybond_submit_spend_evidence")).toBe(true);
    expect(names.has("paybond_create_intent_legacy")).toBe(false);
    const assertSpendControlTool = (
      name: string,
      expected: {
        title: string;
        destructiveHint?: boolean;
        descriptionFragments: string[];
        outputProperties: string[];
      },
    ): void => {
      const tool = toolByName.get(name);
      expect(tool?.title, name).toBe(expected.title);
      for (const fragment of expected.descriptionFragments) {
        expect(tool?.description, name).toEqual(expect.stringContaining(fragment));
      }
      expect(tool?.annotations, name).toEqual(
        expect.objectContaining({
          title: expected.title,
          readOnlyHint: false,
          destructiveHint: expected.destructiveHint ?? false,
          idempotentHint: false,
          openWorldHint: true,
        }),
      );
      expect(tool?.outputSchema, name).toEqual(
        expect.objectContaining({
          type: "object",
          properties: expect.any(Object),
        }),
      );
      const properties = (tool?.outputSchema as { properties?: Record<string, unknown> } | undefined)?.properties;
      for (const property of expected.outputProperties) {
        expect(properties, `${name}.${property}`).toHaveProperty(property);
      }
    };

    const authorize = toolByName.get("paybond_authorize_agent_spend");
    expect(authorize?.title).toBe("Authorize Agent Spend");
    expect(authorize?.description).toContain("Use this when");
    expect(authorize?.description).toContain("Do not use this for");
    expect(authorize?.annotations).toMatchObject({
      title: "Authorize Agent Spend",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    });
    expect(authorize?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        allow: { type: "boolean" },
        tenant: { type: "string" },
        intent_id: { type: "string" },
      },
    });
    expect(toolByName.get("paybond_create_spend_intent")).toMatchObject({
      title: "Create Spend Intent",
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
      },
      outputSchema: {
        type: "object",
        properties: {
          intent_id: { type: "string" },
          capability_token: { type: "string" },
        },
      },
    });
    expect(toolByName.get("paybond_fund_intent")).toMatchObject({
      title: "Fund Intent",
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
    });
    expect(toolByName.get("paybond_get_principal")).toMatchObject({
      annotations: {
        readOnlyHint: true,
        openWorldHint: false,
      },
    });
    expect(toolByName.get("paybond_bootstrap_sandbox_guardrail")?.description).toContain("sandbox-only");
    for (const expected of [
      {
        name: "paybond_verify_capability",
        title: "Verify Paybond Capability",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["allow", "tenant", "intent_id", "audit_id"],
      },
      {
        name: "paybond_authorize_agent_spend",
        title: "Authorize Agent Spend",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["allow", "tenant", "intent_id", "audit_id"],
      },
      {
        name: "paybond_bootstrap_sandbox_guardrail",
        title: "Bootstrap Sandbox Guardrail",
        descriptionFragments: ["Use this when", "sandbox-only", "Do not use this"],
        outputProperties: [
          "tenant_id",
          "intent_id",
          "capability_token",
          "operation",
          "requested_spend_cents",
          "sandbox_lifecycle_status",
        ],
      },
      {
        name: "paybond_submit_sandbox_guardrail_evidence",
        title: "Submit Sandbox Guardrail Evidence",
        descriptionFragments: ["Use this when", "sandbox guardrail intent", "Do not use this"],
        outputProperties: [
          "tenant_id",
          "intent_id",
          "operation",
          "requested_spend_cents",
          "sandbox_lifecycle_status",
          "predicate_passed",
        ],
      },
      {
        name: "paybond_create_spend_intent",
        title: "Create Spend Intent",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["intent_id", "state", "capability_token"],
      },
      {
        name: "paybond_fund_intent",
        title: "Fund Intent",
        destructiveHint: true,
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["intent_id", "state", "capability_token"],
      },
      {
        name: "paybond_submit_spend_evidence",
        title: "Submit Spend Evidence",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["intent_id", "state", "evidence_id"],
      },
    ]) {
      assertSpendControlTool(expected.name, expected);
    }
  });

  it("returns enriched initialize serverInfo while keeping the negotiated protocol", async () => {
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });

    const response = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    });

    expect(response?.result).toMatchObject({
      protocolVersion: "2025-11-25",
      serverInfo: {
        name: "Paybond MCP",
        title: "Paybond MCP",
        version: packageJson.version,
        description: expect.stringContaining("agent spend controls"),
        websiteUrl: "https://paybond.ai",
      },
    });
  });

  it("loads PAYBOND_API_KEY from the local env file when process env is absent", () => {
    const cwd = mkdtempSync(join(tmpdir(), "paybond-mcp-"));
    const envFile = join(cwd, ".env.local");
    writeFileSync(envFile, `PAYBOND_API_KEY=${apiKey()}\n`, "utf8");

    expect(settingsFromEnv({ PAYBOND_ENV_FILE: envFile })).toMatchObject({
      apiKey: apiKey(),
      gatewayBaseUrl: "https://api.paybond.ai",
    });
  });

  it("accepts PAYBOND_GATEWAY_URL as the registry-facing gateway override", () => {
    expect(
      settingsFromEnv({
        PAYBOND_API_KEY: apiKey(),
        PAYBOND_GATEWAY_URL: "https://gateway.registry.test",
        PAYBOND_GATEWAY_BASE_URL: "https://gateway.legacy.test",
      }),
    ).toMatchObject({
      gatewayBaseUrl: "https://gateway.registry.test",
    });
  });

  it("returns gateway principal through the MCP tool", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(
          JSON.stringify({
            tenant_id: "tenant-a",
            roles: ["operator"],
            subject: "service-account-1",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_get_principal");
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      roles: ["operator"],
    });
  });

  it("returns the published A2A agent card through the MCP tool", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.endsWith("/.well-known/agent-card.json")) {
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
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_get_a2a_agent_card");
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      name: "Paybond Protocol Trust Delegation",
      version: "2.0.0-preview",
    });
  });

  it("returns the signed Signal portfolio artifact through the MCP tool", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/auth/principal")) {
          return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/signal/v1/portfolio/signed-export")) {
          return new Response(
            JSON.stringify({
              schema_version: 1,
              artifact_version: "1",
              kind: "paybond.signal.portfolio_snapshot",
              tenant_id: "tenant-a",
              score_model_version: "1.0",
              scoring_model: "paybond.signal.v1",
              checkpoint_last_ledger_seq: 55,
              operators: [],
              signing_algorithm: "ed25519-sha256-json-v1",
              message_digest_hex: "ab".repeat(32),
              signing_public_key_hex: "cd".repeat(32),
              signature_hex: "ef".repeat(64),
            }),
            { status: 200, headers: { "content-type": "application/json" } },
          );
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_get_signed_portfolio_artifact");
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      checkpoint_last_ledger_seq: 55,
      kind: "paybond.signal.portfolio_snapshot",
    });
  });

  it("returns the fraud assessment through the MCP tool", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/auth/principal")) {
          return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/signal/v1/operators/did%3Aexample%3Aalpha/review-status")) {
          return new Response(
            JSON.stringify({
              schema_version: 1,
              tenant_id: "tenant-a",
              operator_did: "did:example:alpha",
              score_model_version: "1.0",
              review_state: "open",
              review_reasons: ["FRAUD_REVIEW"],
              fraud_signals: [],
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
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_get_fraud_assessment", {
      operator_did: "did:example:alpha",
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      operator_did: "did:example:alpha",
      fraud_assessment: { level: "high" },
    });
  });

  it("returns fraud metrics through the MCP tool", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/auth/principal")) {
          return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/signal/v1/fraud/metrics?window=7d")) {
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
        }
        throw new Error(`unexpected url ${url}`);
      }),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_get_fraud_metrics", {
      window: "7d",
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      flagged_operator_count: 2,
    });
  });

  it("surfaces tool errors when verify tenant binding drifts", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = input.toString();
        if (url.endsWith("/v1/auth/principal")) {
          return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(
          JSON.stringify({
            allow: true,
            audit_id: "550e8400-e29b-41d4-a716-446655440001",
            tenant: "other-tenant",
            intent_id: intentId,
          }),
          {
            status: 200,
            headers: { "content-type": "application/json" },
          },
        );
      }),
    );
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_verify_capability", {
      intent_id: intentId,
      token: "cap-token",
      operation: "travel.book_hotel",
      requested_spend_cents: 100,
    });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toMatch(/tenant mismatch/);
  });

  it("bootstraps and submits sandbox guardrail evidence without caller tenant headers", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/v1/sandbox/guardrails/bootstrap")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(`Bearer ${apiKey()}`);
        expect(headers.get("x-tenant-id")).toBeNull();
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeNull();
        expect(headers.get("idempotency-key")).toBe("sandbox-bootstrap-1");
        expect(init?.body).toBe(
          JSON.stringify({
            operation: "vendor.lookup",
            requested_spend_cents: 125,
            currency: "USD",
            evidence_schema: { type: "object" },
            metadata: { demo: true },
          }),
        );
        return new Response(
          JSON.stringify({
            tenant_id: "tenant-a",
            intent_id: intentId,
            capability_token: "cap-sandbox",
            operation: "vendor.lookup",
            requested_spend_cents: 125,
            sandbox_lifecycle_status: "funded",
            settlement_rail: "simulator",
            settlement_mode: "sandbox",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.endsWith(`/v1/sandbox/guardrails/${intentId}/evidence`)) {
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(`Bearer ${apiKey()}`);
        expect(headers.get("x-tenant-id")).toBeNull();
        expect(headers.get("x-paybond-agent-recognition-proof")).toBeNull();
        expect(headers.get("idempotency-key")).toBe("sandbox-evidence-1");
        expect(init?.body).toBe(
          JSON.stringify({
            payload: { ok: true },
            artifacts: ["artifact-1"],
            operation: "vendor.lookup",
            requested_spend_cents: 125,
            metadata: { demo: true },
          }),
        );
        return new Response(
          JSON.stringify({
            tenant_id: "tenant-a",
            intent_id: intentId,
            capability_token: "cap-sandbox",
            operation: "vendor.lookup",
            requested_spend_cents: 125,
            sandbox_lifecycle_status: "evidence_submitted",
            settlement_rail: "simulator",
            settlement_mode: "sandbox",
            predicate_passed: true,
            payload_digest: "ab".repeat(32),
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected url ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });

    const bootstrap = await server.callTool("paybond_bootstrap_sandbox_guardrail", {
      operation: "vendor.lookup",
      requested_spend_cents: 125,
      currency: "USD",
      evidence_schema: { type: "object" },
      metadata: { demo: true },
      idempotency_key: "sandbox-bootstrap-1",
    });
    expect(bootstrap.isError).toBeUndefined();
    expect(bootstrap.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      intent_id: intentId,
      capability_token: "cap-sandbox",
      sandbox_lifecycle_status: "funded",
    });

    const evidence = await server.callTool("paybond_submit_sandbox_guardrail_evidence", {
      intent_id: intentId,
      payload: { ok: true },
      artifacts: ["artifact-1"],
      operation: "vendor.lookup",
      requested_spend_cents: 125,
      metadata: { demo: true },
      idempotency_key: "sandbox-evidence-1",
    });
    expect(evidence.isError).toBeUndefined();
    expect(evidence.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      intent_id: intentId,
      sandbox_lifecycle_status: "evidence_submitted",
      predicate_passed: true,
    });
  });

  it("defaults verifier context for recognition verification", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/protocol/v2/recognition/verify")) {
        expect(init?.body).toBe(
          JSON.stringify({
            proof: { nonce: "nonce-123" },
            expected_purpose: "harbor.policy.rollback",
            expected_verifier: {
              tenant_id: "tenant-a",
              verifier_id: "paybond-gateway",
            },
            expected_request: {
              method: "POST",
              path: "/harbor/policy/v1/rollback",
              body_digest_sha256_hex: "ab".repeat(32),
            },
          }),
        );
        return new Response(
          JSON.stringify({
            valid: true,
            proof: { nonce: "nonce-123" },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected url ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_verify_agent_recognition_proof_v1", {
      proof: { nonce: "nonce-123" },
      expected_purpose: "harbor.policy.rollback",
      expected_request: {
        method: "POST",
        path: "/harbor/policy/v1/rollback",
        body_digest_sha256_hex: "ab".repeat(32),
      },
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({ valid: true });
  });

  it("imports a protocol mandate through the MCP tool", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/protocol/v2/mandates")) {
        return new Response(
          JSON.stringify({
            valid: true,
            intent_id: "550e8400-e29b-41d4-a716-446655440000",
            mandate_digest_sha256_hex: "ab".repeat(32),
            mandate: {
              authorization: { tenant_id: "tenant-a" },
            },
            authorization_receipt: {
              kind: "paybond.protocol_authorization_receipt_v1",
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected url ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_import_agent_mandate_v1", {
      signed_mandate: { kind: "paybond.agent_mandate_v1" },
      intent_id: "550e8400-e29b-41d4-a716-446655440000",
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
          body_digest_sha256_hex: "ab".repeat(32),
        },
      },
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      valid: true,
      authorization_receipt: { kind: "paybond.protocol_authorization_receipt_v1" },
    });
  });

  it("surfaces explicit protocol error codes through MCP tool failures", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/protocol/v2/mandates")) {
        return new Response(
          JSON.stringify({
            error: "mandate_agent_key_mismatch",
            message: "mandate.agent.key_id must match recognition_proof.key_id",
          }),
          { status: 409, headers: { "content-type": "application/json" } },
        );
      }
      throw new Error(`unexpected url ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_import_agent_mandate_v1", {
      signed_mandate: { kind: "paybond.agent_mandate_v1" },
      intent_id: "550e8400-e29b-41d4-a716-446655440000",
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
          body_digest_sha256_hex: "ab".repeat(32),
        },
      },
    });
    expect(result.isError).toBe(true);
    expect(result.content[0]?.text).toContain("mandate_agent_key_mismatch");
  });

  it("creates intents through the gateway harbor path using a recognition proof", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url === "https://gateway.test/harbor/intents") {
        const headers = new Headers(init?.headers);
        expect(headers.get("authorization")).toBe(`Bearer ${apiKey()}`);
        expect(headers.get("x-tenant-id")).toBe("tenant-a");
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
      }
      throw new Error(`unexpected url ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const result = await server.callTool("paybond_create_intent", {
      body: {
        intent_id: "intent-123",
        principal_did: "did:web:example.com#principal",
      },
      recognition_proof: {
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
          body_digest_sha256_hex: "ab".repeat(32),
        },
      },
      idempotency_key: "intent:intent-123",
    });
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toEqual({
      intent_id: "intent-123",
      state: "open",
    });
  });

  it("readonly tool policy limits exposed tools", () => {
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
      toolPolicy: { policy: "readonly", allowlist: [] },
    });
    const names = new Set(server.listTools().map((tool) => String(tool.name)));
    expect(names.has("paybond_get_principal")).toBe(true);
    expect(names.has("paybond_create_spend_intent")).toBe(false);
  });

  it("stdio responses use MCP Content-Length framing", async () => {
    const frame = formatMcpStdioFrame({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
    expect(frame.startsWith("Content-Length:")).toBe(true);
    expect(frame).toContain("\r\n\r\n");
    expect(frame).not.toMatch(/^Starting /m);
    const body = frame.split("\r\n\r\n", 2)[1];
    expect(JSON.parse(body ?? "{}")).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
  });
});
