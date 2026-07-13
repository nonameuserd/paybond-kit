import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentReceiptV1 } from "../src/agent-receipt.js";
import { PaybondMCPServer, formatMcpNdjsonFrame, formatMcpStdioFrame, settingsFromEnv } from "../src/mcp-server.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_RECEIPT_PATH = join(
  MODULE_DIR,
  "../../agent-receipt/conformance/signed-action-receipt-v1.json",
);

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
    expect(names.has("paybond_list_audit_exports")).toBe(true);
    expect(names.has("paybond_get_audit_export")).toBe(true);
    expect(names.has("paybond_verify_agent_mandate_v1")).toBe(true);
    expect(names.has("paybond_import_agent_mandate_v1")).toBe(true);
    expect(names.has("paybond_get_settlement_receipt_v1")).toBe(true);
    expect(names.has("paybond_verify_protocol_receipt_v1")).toBe(true);
    expect(names.has("paybond_get_agent_receipt_v1")).toBe(true);
    expect(names.has("paybond_verify_agent_receipt_v1")).toBe(true);
    expect(names.has("paybond_authorize_agent_spend")).toBe(true);
    expect(names.has("paybond_get_budget_remaining")).toBe(true);
    expect(names.has("paybond_explain_policy")).toBe(true);
    expect(names.has("paybond_bootstrap_sandbox_guardrail")).toBe(true);
    expect(names.has("paybond_submit_sandbox_guardrail_evidence")).toBe(true);
    expect(names.has("paybond_validate_completion_evidence")).toBe(true);
    expect(names.has("paybond_create_intent")).toBe(true);
    expect(names.has("paybond_create_spend_intent")).toBe(true);
    expect(names.has("paybond_submit_evidence")).toBe(true);
    expect(names.has("paybond_submit_spend_evidence")).toBe(true);
    expect(names.has("paybond_create_intent_legacy")).toBe(false);
    expect(names.has("paybond_fund_intent")).toBe(false);
    expect(names.has("paybond_confirm_settlement")).toBe(false);
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
        remaining_cents: { type: "integer" },
        reason_codes: { type: "array", items: { type: "string" } },
        message: { type: "string" },
        decision_id: { type: "string" },
        approval_request_id: { type: "string" },
      },
    });
    expect(toolByName.get("paybond_get_budget_remaining")).toMatchObject({
      title: "Get Budget Remaining",
      annotations: {
        readOnlyHint: true,
        openWorldHint: false,
      },
      outputSchema: {
        type: "object",
        properties: {
          remaining_cents: { type: "integer" },
          spend_scope: expect.objectContaining({ type: "object" }),
          policy_version: { type: "integer" },
        },
      },
    });
    expect(toolByName.get("paybond_explain_policy")).toMatchObject({
      title: "Explain Spend Policy",
      annotations: {
        readOnlyHint: true,
        openWorldHint: false,
      },
      outputSchema: {
        type: "object",
        properties: {
          outcome: { type: "string" },
          reason_codes: { type: "array", items: { type: "string" } },
          explanation: { type: "string" },
          remaining_cents: { type: "integer" },
        },
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
    const fraudAssessment = toolByName.get("paybond_get_fraud_assessment");
    expect(fraudAssessment?.title).toBe("Get Fraud Assessment");
    expect(fraudAssessment?.description).toContain("Use this when");
    expect(fraudAssessment?.description).toContain("did:web:vendor.example#booker-agent");
    expect(fraudAssessment?.description).toContain("paybond_get_fraud_metrics");
    expect(fraudAssessment?.description).toContain("paybond_get_intent");
    expect(fraudAssessment?.description).toContain("Do not use this");
    expect(fraudAssessment?.annotations).toMatchObject({
      title: "Get Fraud Assessment",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(fraudAssessment?.inputSchema).toMatchObject({
      type: "object",
      required: ["operator_did"],
      properties: {
        operator_did: {
          type: "string",
          description: expect.stringContaining("did:web:vendor.example#booker-agent"),
          examples: expect.arrayContaining(["did:web:vendor.example#booker-agent"]),
        },
        score_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
      },
    });
    expect(fraudAssessment?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: expect.stringContaining("tenant-a"),
          examples: ["tenant-a"],
        },
        operator_did: {
          type: "string",
          description: expect.stringContaining("Operator DID"),
          examples: ["did:web:vendor.example#booker-agent"],
        },
        fraud_assessment: {
          type: "object",
          description: expect.stringContaining("level"),
          examples: expect.arrayContaining([
            expect.objectContaining({ level: "high", signal_count: 1 }),
          ]),
        },
      },
    });

    const portfolioSummary = toolByName.get("paybond_get_portfolio_summary");
    expect(portfolioSummary?.title).toBe("Get Portfolio Summary");
    expect(portfolioSummary?.description).toContain("Use this when");
    expect(portfolioSummary?.description).toContain("paybond_get_signed_portfolio_artifact");
    expect(portfolioSummary?.description).toContain("paybond_get_reputation_receipt");
    expect(portfolioSummary?.description).toContain("Do not use this");
    expect(portfolioSummary?.description).toContain("no side effects");
    expect(portfolioSummary?.annotations).toMatchObject({
      title: "Get Portfolio Summary",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(portfolioSummary?.inputSchema).toMatchObject({
      type: "object",
      properties: {
        score_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
      },
    });
    expect(portfolioSummary?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: expect.stringContaining("tenant-a"),
          examples: ["tenant-a"],
        },
        score_model_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
        operator_count: { type: "integer" },
        average_score: { type: "number" },
        operators_under_review: { type: "integer" },
      },
    });
    expect(
      (portfolioSummary?.outputSchema as { properties?: Record<string, unknown> } | undefined)
        ?.properties,
    ).not.toHaveProperty("operators");

    const verifyProtocolReceipt = toolByName.get("paybond_verify_protocol_receipt_v1");
    expect(verifyProtocolReceipt?.title).toBe("Verify Protocol Receipt");
    expect(verifyProtocolReceipt?.description).toContain("Use this when");
    expect(verifyProtocolReceipt?.description).toContain("paybond_verify_agent_mandate_v1");
    expect(verifyProtocolReceipt?.description).toContain("paybond_verify_capability");
    expect(verifyProtocolReceipt?.description).toContain("paybond_get_settlement_receipt_v1");
    expect(verifyProtocolReceipt?.description).toContain("Do not use this");
    expect(verifyProtocolReceipt?.description).toContain("side-effect free");
    expect(verifyProtocolReceipt?.annotations).toMatchObject({
      title: "Verify Protocol Receipt",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(verifyProtocolReceipt?.inputSchema).toMatchObject({
      type: "object",
      required: ["receipt"],
      properties: {
        receipt: {
          type: "object",
          description: expect.stringContaining("paybond.protocol_authorization_receipt_v1"),
        },
      },
    });
    expect(
      String(
        (
          verifyProtocolReceipt?.inputSchema as {
            properties?: { receipt?: { description?: string } };
          }
        )?.properties?.receipt?.description,
      ),
    ).toContain("paybond.protocol_settlement_receipt_v1");
    expect(verifyProtocolReceipt?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        valid: {
          type: "boolean",
          description: expect.stringContaining("Ed25519"),
        },
        kind: {
          type: "string",
          description: expect.stringContaining("paybond.protocol_authorization_receipt_v1"),
        },
        receipt_id: { type: "string" },
        tenant_id: { type: "string" },
        receipt: { type: "object" },
      },
    });

    const fraudMetrics = toolByName.get("paybond_get_fraud_metrics");
    expect(fraudMetrics?.title).toBe("Get Fraud Metrics");
    expect(fraudMetrics?.description).toContain("Use this when");
    expect(fraudMetrics?.description).toContain("paybond_get_fraud_assessment");
    expect(fraudMetrics?.description).toContain("Do not use this");
    expect(fraudMetrics?.description).toContain("24h");
    expect(fraudMetrics?.description).toContain("no side effects");
    expect(fraudMetrics?.annotations).toMatchObject({
      title: "Get Fraud Metrics",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(fraudMetrics?.inputSchema).toMatchObject({
      type: "object",
      properties: {
        window: {
          type: "string",
          enum: ["24h", "7d", "30d"],
          description: expect.stringContaining("24h"),
          examples: expect.arrayContaining(["24h", "7d", "30d"]),
        },
        score_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
      },
    });
    expect(fraudMetrics?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: expect.stringContaining("tenant-a"),
        },
        window: {
          type: "string",
          description: expect.stringContaining("24h"),
        },
        flagged_operator_count: {
          type: "integer",
          description: expect.stringContaining("Operators"),
        },
        critical_signal_count: {
          type: "integer",
          description: expect.stringContaining("critical"),
        },
        backtest_summary: {
          type: "string",
          description: expect.stringContaining("backtest"),
        },
      },
    });

    const reputationReceipt = toolByName.get("paybond_get_reputation_receipt");
    expect(reputationReceipt?.title).toBe("Get Reputation Receipt");
    expect(reputationReceipt?.description).toContain("Use this when");
    expect(reputationReceipt?.description).toContain("paybond_get_portfolio_summary");
    expect(reputationReceipt?.description).toContain("paybond_get_signed_portfolio_artifact");
    expect(reputationReceipt?.description).toContain("paybond_get_fraud_assessment");
    expect(reputationReceipt?.description).toContain("Do not use this");
    expect(reputationReceipt?.description).toContain("returns null");
    expect(reputationReceipt?.annotations).toMatchObject({
      title: "Get Reputation Receipt",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(reputationReceipt?.inputSchema).toMatchObject({
      type: "object",
      required: ["operator_did"],
      properties: {
        operator_did: {
          type: "string",
          description: expect.stringContaining("did:web:vendor.example#booker-agent"),
          examples: expect.arrayContaining(["did:web:vendor.example#booker-agent"]),
        },
        score_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
      },
    });
    expect(reputationReceipt?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        schema_version: { type: "integer" },
        updated_at: { type: "string" },
        receipt: {
          type: "object",
          description: expect.stringContaining("signature_hex"),
        },
      },
    });

    expect(toolByName.get("paybond_get_principal")).toMatchObject({
      title: "Get Paybond Principal",
      description: expect.stringContaining("Use this when"),
      annotations: {
        title: "Get Paybond Principal",
        readOnlyHint: true,
        openWorldHint: false,
      },
    });
    const principal = toolByName.get("paybond_get_principal");
    expect(principal?.description).toContain("Call early as a prerequisite");
    expect(principal?.description).toContain("Not required before every later call");
    expect(principal?.description).toContain(
      "use paybond_get_intent instead when you have an intent_id",
    );
    expect(principal?.description).toContain(
      "Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead",
    );
    expect(principal?.description).toContain("Do not use this when");
    expect(principal?.description).toContain("no side effects");
    expect(principal?.description).toContain("read-only");
    expect(principal?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        tenant_id: {
          type: "string",
          description: expect.stringContaining("Tenant bound"),
        },
        subject: {
          type: "string",
          description: expect.stringContaining("service-account"),
          examples: ["service-account-1"],
        },
        roles: {
          type: "array",
          description: expect.stringContaining("RBAC"),
          examples: [["operator"]],
        },
      },
    });

    const signedPortfolio = toolByName.get("paybond_get_signed_portfolio_artifact");
    expect(signedPortfolio?.title).toBe("Get Signed Portfolio Artifact");
    expect(signedPortfolio?.description).toContain("Use this when");
    expect(signedPortfolio?.description).toContain("paybond_get_portfolio_summary");
    expect(signedPortfolio?.description).toContain("paybond_get_reputation_receipt");
    expect(signedPortfolio?.description).toContain("paybond_get_fraud_assessment");
    expect(signedPortfolio?.description).toContain("Do not use this");
    expect(signedPortfolio?.description).toContain("no side effects");
    expect(signedPortfolio?.annotations).toMatchObject({
      title: "Get Signed Portfolio Artifact",
      readOnlyHint: true,
      openWorldHint: false,
    });
    expect(signedPortfolio?.inputSchema).toMatchObject({
      type: "object",
      properties: {
        score_version: {
          type: "string",
          description: expect.stringContaining("1.0"),
          examples: ["1.0"],
        },
      },
    });
    expect(signedPortfolio?.outputSchema).toMatchObject({
      type: "object",
      properties: {
        kind: {
          type: "string",
          description: expect.stringContaining("paybond.signal.portfolio_snapshot"),
          examples: ["paybond.signal.portfolio_snapshot"],
        },
        tenant_id: {
          type: "string",
          description: expect.stringContaining("tenant-a"),
          examples: ["tenant-a"],
        },
        signature_hex: {
          type: "string",
          description: expect.stringContaining("Ed25519"),
        },
        checkpoint_last_ledger_seq: { type: "integer" },
      },
    });

    expect(toolByName.get("paybond_bootstrap_sandbox_guardrail")?.description).toContain("sandbox-only");
    for (const expected of [
      {
        name: "paybond_verify_capability",
        title: "Verify Paybond Capability",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: [
          "allow",
          "tenant",
          "intent_id",
          "audit_id",
          "remaining_cents",
          "reason_codes",
          "message",
          "decision_id",
          "approval_request_id",
        ],
      },
      {
        name: "paybond_authorize_agent_spend",
        title: "Authorize Agent Spend",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: [
          "allow",
          "tenant",
          "intent_id",
          "audit_id",
          "remaining_cents",
          "reason_codes",
          "message",
          "decision_id",
          "approval_request_id",
        ],
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
        name: "paybond_submit_spend_evidence",
        title: "Submit Spend Evidence",
        descriptionFragments: ["Use this when", "Do not use this"],
        outputProperties: ["intent_id", "state", "evidence_id"],
      },
    ]) {
      assertSpendControlTool(expected.name, expected);
    }
  });

  it("allowlist policy exposes live-money tool metadata", () => {
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
      toolPolicy: {
        policy: "allowlist",
        allowlist: ["paybond_fund_intent", "paybond_confirm_settlement"],
      },
    });
    const toolByName = new Map(server.listTools().map((tool) => [String(tool.name), tool]));
    expect(toolByName.get("paybond_fund_intent")).toMatchObject({
      title: "Fund Intent",
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
      },
    });
  });

  it("returns enriched initialize serverInfo while keeping the negotiated protocol", async () => {
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

  it("loads PAYBOND_API_KEY and gateway URL from the local env file when process env is absent", () => {
    const cwd = mkdtempSync(join(tmpdir(), "paybond-mcp-"));
    const envFile = join(cwd, ".env.local");
    writeFileSync(
      envFile,
      `PAYBOND_API_KEY=${apiKey()}\nPAYBOND_GATEWAY_BASE_URL=https://gateway.from-file.test\n`,
      "utf8",
    );

    expect(settingsFromEnv({ PAYBOND_ENV_FILE: envFile })).toMatchObject({
      apiKey: apiKey(),
      gatewayBaseUrl: "https://gateway.from-file.test",
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

  it("returns initialize without waiting on Gateway principal preload", async () => {
    let resolvePrincipal: ((value: Response) => void) | undefined;
    const principalPending = new Promise<Response>((resolve) => {
      resolvePrincipal = resolve;
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return principalPending;
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const initResponse = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    });
    expect(initResponse?.result).toBeDefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);

    resolvePrincipal?.(
      new Response(
        JSON.stringify({
          tenant_id: "tenant-a",
          roles: ["operator"],
          subject: "service-account-1",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
    );

    const result = await server.callTool("paybond_get_principal");
    expect(result.isError).toBeUndefined();
    expect(result.structuredContent).toMatchObject({
      tenant_id: "tenant-a",
      roles: ["operator"],
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("returns initialize even when principal preload fails", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("gateway unreachable");
    });
    vi.stubGlobal("fetch", fetchMock);

    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
      maxRetries: 1,
    });
    const initResponse = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    });
    expect(initResponse?.result).toMatchObject({
      protocolVersion: "2025-11-25",
      serverInfo: { name: "Paybond MCP" },
    });

    await vi.waitFor(() => {
      expect(fetchMock).toHaveBeenCalled();
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

  it("calls spend preflight for budget remaining and explain policy", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/v1/spend/preflight")) {
        const headers = new Headers(init?.headers);
        expect(headers.get("x-tenant-id")).toBe("tenant-a");
        const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>;
        expect(body.intent_id).toBe(intentId);
        expect(body.operation).toBe("tool.purchase");
        expect(body.requested_spend_cents).toBe(75000);
        expect(body.vendor_id).toBe("vendor-1");
        return new Response(
          JSON.stringify({
            classification: "hold",
            outcome: "approval_required",
            reason_codes: ["approval_threshold_exceeded"],
            remaining_cents: 25000,
            spend_scope: { scope_type: "tenant", scope_key: "" },
            policy_version: 3,
            explanation:
              "Requested spend is at or above the approval threshold and requires human approval.",
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

    const budget = await server.callTool("paybond_get_budget_remaining", {
      intent_id: intentId,
      operation: "tool.purchase",
      requested_spend_cents: 75000,
      vendor_id: "vendor-1",
    });
    expect(budget.isError).toBeUndefined();
    expect(budget.structuredContent).toEqual({
      remaining_cents: 25000,
      spend_scope: { scope_type: "tenant", scope_key: "" },
      policy_version: 3,
    });

    const explained = await server.callTool("paybond_explain_policy", {
      intent_id: intentId,
      operation: "tool.purchase",
      requested_spend_cents: 75000,
      vendor_id: "vendor-1",
    });
    expect(explained.isError).toBeUndefined();
    expect(explained.structuredContent).toEqual({
      outcome: "approval_required",
      reason_codes: ["approval_threshold_exceeded"],
      explanation:
        "Requested spend is at or above the approval threshold and requires human approval.",
      remaining_cents: 25000,
      approval_threshold_exceeded: true,
    });
    expect(fetchMock.mock.calls.filter(([input]) => String(input).endsWith("/v1/spend/preflight"))).toHaveLength(2);
  });

  it("does not cache capability tokens from authorize tool responses", async () => {
    const intentId = "550e8400-e29b-41d4-a716-446655440000";
    let verifyCallCount = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(JSON.stringify({ tenant_id: "tenant-a" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (url.endsWith("/verify")) {
        verifyCallCount += 1;
        const body = JSON.parse(String(init?.body ?? "{}")) as { token?: string };
        if (verifyCallCount === 1) {
          expect(body.token).toBe("cap-explicit");
        } else {
          throw new Error("unexpected second verify without explicit token");
        }
        return new Response(
          JSON.stringify({
            allow: true,
            tenant: "tenant-a",
            intent_id: intentId,
            audit_id: "audit-1",
            capability_token: "cap-poison",
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

    const first = await server.callTool("paybond_authorize_agent_spend", {
      intent_id: intentId,
      token: "cap-explicit",
      operation: "vendor.lookup",
    });
    expect(first.isError).toBeUndefined();

    const second = await server.callTool("paybond_authorize_agent_spend", {
      intent_id: intentId,
      operation: "vendor.lookup",
    });
    expect(second.isError).toBe(true);
    expect(second.content[0]?.text).toMatch(/unavailable or expired/);
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
      if (url.endsWith("/verify")) {
        expect(init?.body).toBe(
          JSON.stringify({
            intent_id: intentId,
            token: "cap-sandbox",
            operation: "vendor.lookup",
            requested_spend_cents: 125,
          }),
        );
        return new Response(
          JSON.stringify({
            allow: true,
            tenant: "tenant-a",
            intent_id: intentId,
            audit_id: "audit-1",
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
      capability_token: "[redacted]",
      sandbox_lifecycle_status: "funded",
    });

    const authorize = await server.callTool("paybond_authorize_agent_spend", {
      intent_id: intentId,
      operation: "vendor.lookup",
      requested_spend_cents: 125,
    });
    expect(authorize.isError).toBeUndefined();
    expect(authorize.structuredContent).toMatchObject({
      allow: true,
      intent_id: intentId,
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

  it("ignores caller-supplied expected_verifier for recognition verification", async () => {
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
      expected_verifier: {
        tenant_id: "tenant-evil",
        verifier_id: "attacker-controlled",
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
    expect(names.has("paybond_list_audit_exports")).toBe(true);
    expect(names.has("paybond_get_audit_export")).toBe(true);
    expect(names.has("paybond_get_budget_remaining")).toBe(true);
    expect(names.has("paybond_explain_policy")).toBe(true);
    expect(names.has("paybond_create_spend_intent")).toBe(false);
  });

  it("default spend-write policy blocks live-money tools", () => {
    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    const names = new Set(server.listTools().map((tool) => String(tool.name)));
    expect(names.has("paybond_create_spend_intent")).toBe(true);
    expect(names.has("paybond_fund_intent")).toBe(false);
    expect(names.has("paybond_confirm_settlement")).toBe(false);
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

  it("stdio responses can use newline-delimited JSON framing", () => {
    const frame = formatMcpNdjsonFrame({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
    expect(frame.endsWith("\n")).toBe(true);
    expect(frame.startsWith("Content-Length:")).toBe(false);
    expect(JSON.parse(frame.trim())).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: { ok: true },
    });
  });

  it("advertises agent receipt resource templates on initialize", async () => {
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

    const response = await server.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
    });

    expect(response?.result).toMatchObject({
      capabilities: {
        resources: {
          subscribe: false,
          listChanged: false,
        },
      },
    });
  });

  it("reads paybond://receipt/{id} via resources/read after local verification", async () => {
    const conformanceReceipt = JSON.parse(
      readFileSync(CONFORMANCE_RECEIPT_PATH, "utf8"),
    ) as AgentReceiptV1;
    const receiptId = conformanceReceipt.receipt_id;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(
          JSON.stringify({
            tenant_id: conformanceReceipt.tenant_id,
            roles: ["operator"],
            subject: "svc",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes(`/protocol/v2/agent-receipts/${receiptId}`)) {
        return new Response(JSON.stringify(conformanceReceipt), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize" });

    const templates = await server.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "resources/templates/list",
    });
    expect(templates?.result).toMatchObject({
      resourceTemplates: [
        expect.objectContaining({
          uriTemplate: "paybond://receipt/{receipt_id}",
        }),
      ],
    });

    const read = await server.handleMessage({
      jsonrpc: "2.0",
      id: 3,
      method: "resources/read",
      params: { uri: `paybond://receipt/${receiptId}` },
    });
    expect(read?.result).toMatchObject({
      contents: [
        expect.objectContaining({
          uri: `paybond://receipt/${receiptId}`,
          mimeType: "application/json",
          _meta: {
            verification: {
              valid: true,
              message_digest: conformanceReceipt.message_digest_sha256_hex,
            },
          },
        }),
      ],
    });
    const text = (read?.result as { contents?: Array<{ text?: string }> })?.contents?.[0]?.text;
    expect(JSON.parse(text ?? "{}")).toEqual(conformanceReceipt);
    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining(`/protocol/v2/agent-receipts/${receiptId}`),
      expect.any(Object),
    );
  });

  it("rejects tampered paybond://receipt/{id} resources before MCP handoff", async () => {
    const conformanceReceipt = JSON.parse(
      readFileSync(CONFORMANCE_RECEIPT_PATH, "utf8"),
    ) as AgentReceiptV1;
    const receiptId = conformanceReceipt.receipt_id;
    const tampered = structuredClone(conformanceReceipt);
    tampered.outcome.harbor_state = "released";

    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(
          JSON.stringify({
            tenant_id: conformanceReceipt.tenant_id,
            roles: ["operator"],
            subject: "svc",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes(`/protocol/v2/agent-receipts/${receiptId}`)) {
        return new Response(JSON.stringify(tampered), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });
    await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize" });

    const read = await server.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "resources/read",
      params: { uri: `paybond://receipt/${receiptId}` },
    });
    expect(read?.error).toMatchObject({
      code: -32000,
      message: expect.stringContaining("agent receipt verification failed"),
    });
    expect(read?.error?.message).toMatch(/message digest mismatch/);
    expect(read?.result).toBeUndefined();
  });

  it("exposes get/verify agent receipt tools", async () => {
    const conformanceReceipt = JSON.parse(
      readFileSync(CONFORMANCE_RECEIPT_PATH, "utf8"),
    ) as AgentReceiptV1;
    const receiptId = conformanceReceipt.receipt_id;
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/v1/auth/principal")) {
        return new Response(
          JSON.stringify({
            tenant_id: conformanceReceipt.tenant_id,
            roles: ["operator"],
            subject: "svc",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      }
      if (url.includes(`/protocol/v2/agent-receipts/${receiptId}`)) {
        return new Response(JSON.stringify(conformanceReceipt), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const server = new PaybondMCPServer({
      gatewayBaseUrl: "https://gateway.test",
      apiKey: apiKey(),
    });

    const getResult = await server.callTool("paybond_get_agent_receipt_v1", {
      receipt_id: receiptId,
    });
    expect(getResult.isError).toBeUndefined();
    expect(getResult.structuredContent).toMatchObject({
      receipt_id: receiptId,
      tenant_id: conformanceReceipt.tenant_id,
    });

    const verifyResult = await server.callTool("paybond_verify_agent_receipt_v1", {
      receipt: conformanceReceipt,
    });
    expect(verifyResult.isError).toBeUndefined();
    expect(verifyResult.structuredContent).toMatchObject({
      valid: true,
      kind: "paybond.agent_receipt_v1",
      receipt_id: receiptId,
      tenant_id: conformanceReceipt.tenant_id,
      validity_tier: "operational",
    });
  });
});
