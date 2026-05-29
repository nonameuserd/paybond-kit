#!/usr/bin/env node

import {
  GatewayAuthError,
  GatewayFraudClient,
  GatewaySignalClient,
  SignalHttpError,
  DEFAULT_PAYBOND_GATEWAY_BASE_URL,
} from "./index.js";

declare const process: {
  argv: string[];
  env: Record<string, string | undefined>;
  exitCode?: number;
  stdin: {
    setEncoding(encoding: string): void;
    on(event: "data", listener: (chunk: string) => void): void;
    on(event: "end", listener: () => void): void;
    resume(): void;
  };
  stdout: { write(chunk: string): boolean };
  stderr: { write(chunk: string): boolean };
};

declare const Buffer: {
  from(input: string, encoding?: string): {
    toString(encoding?: string): string;
  };
};

const SERVER_NAME = "Paybond MCP";
const SERVER_VERSION = "0.6.0";
const MCP_PROTOCOL_VERSION = "2025-11-25";
const DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal";
const DEFAULT_RECOGNITION_VERIFIER_ID = "paybond-gateway";
const agentRecognitionProofHeader = "x-paybond-agent-recognition-proof";

type JSONRPCID = string | number | null;

type JSONRPCRequest = {
  jsonrpc?: unknown;
  id?: JSONRPCID;
  method?: unknown;
  params?: unknown;
};

type JSONRPCResponse = {
  jsonrpc: "2.0";
  id: JSONRPCID;
  result?: unknown;
  error?: {
    code: number;
    message: string;
  };
};

type MCPToolDefinition = {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  call: (args: Record<string, unknown>) => Promise<Record<string, unknown> | null>;
};

type MCPCallToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

export type PaybondMCPSettings = {
  apiKey: string;
  gatewayBaseUrl?: string;
  principalPath?: string;
  maxRetries?: number;
};

class GatewayHTTPError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;
  readonly errorCode?: string;
  readonly errorMessage?: string;

  constructor(
    message: string,
    init: { statusCode: number; url: string; bodyText: string; errorCode?: string; errorMessage?: string },
  ) {
    super(message);
    this.name = "GatewayHTTPError";
    this.statusCode = init.statusCode;
    this.url = init.url;
    this.bodyText = init.bodyText;
    const parsed = parseGatewayErrorEnvelope(init.bodyText);
    this.errorCode = init.errorCode ?? parsed.errorCode;
    this.errorMessage = init.errorMessage ?? parsed.errorMessage;
  }
}

function parseGatewayErrorEnvelope(text: string): { errorCode?: string; errorMessage?: string } {
  if (!text.trim().startsWith("{")) {
    return {};
  }
  try {
    const body = JSON.parse(text);
    if (body === null || Array.isArray(body) || typeof body !== "object") {
      return {};
    }
    const errorCode = typeof body.error === "string" && body.error.trim() ? body.error.trim() : undefined;
    const errorMessage = typeof body.message === "string" && body.message.trim() ? body.message.trim() : undefined;
    return { errorCode, errorMessage };
  } catch {
    return {};
  }
}

function gatewayHTTPErrorMessage(method: "GET" | "POST", path: string, statusCode: number, bodyText: string): string {
  const parsed = parseGatewayErrorEnvelope(bodyText);
  if (parsed.errorCode) {
    return `Gateway ${method} ${path} HTTP ${statusCode} (${parsed.errorCode}): ${parsed.errorMessage ?? bodyText}`;
  }
  return `Gateway ${method} ${path} HTTP ${statusCode}: ${bodyText}`;
}

class GatewayAPIClient {
  private readonly gatewayBase: string;
  private readonly apiKey: string;
  private readonly maxRetries: number;

  constructor(init: { gatewayBaseUrl: string; apiKey: string; maxRetries?: number }) {
    this.gatewayBase = normalizeBase(init.gatewayBaseUrl);
    this.apiKey = init.apiKey.trim();
    this.maxRetries = Math.max(1, init.maxRetries ?? 3);
  }

  async getJSON(path: string, extraHeaders?: Record<string, string>): Promise<Record<string, unknown>> {
    return this.requestJSON("GET", path, undefined, extraHeaders);
  }

  async postJSON(
    path: string,
    payload: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    return this.requestJSON("POST", path, payload, extraHeaders);
  }

  private async requestJSON(
    method: "GET" | "POST",
    path: string,
    payload?: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
    const url = `${this.gatewayBase}${path.startsWith("/") ? path : `/${path}`}`;
    let lastErr: unknown;
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await fetch(url, {
          method,
          headers: {
            accept: "application/json",
            authorization: `Bearer ${this.apiKey}`,
            ...(extraHeaders ?? {}),
            ...(payload === undefined ? {} : { "content-type": "application/json" }),
          },
          ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
        });
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
        const parsed = parseGatewayErrorEnvelope(text);
        throw new GatewayHTTPError(gatewayHTTPErrorMessage(method, path, res.status, text), {
          statusCode: res.status,
          url,
          bodyText: text,
          errorCode: parsed.errorCode,
          errorMessage: parsed.errorMessage,
        });
      }
      return parseJSONObject(text, `Gateway ${method} ${path}`);
    }

    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }
}

class PaybondMCPRuntime {
  private readonly settings: Required<Pick<PaybondMCPSettings, "gatewayBaseUrl" | "apiKey" | "principalPath" | "maxRetries">>;
  private readonly gateway: GatewayAPIClient;
  private principalValue: Promise<Record<string, unknown>> | null = null;
  private signalValue: Promise<GatewaySignalClient> | null = null;
  private fraudValue: Promise<GatewayFraudClient> | null = null;

  constructor(settings: PaybondMCPSettings) {
    this.settings = {
      gatewayBaseUrl: settings.gatewayBaseUrl ?? DEFAULT_PAYBOND_GATEWAY_BASE_URL,
      apiKey: settings.apiKey,
      principalPath: settings.principalPath ?? DEFAULT_PRINCIPAL_PATH,
      maxRetries: Math.max(1, settings.maxRetries ?? 3),
    };
    this.gateway = new GatewayAPIClient({
      gatewayBaseUrl: this.settings.gatewayBaseUrl,
      apiKey: this.settings.apiKey,
      maxRetries: this.settings.maxRetries,
    });
  }

  async principal(): Promise<Record<string, unknown>> {
    this.principalValue ??= this.gateway.getJSON(this.settings.principalPath);
    const body = await this.principalValue;
    return { ...body };
  }

  async tenantId(): Promise<string> {
    const tenantId = String((await this.principal()).tenant_id ?? "").trim();
    if (!tenantId) {
      throw new Error("gateway principal JSON missing tenant_id");
    }
    return tenantId;
  }

  async signal(): Promise<GatewaySignalClient> {
    this.signalValue ??= (async () =>
      new GatewaySignalClient(this.settings.gatewayBaseUrl, await this.tenantId(), {
        staticGatewayBearerToken: this.settings.apiKey,
        maxRetries: this.settings.maxRetries,
      }))();
    return this.signalValue;
  }

  async fraud(): Promise<GatewayFraudClient> {
    this.fraudValue ??= (async () =>
      new GatewayFraudClient(this.settings.gatewayBaseUrl, await this.tenantId(), {
        staticGatewayBearerToken: this.settings.apiKey,
        maxRetries: this.settings.maxRetries,
      }))();
    return this.fraudValue;
  }

  async listIntents(init: {
    status?: string;
    operatorDid?: string;
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({
      limit: String(Math.max(1, Math.min(intArg(init.limit ?? 20, "limit"), 200))),
    });
    if (init.status?.trim()) {
      params.set("status", init.status.trim());
    }
    if (init.operatorDid?.trim()) {
      params.set("operator_did", init.operatorDid.trim());
    }
    if (init.cursor?.trim()) {
      params.set("cursor", init.cursor.trim());
    }
    return this.gateway.getJSON(`/harbor/operator/v1/intents?${params.toString()}`, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async getIntent(intentId: string): Promise<Record<string, unknown>> {
    return this.gateway.getJSON(`/harbor/operator/v1/intents/${encodeURIComponent(intentId)}`, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async getA2AAgentCard(): Promise<Record<string, unknown>> {
    return this.gateway.getJSON("/.well-known/agent-card.json");
  }

  async getA2ATaskContracts(): Promise<Record<string, unknown>> {
    return this.gateway.getJSON("/protocol/v2/a2a/task-contracts");
  }

  async getA2ATaskContract(contractId: string): Promise<Record<string, unknown>> {
    return this.gateway.getJSON(`/protocol/v2/a2a/task-contracts/${encodeURIComponent(contractId)}`);
  }

  async verifyCapability(init: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
  }): Promise<Record<string, unknown>> {
    const body = await this.gateway.postJSON(
      "/verify",
      {
        intent_id: init.intentId,
        token: init.token,
        operation: init.operation,
        requested_spend_cents: init.requestedSpendCents ?? 0,
      },
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
    const expectedTenant = await this.tenantId();
    const echoedTenant = String(body.tenant ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(`tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`);
    }
    const echoedIntent = String(body.intent_id ?? "").trim();
    if (echoedIntent !== init.intentId) {
      throw new Error(`verify intent mismatch: requested=${init.intentId} gateway=${echoedIntent}`);
    }
    return body;
  }

  async verifyAgentMandateV1(signedMandate: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.gateway.postJSON("/protocol/v2/mandates/verify", signedMandate, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async verifyAgentRecognitionProofV1(init: {
    proof: Record<string, unknown>;
    expectedPurpose: string;
    expectedRequest: Record<string, unknown>;
    expectedVerifier?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const verifier = {
      tenant_id: await this.tenantId(),
      verifier_id: DEFAULT_RECOGNITION_VERIFIER_ID,
      ...(init.expectedVerifier ?? {}),
    };
    return this.gateway.postJSON(
      "/protocol/v2/recognition/verify",
      {
        proof: init.proof,
        expected_purpose: init.expectedPurpose,
        expected_verifier: verifier,
        expected_request: init.expectedRequest,
      },
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
  }

  async importAgentMandateV1(init: {
    signedMandate: Record<string, unknown>;
    intentId: string;
    recognitionProof: Record<string, unknown>;
    transportBinding?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const body = await this.gateway.postJSON(
      "/protocol/v2/mandates",
      {
        signed_mandate: init.signedMandate,
        intent_id: init.intentId,
        transport_binding: init.transportBinding ?? {},
        recognition_proof: init.recognitionProof,
      },
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
    const expectedTenant = await this.tenantId();
    const mandate = ensureObject(body.mandate, "mandate");
    const authorization = ensureObject(mandate.authorization, "mandate.authorization");
    const echoedTenant = String(authorization.tenant_id ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(`tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`);
    }
    const echoedIntent = String(body.intent_id ?? "").trim();
    if (echoedIntent !== init.intentId) {
      throw new Error(`intent mismatch: requested=${init.intentId} gateway=${echoedIntent}`);
    }
    return body;
  }

  async getSettlementReceiptV1(receiptId: string): Promise<Record<string, unknown>> {
    const body = await this.gateway.getJSON(`/protocol/v2/receipts/${encodeURIComponent(receiptId)}`, {
      "x-tenant-id": await this.tenantId(),
    });
    const expectedTenant = await this.tenantId();
    const echoedTenant = String(body.tenant_id ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(`tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`);
    }
    const echoedReceipt = String(body.receipt_id ?? "").trim();
    if (echoedReceipt !== receiptId) {
      throw new Error(`receipt mismatch: requested=${receiptId} gateway=${echoedReceipt}`);
    }
    return body;
  }

  async verifyProtocolReceiptV1(receipt: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.gateway.postJSON("/protocol/v2/receipts/verify", receipt, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async createHarborIntent(init: {
    body: Record<string, unknown>;
    recognitionProof: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      "/harbor/intents",
      init.body,
      gatewayMutationHeaders(await this.tenantId(), init.recognitionProof, optionalMutationHeaders(init.idempotencyKey)),
    );
  }

  async fundHarborIntent(init: {
    intentId: string;
    recognitionProof: Record<string, unknown>;
    paymentSignature?: string;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/fund`,
      {},
      gatewayMutationHeaders(await this.tenantId(), init.recognitionProof, {
        ...optionalMutationHeaders(init.idempotencyKey),
        ...(init.paymentSignature?.trim() ? { "payment-signature": init.paymentSignature.trim() } : {}),
      }),
    );
  }

  async submitHarborEvidence(init: {
    intentId: string;
    body: Record<string, unknown>;
    recognitionProof: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/evidence`,
      init.body,
      gatewayMutationHeaders(await this.tenantId(), init.recognitionProof, optionalMutationHeaders(init.idempotencyKey)),
    );
  }

  async confirmHarborSettlement(init: {
    intentId: string;
    body: Record<string, unknown>;
    recognitionProof: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/settlement/confirm`,
      init.body,
      gatewayMutationHeaders(await this.tenantId(), init.recognitionProof, optionalMutationHeaders(init.idempotencyKey)),
    );
  }
}

function optionalMutationHeaders(idempotencyKey?: string): Record<string, string> {
  if (!idempotencyKey?.trim()) {
    return {};
  }
  return { "idempotency-key": idempotencyKey.trim() };
}

function gatewayMutationHeaders(
  tenantId: string,
  recognitionProof: Record<string, unknown>,
  extraHeaders?: Record<string, string>,
): Record<string, string> {
  return {
    ...(extraHeaders ?? {}),
    "x-tenant-id": tenantId,
    [agentRecognitionProofHeader]: encodeRecognitionProofHeader(recognitionProof),
  };
}

export class PaybondMCPServer {
  private readonly runtime: PaybondMCPRuntime;
  private readonly tools: MCPToolDefinition[];
  private initialized = false;

  constructor(settings: PaybondMCPSettings) {
    if (!settings.apiKey.trim()) {
      throw new Error("PAYBOND_API_KEY is required");
    }
    this.runtime = new PaybondMCPRuntime(settings);
    this.tools = this.buildTools(settings);
  }

  listTools(): Array<Record<string, unknown>> {
    return this.tools.map((tool) => ({
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
    }));
  }

  async callTool(name: string, args: Record<string, unknown> = {}): Promise<MCPCallToolResult> {
    const tool = this.tools.find((candidate) => candidate.name === name);
    if (!tool) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }
    try {
      const value = await tool.call(args);
      return toToolResult(value);
    } catch (err) {
      return {
        content: [{ type: "text", text: formatError(err) }],
        isError: true,
      };
    }
  }

  async handleMessage(message: JSONRPCRequest): Promise<JSONRPCResponse | null> {
    if (message.jsonrpc !== "2.0") {
      return responseError(message.id ?? null, -32600, "Invalid Request");
    }

    const method = typeof message.method === "string" ? message.method : null;
    if (!method) {
      return responseError(message.id ?? null, -32600, "Invalid Request");
    }

    // Notifications do not receive responses.
    if (message.id === undefined) {
      if (method === "notifications/initialized") {
        this.initialized = true;
      }
      return null;
    }

    switch (method) {
      case "initialize":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {
              tools: {
                listChanged: false,
              },
            },
            serverInfo: {
              name: SERVER_NAME,
              version: SERVER_VERSION,
            },
            instructions:
              "This MCP server is tenant-bound to the configured Paybond service-account API key. " +
              "It works with any MCP-compatible host and does not assume a specific model provider.",
          },
        };
      case "ping":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {},
        };
      case "tools/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: this.listTools(),
          },
        };
      case "tools/call": {
        const params = ensureObject(message.params, "tools/call params");
        const name = stringArg(params.name, "name");
        const args = params.arguments === undefined ? {} : ensureObject(params.arguments, "arguments");
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: await this.callTool(name, args),
        };
      }
      default:
        return responseError(message.id, -32601, `Method not found: ${method}`);
    }
  }

  runStdio(): void {
    let buffer = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      buffer += chunk;
      while (true) {
        const newlineIndex = buffer.indexOf("\n");
        if (newlineIndex < 0) {
          break;
        }
        const line = buffer.slice(0, newlineIndex).trim();
        buffer = buffer.slice(newlineIndex + 1);
        if (!line) {
          continue;
        }
        void this.handleLine(line);
      }
    });
    process.stdin.on("end", () => {
      if (buffer.trim()) {
        void this.handleLine(buffer.trim());
      }
    });
    process.stdin.resume();
  }

  private async handleLine(line: string): Promise<void> {
    let parsed: JSONRPCRequest;
    try {
      parsed = JSON.parse(line) as JSONRPCRequest;
    } catch {
      this.writeResponse(responseError(null, -32700, "Parse error"));
      return;
    }

    const response = await this.handleMessage(parsed);
    if (response !== null) {
      this.writeResponse(response);
    }
  }

  private writeResponse(response: JSONRPCResponse): void {
    process.stdout.write(`${JSON.stringify(response)}\n`);
  }

  private buildTools(settings: PaybondMCPSettings): MCPToolDefinition[] {
    const tools: MCPToolDefinition[] = [
      {
        name: "paybond_get_principal",
        description:
          "Resolve the tenant-bound Paybond principal behind the configured service-account API key.",
        inputSchema: emptyObjectSchema(),
        call: async () => this.runtime.principal(),
      },
      {
        name: "paybond_verify_capability",
        description:
          "Verify a capability token for one tenant-bound Harbor intent through the gateway compatibility route.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string", description: "Canonical Harbor intent UUID." },
            token: { type: "string", description: "Capability token to verify." },
            operation: { type: "string", description: "Delegated operation or tool name." },
            requested_spend_cents: {
              type: "integer",
              description: "Optional requested spend in cents for this tool call.",
            },
          },
          ["intent_id", "token", "operation"],
        ),
        call: async (args) =>
          this.runtime.verifyCapability({
            intentId: uuidArg(args.intent_id, "intent_id"),
            token: stringArg(args.token, "token"),
            operation: stringArg(args.operation, "operation"),
            requestedSpendCents:
              args.requested_spend_cents === undefined
                ? 0
                : intArg(args.requested_spend_cents, "requested_spend_cents"),
          }),
      },
      {
        name: "paybond_list_intents",
        description:
          "List tenant-scoped Harbor intents through the gateway operator view with optional filters.",
        inputSchema: objectSchema({
          status: { type: "string" },
          operator_did: { type: "string" },
          limit: { type: "integer", minimum: 1, maximum: 200 },
          cursor: { type: "string" },
        }),
        call: async (args) =>
          this.runtime.listIntents({
            status: optionalString(args.status),
            operatorDid: optionalString(args.operator_did),
            limit: args.limit === undefined ? 20 : intArg(args.limit, "limit"),
            cursor: optionalString(args.cursor),
          }),
      },
      {
        name: "paybond_get_intent",
        description: "Fetch one tenant-scoped Harbor intent detail through the gateway operator view.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string", description: "Canonical Harbor intent UUID." },
          },
          ["intent_id"],
        ),
        call: async (args) => this.runtime.getIntent(uuidArg(args.intent_id, "intent_id")),
      },
      {
        name: "paybond_get_reputation_receipt",
        description: "Fetch the signed Signal receipt for one operator DID.",
        inputSchema: objectSchema(
          {
            operator_did: { type: "string" },
            score_version: { type: "string" },
          },
          ["operator_did"],
        ),
        call: async (args) =>
          (await this.runtime.signal()).getReputationReceipt(
            stringArg(args.operator_did, "operator_did"),
            optionalString(args.score_version),
          ),
      },
      {
        name: "paybond_get_portfolio_summary",
        description: "Fetch the tenant-scoped Signal portfolio summary.",
        inputSchema: objectSchema({
          score_version: { type: "string" },
        }),
        call: async (args) =>
          (await this.runtime.signal()).getPortfolioSummary(optionalString(args.score_version)),
      },
      {
        name: "paybond_get_signed_portfolio_artifact",
        description:
          "Fetch the tenant-scoped signed Signal portfolio artifact for portable verifier and partner sharing.",
        inputSchema: objectSchema({
          score_version: { type: "string" },
        }),
        call: async (args) =>
          (await this.runtime.signal()).getSignedPortfolioArtifact(optionalString(args.score_version)),
      },
      {
        name: "paybond_get_fraud_assessment",
        description: "Fetch the read-only fraud assessment for one tenant-scoped operator DID.",
        inputSchema: objectSchema(
          {
            operator_did: { type: "string" },
            score_version: { type: "string" },
          },
          ["operator_did"],
        ),
        call: async (args) =>
          (await this.runtime.fraud()).getFraudAssessment(
            stringArg(args.operator_did, "operator_did"),
            optionalString(args.score_version),
          ),
      },
      {
        name: "paybond_get_fraud_metrics",
        description: "Fetch tenant-scoped read-only fraud backtesting and monitoring metrics for a supported active window.",
        inputSchema: objectSchema({
          window: { type: "string", enum: ["24h", "7d", "30d"] },
          score_version: { type: "string" },
        }),
        call: async (args) =>
          (await this.runtime.fraud()).getFraudMetrics({
            window: optionalString(args.window),
            scoreVersion: optionalString(args.score_version),
          }),
      },
      {
        name: "paybond_get_a2a_agent_card",
        description: "Fetch the published Paybond A2A discovery card for protocol-trust delegation.",
        inputSchema: objectSchema({}),
        call: async () => this.runtime.getA2AAgentCard(),
      },
      {
        name: "paybond_list_a2a_task_contracts",
        description: "Fetch the published catalog of Paybond A2A task contracts for delegated Harbor workflows.",
        inputSchema: objectSchema({}),
        call: async () => this.runtime.getA2ATaskContracts(),
      },
      {
        name: "paybond_get_a2a_task_contract",
        description: "Fetch one published Paybond A2A task contract by identifier.",
        inputSchema: objectSchema(
          {
            contract_id: { type: "string" },
          },
          ["contract_id"],
        ),
        call: async (args) => this.runtime.getA2ATaskContract(stringArg(args.contract_id, "contract_id")),
      },
      {
        name: "paybond_verify_agent_mandate_v1",
        description:
          "Verify a signed AgentMandateV1 envelope through the gateway v2 protocol surface.",
        inputSchema: objectSchema(
          {
            signed_mandate: { type: "object", additionalProperties: true },
          },
          ["signed_mandate"],
        ),
        call: async (args) =>
          this.runtime.verifyAgentMandateV1(ensureObject(args.signed_mandate, "signed_mandate")),
      },
      {
        name: "paybond_verify_agent_recognition_proof_v1",
        description:
          "Verify a replay-safe AgentRecognitionProofV1 against an expected purpose, verifier context, and request envelope.",
        inputSchema: objectSchema(
          {
            proof: { type: "object", additionalProperties: true },
            expected_purpose: { type: "string" },
            expected_request: { type: "object", additionalProperties: true },
            expected_verifier: { type: "object", additionalProperties: true },
          },
          ["proof", "expected_purpose", "expected_request"],
        ),
        call: async (args) =>
          this.runtime.verifyAgentRecognitionProofV1({
            proof: ensureObject(args.proof, "proof"),
            expectedPurpose: stringArg(args.expected_purpose, "expected_purpose"),
            expectedRequest: ensureObject(args.expected_request, "expected_request"),
            expectedVerifier:
              args.expected_verifier === undefined
                ? undefined
                : ensureObject(args.expected_verifier, "expected_verifier"),
          }),
      },
      {
        name: "paybond_import_agent_mandate_v1",
        description:
          "Import a signed AgentMandateV1 through the gateway v2 protocol route and bind it to one Harbor intent using a replay-safe recognition proof.",
        inputSchema: objectSchema(
          {
            signed_mandate: { type: "object", additionalProperties: true },
            intent_id: { type: "string" },
            recognition_proof: { type: "object", additionalProperties: true },
            transport_binding: { type: "object", additionalProperties: true },
          },
          ["signed_mandate", "intent_id", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.importAgentMandateV1({
            signedMandate: ensureObject(args.signed_mandate, "signed_mandate"),
            intentId: uuidArg(args.intent_id, "intent_id"),
            recognitionProof: ensureObject(args.recognition_proof, "recognition_proof"),
            transportBinding:
              args.transport_binding === undefined
                ? undefined
                : ensureObject(args.transport_binding, "transport_binding"),
          }),
      },
      {
        name: "paybond_get_settlement_receipt_v1",
        description: "Fetch the signed protocol-v2 settlement receipt for one Harbor intent.",
        inputSchema: objectSchema(
          {
            receipt_id: { type: "string" },
          },
          ["receipt_id"],
        ),
        call: async (args) => this.runtime.getSettlementReceiptV1(uuidArg(args.receipt_id, "receipt_id")),
      },
      {
        name: "paybond_verify_protocol_receipt_v1",
        description: "Verify a protocol-v2 authorization or settlement receipt through the gateway.",
        inputSchema: objectSchema(
          {
            receipt: { type: "object", additionalProperties: true },
          },
          ["receipt"],
        ),
        call: async (args) => this.runtime.verifyProtocolReceiptV1(ensureObject(args.receipt, "receipt")),
      },
      {
        name: "paybond_create_intent",
        description:
          "Create a Harbor intent through the gateway /harbor intent route. The request body must already be signed upstream and every call requires a recognition proof.",
        inputSchema: objectSchema(
          {
            body: { type: "object", additionalProperties: true },
            recognition_proof: { type: "object", additionalProperties: true },
            idempotency_key: { type: "string" },
          },
          ["body", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.createHarborIntent({
            body: ensureObject(args.body, "body"),
            recognitionProof: ensureObject(args.recognition_proof, "recognition_proof"),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_fund_intent",
        description:
          "Advance Harbor funding through the gateway /harbor path with a replay-safe recognition proof.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string" },
            recognition_proof: { type: "object", additionalProperties: true },
            payment_signature: { type: "string" },
            idempotency_key: { type: "string" },
          },
          ["intent_id", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.fundHarborIntent({
            intentId: uuidArg(args.intent_id, "intent_id"),
            recognitionProof: ensureObject(args.recognition_proof, "recognition_proof"),
            paymentSignature: optionalString(args.payment_signature),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_submit_evidence",
        description:
          "Submit payee evidence through the gateway /harbor path with a replay-safe recognition proof.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string" },
            body: { type: "object", additionalProperties: true },
            recognition_proof: { type: "object", additionalProperties: true },
            idempotency_key: { type: "string" },
          },
          ["intent_id", "body", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.submitHarborEvidence({
            intentId: uuidArg(args.intent_id, "intent_id"),
            body: ensureObject(args.body, "body"),
            recognitionProof: ensureObject(args.recognition_proof, "recognition_proof"),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_confirm_settlement",
        description:
          "Confirm Harbor settlement through the gateway /harbor path with a replay-safe recognition proof.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string" },
            body: { type: "object", additionalProperties: true },
            recognition_proof: { type: "object", additionalProperties: true },
            idempotency_key: { type: "string" },
          },
          ["intent_id", "body", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.confirmHarborSettlement({
            intentId: uuidArg(args.intent_id, "intent_id"),
            body: ensureObject(args.body, "body"),
            recognitionProof: ensureObject(args.recognition_proof, "recognition_proof"),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
    ];

    return tools;
  }
}

export function settingsFromEnv(env: Record<string, string | undefined> = process.env): PaybondMCPSettings {
  const apiKey = String(env.PAYBOND_API_KEY ?? "").trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required");
  }
  return {
    gatewayBaseUrl: DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    apiKey,
    principalPath: optionalEnv(env.PAYBOND_PRINCIPAL_PATH) ?? DEFAULT_PRINCIPAL_PATH,
    maxRetries: optionalEnv(env.PAYBOND_MCP_MAX_RETRIES)
      ? intArg(optionalEnv(env.PAYBOND_MCP_MAX_RETRIES), "PAYBOND_MCP_MAX_RETRIES")
      : 3,
  };
}

export function main(argv: string[] = process.argv.slice(2)): number {
  if (argv.includes("--help")) {
    process.stderr.write(
      "Usage: paybond-mcp-server\n\n" +
        "Runs the tenant-bound Paybond MCP server over stdio using PAYBOND_API_KEY.\n",
    );
    return 0;
  }
  if (argv.length > 0) {
    process.stderr.write("paybond-mcp-server does not accept positional arguments\n");
    return 1;
  }
  try {
    new PaybondMCPServer(settingsFromEnv()).runStdio();
    return 0;
  } catch (err) {
    process.stderr.write(`${formatError(err)}\n`);
    return 1;
  }
}

function normalizeBase(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

function parseJSONObject(text: string, context: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${context} response was not JSON`);
  }
  return ensureObject(parsed, `${context} response`);
}

function ensureObject(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function stringArg(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function intArg(value: unknown, field: string): number {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim()
        ? Number.parseInt(value, 10)
        : Number.NaN;
  if (!Number.isInteger(parsed)) {
    throw new Error(`${field} must be an integer`);
  }
  return parsed;
}

function uuidArg(value: unknown, field: string): string {
  const raw = stringArg(value, field);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(raw)) {
    throw new Error(`${field} must be a canonical UUID`);
  }
  return raw;
}

function encodeRecognitionProofHeader(proof: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(proof), "utf8").toString("base64url");
}

function objectSchema(
  properties: Record<string, unknown>,
  required: string[] = [],
): Record<string, unknown> {
  return {
    type: "object",
    properties,
    additionalProperties: false,
    ...(required.length === 0 ? {} : { required }),
  };
}

function emptyObjectSchema(): Record<string, unknown> {
  return {
    type: "object",
    properties: {},
    additionalProperties: false,
  };
}

function toToolResult(value: Record<string, unknown> | null): MCPCallToolResult {
  if (value === null) {
    return {
      content: [{ type: "text", text: "null" }],
    };
  }
  return {
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
  };
}

function jsonObjectFromValue(value: unknown): Record<string, unknown> {
  if (value === null) {
    return {};
  }
  if (Array.isArray(value)) {
    return { items: value };
  }
  if (typeof value !== "object") {
    return { value };
  }
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function responseError(id: JSONRPCID, code: number, message: string): JSONRPCResponse {
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
    },
  };
}

function parseRetryAfterSeconds(v: string | null): number | null {
  if (!v) return null;
  const n = Number.parseFloat(v.trim());
  if (!Number.isFinite(n)) return null;
  return Math.min(n, 30);
}

function backoffMs(attempt: number): number {
  const base = 200 * 2 ** attempt;
  const jitter = Math.random() * 100;
  return Math.min(base + jitter, 5000);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function optionalEnv(value: string | undefined): string | undefined {
  return value?.trim() ? value.trim() : undefined;
}

function formatError(err: unknown): string {
  if (
    err instanceof Error ||
    err instanceof GatewayAuthError ||
    err instanceof GatewayHTTPError ||
    err instanceof SignalHttpError
  ) {
    return err.message;
  }
  return String(err);
}

const isMainModule = (() => {
  const scriptPath = process.argv[1];
  if (!scriptPath) {
    return false;
  }
  try {
    return import.meta.url === new URL(scriptPath, "file://").href;
  } catch {
    return import.meta.url.endsWith(scriptPath);
  }
})();

if (isMainModule && main() !== 0) {
  process.exitCode = 1;
}
