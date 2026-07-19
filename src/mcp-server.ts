#!/usr/bin/env node

import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { requireSecureGatewayUrl } from "./gateway-url.js";
import { deprecatedAliasWarning } from "./cli/automation.js";
import { redactSensitiveFields } from "./cli/redact.js";
import {
  MCP_TOOL_ALLOWLIST_ENV,
  MCP_TOOL_POLICY_ENV,
  type McpToolPolicyConfig,
  mergeMcpToolPolicy,
  parseMcpToolAllowlist,
  parseMcpToolPolicy,
  resolveMcpToolPolicy,
  toolAllowedByPolicy,
} from "./cli/mcp-policy.js";
import {
  MCP_EVIDENCE_POLICY_ENV,
  McpEvidenceValidationGate,
  completionEvidenceValidationOk,
  extractHarborEvidenceValidationInput,
  extractSandboxGuardrailValidationInput,
  parseMcpEvidencePolicy,
  type McpEvidencePolicy,
} from "./mcp-evidence-policy.js";
import {
  McpCapabilityTokenCache,
  mcpToolStoresCapabilityToken,
  parseMcpCapabilityTokenCacheConfig,
  type McpCapabilityTokenCacheConfig,
} from "./mcp-capability-token-cache.js";
import {
  createMcpPolicyGatewayAdapter,
  McpPolicyReloadGate,
  parseMcpPolicyReloadConfig,
  type McpPolicyReloadConfig,
} from "./mcp-policy-reload.js";
import {
  AGENT_RECEIPT_KIND_V1,
  verifyAgentReceiptV1FromJSON,
} from "./agent-receipt.js";
import {
  agentReceiptResourceTemplateDefinition,
  agentReceiptResourceUri,
  MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
  parseAgentReceiptResourceUri,
} from "./mcp-receipt-resource.js";
import {
  DEFAULT_PAYBOND_GATEWAY_BASE_URL,
  GatewayFraudClient,
  GatewaySignalClient,
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


const SERVER_NAME = "Paybond MCP";
const SERVER_VERSION = "0.12.11";
const MCP_PROTOCOL_VERSION = "2025-11-25";
const DEFAULT_PRINCIPAL_PATH = "/v1/auth/principal";
const DEFAULT_RECOGNITION_VERIFIER_ID = "paybond-gateway";
const agentRecognitionProofHeader = "x-paybond-agent-recognition-proof";
const DEFAULT_ENV_FILE = ".env.local";

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
  title?: string;
  description: string;
  inputSchema: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: MCPToolAnnotations;
  call: (
    args: Record<string, unknown>,
  ) => Promise<Record<string, unknown> | null>;
};

type MCPToolAnnotations = {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
};

type MCPToolSelectionMetadata = {
  title: string;
  description?: string;
  outputSchema?: Record<string, unknown>;
  annotations: MCPToolAnnotations;
};

const AUTHORIZE_SPEND_OUTPUT_PROPERTIES: Record<string, unknown> = {
  allow: {
    type: "boolean",
    description: "Whether the requested operation is allowed.",
  },
  tenant: {
    type: "string",
    description: "Tenant echoed by the gateway.",
  },
  intent_id: {
    type: "string",
    description: "Verified Harbor intent UUID.",
  },
  audit_id: {
    type: "string",
    description: "Gateway audit identifier when available.",
  },
  remaining_cents: {
    type: "integer",
    description: "Remaining spend budget in cents for the evaluated scope, when available.",
  },
  reason_codes: {
    type: "array",
    items: { type: "string" },
    description: "Stable spend-policy reason codes from the authorization decision.",
  },
  message: {
    type: "string",
    description: "Human-readable decision message when present.",
  },
  decision_id: {
    type: "string",
    description: "Persisted spend decision identifier when authorization creates one.",
  },
  approval_request_id: {
    type: "string",
    description: "Approval request identifier when human approval is required.",
  },
};

const TOOL_SELECTION_METADATA: Record<string, MCPToolSelectionMetadata> = {
  paybond_get_principal: {
    title: "Get Paybond Principal",
    description:
      "Use this when you need to confirm which tenant-bound service-account principal the configured PAYBOND_API_KEY authenticates as " +
      "(tenant_id, subject, and roles). Call early as a prerequisite before Harbor escrow, Signal reads, or other tenant-scoped tools when " +
      "tenant identity is unknown. Not required before every later call once tenant_id is already known from a prior principal response or host config. " +
      "Do not use this when you need Harbor intent escrow detail; use paybond_get_intent instead when you have an intent_id. " +
      "Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead. " +
      "Makes one read-only external GET to the gateway principal endpoint; idempotent identity lookup with no side effects " +
      "(no mutations, spend reservations, escrow changes, or ledger writes); auth or gateway failures surface as tool errors.",
    annotations: readOnlyToolAnnotations("Get Paybond Principal"),
    outputSchema: outputObjectSchema({
      tenant_id: {
        type: "string",
        description: "Tenant bound to the configured Paybond API key.",
        examples: ["tenant-a"],
      },
      subject: {
        type: "string",
        description:
          "Service-account subject identifier echoed by the gateway for the authenticated API key (example: service-account-1).",
        examples: ["service-account-1"],
      },
      roles: {
        type: "array",
        items: { type: "string" },
        description:
          "RBAC roles granted to this principal for the authenticated tenant (example: [\"operator\"]).",
        examples: [["operator"]],
      },
    }),
  },
  paybond_verify_capability: {
    title: "Verify Paybond Capability",
    description:
      "Use this when you need raw capability-token verification for one tenant-bound Harbor intent. " +
      "Do not use this to create, fund, or modify intents; use paybond_authorize_agent_spend as the clearer gate before side-effecting agent tools.",
    annotations: additiveMutationToolAnnotations("Verify Paybond Capability"),
    outputSchema: outputObjectSchema(
      {
        ...AUTHORIZE_SPEND_OUTPUT_PROPERTIES,
      },
      ["tenant", "intent_id"],
    ),
  },
  paybond_authorize_agent_spend: {
    title: "Authorize Agent Spend",
    description:
      "Use this when an agent has an intent_id and capability_token and needs a tenant-bound spend gate before calling a side-effecting tool, paid API, vendor action, or settlement workflow. " +
      "Do not use this for creating, funding, or changing intents; call paybond_create_spend_intent or paybond_fund_intent first when no funded capability token exists.",
    annotations: additiveMutationToolAnnotations("Authorize Agent Spend"),
    outputSchema: outputObjectSchema(
      {
        ...AUTHORIZE_SPEND_OUTPUT_PROPERTIES,
      },
      ["tenant", "intent_id"],
    ),
  },
  paybond_get_budget_remaining: {
    title: "Get Budget Remaining",
    description:
      "Use this when you need a read-only dry-run of remaining spend budget for a tenant-bound intent before authorizing a paid tool. " +
      "Do not use this to authorize spend or create decisions; call paybond_authorize_agent_spend when you are ready to gate a side-effecting tool.",
    annotations: readOnlyToolAnnotations("Get Budget Remaining"),
    outputSchema: outputObjectSchema(
      {
        remaining_cents: {
          type: "integer",
          description: "Remaining spend budget in cents for the evaluated scope, when available.",
        },
        spend_scope: {
          type: "object",
          description: "Spend scope used for the budget evaluation (scope_type and scope_key).",
          additionalProperties: true,
        },
        policy_version: {
          type: "integer",
          description: "Active spend-control policy version when a policy is configured.",
        },
      },
      [],
    ),
  },
  paybond_explain_policy: {
    title: "Explain Spend Policy",
    description:
      "Use this when you need a read-only explanation of whether a proposed spend would allow, require approval, or deny under the tenant spend-control policy. " +
      "Do not use this to authorize spend or create approval requests; call paybond_authorize_agent_spend to persist a decision.",
    annotations: readOnlyToolAnnotations("Explain Spend Policy"),
    outputSchema: outputObjectSchema(
      {
        outcome: {
          type: "string",
          description: "Normalized policy outcome: allow, approval_required, or deny.",
        },
        reason_codes: {
          type: "array",
          items: { type: "string" },
          description: "Stable policy reason codes from the dry-run evaluation.",
        },
        explanation: {
          type: "string",
          description: "Human-readable explanation derived from reason codes.",
        },
        remaining_cents: {
          type: "integer",
          description: "Remaining spend budget in cents for the evaluated scope, when available.",
        },
        approval_threshold_exceeded: {
          type: "boolean",
          description:
            "True when the dry-run indicates the request is at or above the approval threshold.",
        },
      },
      ["outcome", "explanation"],
    ),
  },
  paybond_bootstrap_sandbox_guardrail: {
    title: "Bootstrap Sandbox Guardrail",
    description:
      "Use this when building or testing a first paid-tool integration and you need a sandbox-only guardrail intent with no live settlement rails. " +
      "Do not use this for production live money movement or already-created Harbor intents.",
    annotations: additiveMutationToolAnnotations("Bootstrap Sandbox Guardrail"),
    outputSchema: outputObjectSchema(
      {
        tenant_id: { type: "string" },
        intent_id: { type: "string" },
        capability_token: { type: "string" },
        operation: { type: "string" },
        requested_spend_cents: { type: "integer" },
        sandbox_lifecycle_status: { type: "string" },
        settlement_rail: { type: "string" },
        settlement_mode: { type: "string" },
      },
      [
        "tenant_id",
        "intent_id",
        "capability_token",
        "operation",
        "requested_spend_cents",
        "sandbox_lifecycle_status",
      ],
    ),
  },
  paybond_validate_completion_evidence: {
    title: "Validate Completion Evidence",
    description:
      "Pre-validates vendor and canonical completion evidence against catalog JSON Schemas and preset forbidden_evidence_fields. " +
      "Required before evidence submit tools when PAYBOND_MCP_EVIDENCE_POLICY=strict. Harbor remains authoritative at submit time.",
    annotations: readOnlyToolAnnotations("Validate Completion Evidence"),
    outputSchema: outputObjectSchema(
      {
        preset_id: { type: "string" },
        ok: { type: "boolean" },
        vendor_schema_ok: { type: "boolean" },
        canonical_schema_ok: { type: "boolean" },
        quality_fields_missing: { type: "array", items: { type: "string" } },
        forbidden_fields_present: { type: "array", items: { type: "string" } },
        pack_stale: { type: "boolean" },
        drift_kinds: { type: "array", items: { type: "string" } },
      },
      ["preset_id", "ok"],
    ),
  },
  paybond_submit_sandbox_guardrail_evidence: {
    title: "Submit Sandbox Guardrail Evidence",
    description:
      "Use this when a sandbox guardrail intent needs evidence to complete simulator settlement or predicate checks. " +
      "Do not use this for live Harbor spend evidence; use paybond_submit_spend_evidence for production spend intents.",
    annotations: additiveMutationToolAnnotations(
      "Submit Sandbox Guardrail Evidence",
    ),
    outputSchema: outputObjectSchema(
      {
        tenant_id: { type: "string" },
        intent_id: { type: "string" },
        operation: { type: "string" },
        requested_spend_cents: { type: "integer" },
        sandbox_lifecycle_status: { type: "string" },
        predicate_passed: { type: "boolean" },
        payload_digest: { type: "string" },
      },
      [
        "tenant_id",
        "intent_id",
        "operation",
        "requested_spend_cents",
        "sandbox_lifecycle_status",
      ],
    ),
  },
  paybond_list_intents: {
    title: "List Harbor Intents",
    annotations: readOnlyToolAnnotations("List Harbor Intents"),
    outputSchema: outputObjectSchema({
      items: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
      next_cursor: { type: "string" },
    }),
  },
  paybond_get_intent: {
    title: "Get Harbor Intent",
    annotations: readOnlyToolAnnotations("Get Harbor Intent"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      tenant_id: { type: "string" },
    }),
  },
  paybond_list_audit_exports: {
    title: "List Audit Exports",
    annotations: readOnlyToolAnnotations("List Audit Exports"),
    outputSchema: outputObjectSchema({
      tenant_realm_id: { type: "string" },
      jobs: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
      next_cursor: { type: "string" },
    }),
  },
  paybond_get_audit_export: {
    title: "Get Audit Export",
    annotations: readOnlyToolAnnotations("Get Audit Export"),
    outputSchema: outputObjectSchema({
      job: { type: "object", additionalProperties: true },
    }),
  },
  paybond_get_reputation_receipt: {
    title: "Get Reputation Receipt",
    description:
      "Use this when you need the signed Signal reputation receipt for one known tenant-scoped operator DID " +
      "(score, metrics, reason codes, and Ed25519 signing material under receipt). " +
      "Requires PAYBOND_API_KEY with Signal analytics read access. " +
      "Do not use this for tenant-wide aggregates—call paybond_get_portfolio_summary—or a portable signed operator list—call " +
      "paybond_get_signed_portfolio_artifact—or one operator's fraud review posture—call paybond_get_fraud_assessment. " +
      "Idempotent read with no side effects; returns null when no receipt exists for that operator and score_version.",
    annotations: readOnlyToolAnnotations("Get Reputation Receipt"),
    outputSchema: outputObjectSchema({
      schema_version: {
        type: "integer",
        description: "Reputation receipt envelope schema version.",
      },
      updated_at: {
        type: "string",
        description: "RFC3339 timestamp when the stored receipt row was last updated.",
      },
      receipt: {
        type: "object",
        additionalProperties: true,
        description:
          "Signed Signal receipt for the operator (tenant_id, operator_did, score_version, score, metrics, reason_codes, signing_algorithm, message_digest_hex, signing_public_key_hex, signature_hex).",
        examples: [
          {
            tenant_id: "tenant-a",
            operator_did: "did:web:vendor.example#booker-agent",
            score_version: "1.0",
            score: 812,
            signature_hex: "ab".repeat(32),
          },
        ],
      },
    }),
  },
  paybond_get_portfolio_summary: {
    title: "Get Portfolio Summary",
    description:
      "Use this when you need a read-only, tenant-scoped Signal portfolio aggregate for the authenticated API key " +
      "(operator_count, average_score, total_terminal_intents, total_receipted_volume_cents, operators_under_review, " +
      "and checkpoint_last_ledger_seq). Requires PAYBOND_API_KEY with Signal analytics read access and the private-dashboards feature. " +
      "Do not use this when you need a portable signed operator list for partner or verifier sharing—call " +
      "paybond_get_signed_portfolio_artifact instead—or for one operator's signed receipt—call paybond_get_reputation_receipt. " +
      "Idempotent read with no side effects; auth, RBAC, feature, or gateway failures surface as tool errors.",
    annotations: readOnlyToolAnnotations("Get Portfolio Summary"),
    outputSchema: outputObjectSchema({
      schema_version: {
        type: "integer",
        description: "Portfolio summary schema version (currently 1).",
      },
      tenant_id: {
        type: "string",
        description:
          "Tenant echoed by the gateway for the authenticated API key (example: tenant-a).",
        examples: ["tenant-a"],
      },
      score_model_version: {
        type: "string",
        description:
          "Score model version used for the aggregate (echoes the requested score_version or the gateway default 1.0).",
        examples: ["1.0"],
      },
      scoring_model: {
        type: "string",
        description: "Scoring model identifier used by Signal for this summary.",
      },
      checkpoint_last_ledger_seq: {
        type: "integer",
        description: "Last ledger sequence included in the tenant Signal checkpoint.",
      },
      operator_count: {
        type: "integer",
        description: "Number of operators with reputation data for this score model version.",
      },
      average_score: {
        type: "number",
        description: "Average operator score across the tenant portfolio for this score model version.",
      },
      total_terminal_intents: {
        type: "integer",
        description: "Aggregate terminal Harbor intents across operators in the portfolio.",
      },
      total_receipted_volume_cents: {
        type: "integer",
        description: "Aggregate receipted settlement volume in cents across the portfolio.",
      },
      operators_under_review: {
        type: "integer",
        description: "Count of operators currently under Signal review for this score model version.",
      },
    }),
  },
  paybond_get_signed_portfolio_artifact: {
    title: "Get Signed Portfolio Artifact",
    description:
      "Use this when you need a portable, tenant-scoped signed Signal portfolio snapshot (operator list plus Ed25519 signing material) " +
      "for offline verifier checks or partner sharing—not a public leaderboard. " +
      "Requires PAYBOND_API_KEY with Signal analytics read access. Omit score_version to use the gateway default current model (1.0). " +
      "Do not use this for tenant-wide aggregates without signatures—call paybond_get_portfolio_summary—or for one operator's signed receipt—call " +
      "paybond_get_reputation_receipt—or for one operator's fraud review posture—call paybond_get_fraud_assessment. " +
      "Idempotent read with no side effects; auth, RBAC, feature, or gateway failures surface as tool errors.",
    annotations: readOnlyToolAnnotations("Get Signed Portfolio Artifact"),
    outputSchema: outputObjectSchema({
      kind: {
        type: "string",
        description:
          "Artifact kind identifier (currently paybond.signal.portfolio_snapshot).",
        examples: ["paybond.signal.portfolio_snapshot"],
      },
      tenant_id: {
        type: "string",
        description:
          "Tenant echoed by the gateway for the authenticated API key (example: tenant-a). Never invent tenant identifiers.",
        examples: ["tenant-a"],
      },
      score_model_version: {
        type: "string",
        description:
          "Score model version used for the artifact (echoes the requested score_version or the gateway default 1.0).",
        examples: ["1.0"],
      },
      checkpoint_last_ledger_seq: {
        type: "integer",
        description: "Last ledger sequence included in the tenant Signal checkpoint for this artifact.",
      },
      signature_hex: {
        type: "string",
        description: "Ed25519 signature hex over the canonical portfolio artifact payload.",
      },
    }),
  },
  paybond_get_fraud_assessment: {
    title: "Get Fraud Assessment",
    description:
      "Use this when you need the read-only fraud assessment and review posture for one known tenant-scoped operator DID (review state, fraud signals, and compact fraud_assessment). " +
      "Example: look up operator_did=did:web:vendor.example#booker-agent (optionally score_version=1.0) before deciding whether to continue a spend workflow for that operator. " +
      "Do not use this for tenant-wide fraud backtesting metrics—call paybond_get_fraud_metrics instead—or for Harbor intent escrow detail—call paybond_get_intent. " +
      "Idempotent read; returns null when no assessment exists for that operator.",
    annotations: readOnlyToolAnnotations("Get Fraud Assessment"),
    outputSchema: outputObjectSchema({
      tenant_id: {
        type: "string",
        description:
          "Tenant echoed by the gateway for the authenticated API key (example: tenant-a).",
        examples: ["tenant-a"],
      },
      operator_did: {
        type: "string",
        description:
          "Operator DID echoed from the assessment response (example: did:web:vendor.example#booker-agent).",
        examples: ["did:web:vendor.example#booker-agent"],
      },
      fraud_assessment: {
        type: "object",
        additionalProperties: true,
        description:
          "Compact fraud assessment for the operator (level, severity, signal counts, summary). Example shape: {\"level\":\"high\",\"highest_severity\":\"high\",\"signal_count\":1,\"summary\":\"level=high\"}.",
        examples: [
          {
            level: "high",
            highest_severity: "high",
            signal_count: 1,
            summary: "level=high",
          },
        ],
      },
    }),
  },
  paybond_get_fraud_metrics: {
    title: "Get Fraud Metrics",
    description:
      "Use this when you need tenant-wide Signal fraud backtesting and monitoring metrics over a rolling window " +
      "(flagged operators, severity counts, review outcomes, precision/false-positive rates, and backtest_summary). " +
      "Requires PAYBOND_API_KEY with Signal analytics read access and the private-dashboards feature. " +
      "Do not use this for one operator's fraud posture—call paybond_get_fraud_assessment instead—or for Harbor intent escrow detail—call paybond_get_intent. " +
      "Idempotent read with no side effects; omit window to default to 24h; unsupported windows fail with HTTP 400 " +
      "(\"window must be one of 24h, 7d, or 30d\").",
    annotations: readOnlyToolAnnotations("Get Fraud Metrics"),
    outputSchema: outputObjectSchema({
      tenant_id: {
        type: "string",
        description:
          "Tenant echoed by the gateway for the authenticated API key (example: tenant-a).",
        examples: ["tenant-a"],
      },
      score_model_version: {
        type: "string",
        description:
          "Score model version used for the metrics (echoes the requested score_version or the gateway default 1.0).",
        examples: ["1.0"],
      },
      window: {
        type: "string",
        description: "Active metrics window label: 24h, 7d, or 30d.",
        examples: ["24h", "7d", "30d"],
      },
      window_started_at: {
        type: "string",
        description: "RFC3339 start of the evaluated rolling window.",
      },
      window_ended_at: {
        type: "string",
        description: "RFC3339 end of the evaluated rolling window.",
      },
      flagged_operator_count: {
        type: "integer",
        description: "Operators with at least one fraud signal in the window.",
      },
      critical_signal_count: {
        type: "integer",
        description: "Count of critical-severity fraud signals in the window.",
      },
      high_signal_count: {
        type: "integer",
        description: "Count of high-severity fraud signals in the window.",
      },
      elevated_signal_count: {
        type: "integer",
        description: "Count of elevated-severity fraud signals in the window.",
      },
      review_open_count: {
        type: "integer",
        description: "Operators currently in an open review state.",
      },
      labeled_outcome_count: {
        type: "integer",
        description: "Review outcomes labeled in the window (confirmed risk, false positive, or needs more evidence).",
      },
      confirmed_risk_count: {
        type: "integer",
        description: "Labeled confirmed-risk outcomes in the window.",
      },
      false_positive_count: {
        type: "integer",
        description: "Labeled false-positive outcomes in the window.",
      },
      backtest_summary: {
        type: "string",
        description: "Human-readable backtest summary derived from the window metrics.",
      },
    }),
  },
  paybond_get_a2a_agent_card: {
    title: "Get A2A Agent Card",
    annotations: readOnlyToolAnnotations("Get A2A Agent Card"),
    outputSchema: outputObjectSchema({
      name: { type: "string" },
      version: { type: "string" },
      skills: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    }),
  },
  paybond_list_a2a_task_contracts: {
    title: "List A2A Task Contracts",
    annotations: readOnlyToolAnnotations("List A2A Task Contracts"),
    outputSchema: outputObjectSchema({
      contracts: {
        type: "array",
        items: { type: "object", additionalProperties: true },
      },
    }),
  },
  paybond_get_a2a_task_contract: {
    title: "Get A2A Task Contract",
    annotations: readOnlyToolAnnotations("Get A2A Task Contract"),
    outputSchema: outputObjectSchema({
      id: { type: "string" },
      name: { type: "string" },
      description: { type: "string" },
    }),
  },
  paybond_verify_agent_mandate_v1: {
    title: "Verify Agent Mandate",
    annotations: readOnlyToolAnnotations("Verify Agent Mandate"),
    outputSchema: outputObjectSchema({
      valid: { type: "boolean" },
      mandate_digest_sha256_hex: { type: "string" },
    }),
  },
  paybond_verify_agent_recognition_proof_v1: {
    title: "Verify Agent Recognition Proof",
    annotations: readOnlyToolAnnotations("Verify Agent Recognition Proof"),
    outputSchema: outputObjectSchema({
      valid: { type: "boolean" },
      proof: { type: "object", additionalProperties: true },
    }),
  },
  paybond_import_agent_mandate_v1: {
    title: "Import Agent Mandate",
    annotations: additiveMutationToolAnnotations("Import Agent Mandate"),
    outputSchema: outputObjectSchema({
      valid: { type: "boolean" },
      intent_id: { type: "string" },
      mandate_digest_sha256_hex: { type: "string" },
      authorization_receipt: { type: "object", additionalProperties: true },
    }),
  },
  paybond_get_settlement_receipt_v1: {
    title: "Get Settlement Receipt",
    annotations: readOnlyToolAnnotations("Get Settlement Receipt"),
    outputSchema: outputObjectSchema(
      {
        tenant_id: { type: "string" },
        receipt_id: { type: "string" },
        intent_id: { type: "string" },
      },
      ["tenant_id", "receipt_id"],
    ),
  },
  paybond_get_agent_receipt_v1: {
    title: "Get Agent Receipt",
    description:
      "Use this when you need the signed paybond.agent_receipt_v1 JSON for one receipt_id " +
      "(SHA-256 action id or intent-terminal UUID) via tenant-bound Gateway GET. " +
      "Do not use this for protocol settlement receipts—call paybond_get_settlement_receipt_v1. " +
      "For agent-to-agent handoff without embedding JSON in prompts, prefer the MCP resource " +
      "paybond://receipt/{receipt_id} (resources/read verifies at the operational tier). " +
      "Validity tiers beyond operational, continuity-chain, inclusion proofs, owner disclosure, " +
      "and ACTA/PEF/SCITT adapters are Kit/CLI/Gateway auditor surfaces—not this tool's job. " +
      "Read-only and side-effect free.",
    annotations: readOnlyToolAnnotations("Get Agent Receipt"),
    outputSchema: outputObjectSchema(
      {
        tenant_id: { type: "string" },
        receipt_id: { type: "string" },
        kind: { type: "string" },
      },
      ["tenant_id", "receipt_id"],
    ),
  },
  paybond_verify_agent_receipt_v1: {
    title: "Verify Agent Receipt",
    description:
      "Use this when you already have a signed paybond.agent_receipt_v1 JSON object and need an " +
      "offline operational-tier (default) Ed25519 signature check—schema, digest, and Gateway " +
      "signature—matching resources/read on paybond://receipt/{receipt_id}. " +
      "Optional validity_tier=primary|attested raises the bar (payee digest / operator attestation). " +
      "Do not use this for protocol authorization/settlement receipts—call paybond_verify_protocol_receipt_v1. " +
      "Continuity-chain audits, inclusion proofs, owner disclosure, and ACTA/PEF/SCITT are Kit/CLI/Gateway " +
      "auditor surfaces. Read-only and side-effect free: success returns valid=true with kind, receipt_id, " +
      "tenant_id, and the normalized receipt; failures raise a clear verification error.",
    annotations: readOnlyToolAnnotations("Verify Agent Receipt"),
    outputSchema: outputObjectSchema({
      valid: {
        type: "boolean",
        description: "True when operational (or requested) validity checks passed. Example: true.",
        examples: [true],
      },
      kind: {
        type: "string",
        description: "Verified receipt kind (paybond.agent_receipt_v1).",
        examples: ["paybond.agent_receipt_v1"],
      },
      receipt_id: {
        type: "string",
        description: "Canonical receipt identifier from the verified receipt.",
      },
      tenant_id: {
        type: "string",
        description: "Tenant id embedded in the verified receipt (not invented by the caller).",
      },
      validity_tier: {
        type: "string",
        description: "Requested validity tier used for this verify (operational, primary, or attested).",
        examples: ["operational", "primary", "attested"],
      },
      receipt: {
        type: "object",
        additionalProperties: true,
        description: "Normalized verified paybond.agent_receipt_v1 object.",
      },
    }),
  },
  paybond_verify_protocol_receipt_v1: {
    title: "Verify Protocol Receipt",
    description:
      "Use this when you already have a signed protocol-v2 authorization or settlement receipt JSON object and need offline Ed25519 verification (structure, message digest, and signature) through the gateway. " +
      "Do not use this to verify AgentMandateV1 envelopes—call paybond_verify_agent_mandate_v1—or to check a Harbor capability token before spend—call paybond_verify_capability or paybond_authorize_agent_spend. " +
      "To load a settlement receipt by intent UUID first, call paybond_get_settlement_receipt_v1 then pass its body here. " +
      "Read-only and side-effect free: success returns valid=true with kind, receipt_id, tenant_id, and the normalized receipt; unsupported kind, malformed JSON, digest mismatch, or bad signature fail with a gateway error (typically HTTP 400).",
    annotations: readOnlyToolAnnotations("Verify Protocol Receipt"),
    outputSchema: outputObjectSchema({
      valid: {
        type: "boolean",
        description:
          "True when the gateway accepted the receipt structure and Ed25519 signature. Example: true.",
        examples: [true],
      },
      kind: {
        type: "string",
        description:
          "Verified receipt kind echoed from the normalized receipt. One of paybond.protocol_authorization_receipt_v1 or paybond.protocol_settlement_receipt_v1.",
        examples: [
          "paybond.protocol_authorization_receipt_v1",
          "paybond.protocol_settlement_receipt_v1",
        ],
      },
      receipt_id: {
        type: "string",
        description: "Canonical receipt identifier from the verified receipt.",
        examples: ["550e8400-e29b-41d4-a716-446655440000"],
      },
      tenant_id: {
        type: "string",
        description: "Tenant id embedded in the verified receipt (not invented by the caller).",
        examples: ["acme-pilot"],
      },
      receipt: {
        type: "object",
        additionalProperties: true,
        description:
          "Normalized verified receipt object matching the input kind (authorization or settlement fields plus signing material).",
      },
    }),
  },
  paybond_create_intent: {
    title: "Create Harbor Intent",
    description:
      "Use this when you already have a fully signed Harbor intent request body and replay-safe recognition proof for the gateway /harbor/intents route. " +
      "Do not use this for the normal agent spend-control path unless you specifically need the low-level Harbor API; prefer paybond_create_spend_intent.",
    annotations: additiveMutationToolAnnotations("Create Harbor Intent"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      capability_token: { type: "string" },
    }),
  },
  paybond_create_spend_intent: {
    title: "Create Spend Intent",
    description:
      "Use this when an agent workflow needs a new Paybond spend intent with bounded budget, allowed operations, evidence requirements, and settlement review. " +
      "Do not use this for checking an already funded capability token; use paybond_authorize_agent_spend before the paid action.",
    annotations: additiveMutationToolAnnotations("Create Spend Intent"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      capability_token: { type: "string" },
    }),
  },
  paybond_fund_intent: {
    title: "Fund Intent",
    description:
      "Use this when an existing Harbor intent needs to advance through funding via the gateway and you have a replay-safe recognition proof. " +
      "Do not use this to create a new intent or to authorize a downstream tool call; use the returned intent_id and capability_token with paybond_authorize_agent_spend.",
    annotations: liveMutationToolAnnotations("Fund Intent"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      capability_token: { type: "string" },
    }),
  },
  paybond_submit_evidence: {
    title: "Submit Harbor Evidence",
    description:
      "Use this when you already have a Harbor evidence request body and recognition proof for the gateway /harbor/intents/{id}/evidence route. " +
      "Do not use this for the high-level spend-control path unless you need the low-level Harbor API; prefer paybond_submit_spend_evidence.",
    annotations: additiveMutationToolAnnotations("Submit Harbor Evidence"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      evidence_id: { type: "string" },
    }),
  },
  paybond_submit_spend_evidence: {
    title: "Submit Spend Evidence",
    description:
      "Use this when a Paybond spend intent needs signed evidence so release, refund, review, and receipt generation use the same audit-ready record. " +
      "Do not use this to create or fund intents, and do not use it for sandbox guardrail evidence.",
    annotations: additiveMutationToolAnnotations("Submit Spend Evidence"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      evidence_id: { type: "string" },
    }),
  },
  paybond_confirm_settlement: {
    title: "Confirm Settlement",
    description:
      "Use this when a Harbor intent is ready for final settlement confirmation and you have the signed body plus recognition proof. " +
      "Do not use this for evidence submission or capability authorization.",
    annotations: liveMutationToolAnnotations("Confirm Settlement"),
    outputSchema: outputObjectSchema({
      intent_id: { type: "string" },
      state: { type: "string" },
      receipt_id: { type: "string" },
    }),
  },
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
  toolPolicy?: McpToolPolicyConfig;
  evidencePolicy?: McpEvidencePolicy;
  policyReload?: McpPolicyReloadConfig | null;
  capabilityTokenCache?: McpCapabilityTokenCacheConfig;
};

function readIntentAllowedTools(intent: Record<string, unknown>): string[] {
  const raw = intent.allowed_tools;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0);
}

function readEnvFileValue(envFile: string, key: string): string | undefined {
  let body: string;
  try {
    body = readFileSync(envFile, "utf8");
  } catch (err) {
    if ((err as { code?: unknown })?.code === "ENOENT") return undefined;
    throw err;
  }
  const pattern = new RegExp(
    "^\\s*(?:export\\s+)?" + key + "\\s*=\\s*(.*)$",
    "m",
  );
  const match = body.match(pattern);
  if (!match) return undefined;
  let value = String(match[1] ?? "").trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      value = JSON.parse(value);
    } catch {
      value = value.slice(1, -1);
    }
  } else if (value.startsWith("'") && value.endsWith("'")) {
    value = value.slice(1, -1);
  }
  return value.trim() || undefined;
}

class GatewayHTTPError extends Error {
  readonly statusCode: number;
  readonly url: string;
  readonly bodyText: string;
  readonly errorCode?: string;
  readonly errorMessage?: string;

  constructor(
    message: string,
    init: {
      statusCode: number;
      url: string;
      bodyText: string;
      errorCode?: string;
      errorMessage?: string;
    },
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

function parseGatewayErrorEnvelope(text: string): {
  errorCode?: string;
  errorMessage?: string;
} {
  if (!text.trim().startsWith("{")) {
    return {};
  }
  try {
    const body = JSON.parse(text);
    if (body === null || Array.isArray(body) || typeof body !== "object") {
      return {};
    }
    const errorCode =
      typeof body.error === "string" && body.error.trim()
        ? body.error.trim()
        : undefined;
    const errorMessage =
      typeof body.message === "string" && body.message.trim()
        ? body.message.trim()
        : undefined;
    return { errorCode, errorMessage };
  } catch {
    return {};
  }
}

function gatewayHTTPErrorMessage(
  method: "GET" | "POST",
  path: string,
  statusCode: number,
  bodyText: string,
): string {
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

  constructor(init: {
    gatewayBaseUrl: string;
    apiKey: string;
    maxRetries?: number;
  }) {
    this.gatewayBase = normalizeBase(init.gatewayBaseUrl);
    this.apiKey = init.apiKey.trim();
    this.maxRetries = Math.max(1, init.maxRetries ?? 3);
  }

  async getJSON(
    path: string,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>> {
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
            ...(payload === undefined
              ? {}
              : { "content-type": "application/json" }),
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

      if (
        [429, 500, 502, 503, 504].includes(res.status) &&
        attempt + 1 < this.maxRetries
      ) {
        const retryAfter = parseRetryAfterSeconds(
          res.headers.get("retry-after"),
        );
        await delay(
          retryAfter != null ? retryAfter * 1000 : backoffMs(attempt),
        );
        continue;
      }

      const text = await res.text();
      if (!res.ok) {
        const parsed = parseGatewayErrorEnvelope(text);
        throw new GatewayHTTPError(
          gatewayHTTPErrorMessage(method, path, res.status, text),
          {
            statusCode: res.status,
            url,
            bodyText: text,
            errorCode: parsed.errorCode,
            errorMessage: parsed.errorMessage,
          },
        );
      }
      return parseJSONObject(text, `Gateway ${method} ${path}`);
    }

    throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
  }
}

class PaybondMCPRuntime {
  private readonly settings: Required<
    Pick<
      PaybondMCPSettings,
      "gatewayBaseUrl" | "apiKey" | "principalPath" | "maxRetries"
    >
  >;
  private readonly gateway: GatewayAPIClient;
  private principalValue: Promise<Record<string, unknown>> | null = null;
  private signalValue: Promise<GatewaySignalClient> | null = null;
  private fraudValue: Promise<GatewayFraudClient> | null = null;
  private readonly capabilityTokenCache: McpCapabilityTokenCache;
  private readonly evidenceGate: McpEvidenceValidationGate;
  private readonly policyReloadConfig: McpPolicyReloadConfig | null;
  private policyGatePromise: Promise<McpPolicyReloadGate | null> | null = null;

  constructor(settings: PaybondMCPSettings) {
    this.evidenceGate = new McpEvidenceValidationGate(
      settings.evidencePolicy ?? parseMcpEvidencePolicy(undefined),
    );
    this.capabilityTokenCache = new McpCapabilityTokenCache(
      settings.capabilityTokenCache,
    );
    this.policyReloadConfig = settings.policyReload ?? null;
    this.settings = {
      gatewayBaseUrl:
        settings.gatewayBaseUrl ?? DEFAULT_PAYBOND_GATEWAY_BASE_URL,
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

  private async policyGate(): Promise<McpPolicyReloadGate | null> {
    if (!this.policyReloadConfig) {
      return null;
    }
    this.policyGatePromise ??= McpPolicyReloadGate.open(this.policyReloadConfig, {
      gateway: createMcpPolicyGatewayAdapter(this.gateway),
    });
    return this.policyGatePromise;
  }

  async getPolicyReloadStatus(): Promise<Record<string, unknown> | null> {
    const gate = await this.policyGate();
    return gate?.status() ?? null;
  }

  async beginPolicyToolCall(): Promise<void> {
    const gate = await this.policyGate();
    gate?.beginToolCall();
  }

  async endPolicyToolCall(): Promise<void> {
    const gate = await this.policyGate();
    gate?.endToolCall();
  }

  stopPolicyReload(): void {
    void this.policyGatePromise?.then((gate) => gate?.stop());
    this.policyGatePromise = null;
  }

  async authorizeAgentSpend(init: {
    intentId: string;
    token: string;
    operation: string;
    requestedSpendCents?: number;
    toolName?: string;
  }): Promise<Record<string, unknown>> {
    const gate = await this.policyGate();
    let operation = init.operation;
    let requestedSpendCents = init.requestedSpendCents ?? 0;
    let policyDigest: string | undefined;

    if (gate) {
      const intent = await this.getIntent(init.intentId);
      const allowedTools = readIntentAllowedTools(intent);
      const gated = gate.assertSpendGate({
        toolName: init.toolName,
        operation,
        allowedTools,
        requestedSpendCents: init.requestedSpendCents,
      });
      operation = gated.operation;
      requestedSpendCents = gated.requestedSpendCents;
      policyDigest = gated.policyDigest;
    }

    const body = await this.verifyCapability({
      intentId: init.intentId,
      token: init.token,
      operation,
      requestedSpendCents,
    });
    if (policyDigest) {
      body.policy_digest = policyDigest;
    }
    return body;
  }

  private storeCapabilityToken(intentId: string, token: string): void {
    this.capabilityTokenCache.store(intentId, token);
  }

  async resolveCapabilityToken(intentId: string, token?: string): Promise<string> {
    const explicit = token?.trim();
    if (explicit) {
      return explicit;
    }
    const stored = this.capabilityTokenCache.resolve(intentId.trim());
    if (stored) {
      return stored;
    }
    throw new Error(
      `capability token unavailable or expired for intent ${intentId}; create or bootstrap a funded intent first`,
    );
  }

  prepareToolResponse(
    value: Record<string, unknown> | null,
    toolName: string,
  ): Record<string, unknown> | null {
    if (value === null) {
      return null;
    }
    const intentId = String(value.intent_id ?? "").trim();
    const token = value.capability_token;
    if (
      mcpToolStoresCapabilityToken(toolName) &&
      intentId &&
      typeof token === "string" &&
      token.trim()
    ) {
      this.storeCapabilityToken(intentId, token);
    }
    return redactSensitiveFields(value) as Record<string, unknown>;
  }

  validateCompletionEvidence(input: {
    presetId: string;
    vendorPayload?: Record<string, unknown>;
    canonicalPayload?: Record<string, unknown>;
    frozenVendorApiVersion?: string;
    frozenVendorSchemaDigestHex?: string;
    frozenCanonicalSchemaDigestHex?: string;
  }): Record<string, unknown> {
    const report = this.evidenceGate.validateAndRecord(input);
    return {
      ...report,
      ok: completionEvidenceValidationOk(report),
    };
  }

  private requireEvidenceValidation(input: {
    presetId: string;
    vendorPayload?: Record<string, unknown>;
    canonicalPayload?: Record<string, unknown>;
  }): void {
    this.evidenceGate.requirePass(input);
  }

  /**
   * Best-effort principal warm-up. Callers must not await this on the MCP
   * initialize path; principal resolves lazily on first tool use.
   */
  async preloadPrincipal(): Promise<void> {
    await this.principal();
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
      new GatewaySignalClient(
        this.settings.gatewayBaseUrl,
        await this.tenantId(),
        {
          staticGatewayBearerToken: this.settings.apiKey,
          maxRetries: this.settings.maxRetries,
        },
      ))();
    return this.signalValue;
  }

  async fraud(): Promise<GatewayFraudClient> {
    this.fraudValue ??= (async () =>
      new GatewayFraudClient(
        this.settings.gatewayBaseUrl,
        await this.tenantId(),
        {
          staticGatewayBearerToken: this.settings.apiKey,
          maxRetries: this.settings.maxRetries,
        },
      ))();
    return this.fraudValue;
  }

  async listIntents(init: {
    status?: string;
    operatorDid?: string;
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({
      limit: String(
        Math.max(1, Math.min(intArg(init.limit ?? 20, "limit"), 200)),
      ),
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
    return this.gateway.getJSON(
      `/harbor/operator/v1/intents?${params.toString()}`,
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
  }

  async getIntent(intentId: string): Promise<Record<string, unknown>> {
    return this.gateway.getJSON(
      `/harbor/operator/v1/intents/${encodeURIComponent(intentId)}`,
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
  }

  async listAuditExports(init: {
    limit?: number;
    cursor?: string;
  }): Promise<Record<string, unknown>> {
    const params = new URLSearchParams({
      limit: String(
        Math.max(1, Math.min(intArg(init.limit ?? 50, "limit"), 200)),
      ),
    });
    if (init.cursor?.trim()) {
      params.set("cursor", init.cursor.trim());
    }
    const body = await this.gateway.getJSON(
      `/v1/compliance/audit-exports?${params.toString()}`,
    );
    return body;
  }

  async getAuditExport(
    jobId: string,
    init?: { issueDownload?: boolean },
  ): Promise<Record<string, unknown>> {
    const query = init?.issueDownload ? "?issue_download=1" : "";
    return this.gateway.getJSON(
      `/v1/compliance/audit-exports/${encodeURIComponent(jobId)}${query}`,
    );
  }

  async getA2AAgentCard(): Promise<Record<string, unknown>> {
    return this.gateway.getJSON("/.well-known/agent-card.json");
  }

  async getA2ATaskContracts(): Promise<Record<string, unknown>> {
    return this.gateway.getJSON("/protocol/v2/a2a/task-contracts");
  }

  async getA2ATaskContract(
    contractId: string,
  ): Promise<Record<string, unknown>> {
    return this.gateway.getJSON(
      `/protocol/v2/a2a/task-contracts/${encodeURIComponent(contractId)}`,
    );
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
      throw new Error(
        `tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`,
      );
    }
    const echoedIntent = String(body.intent_id ?? "").trim();
    if (echoedIntent !== init.intentId) {
      throw new Error(
        `verify intent mismatch: requested=${init.intentId} gateway=${echoedIntent}`,
      );
    }
    return body;
  }

  /**
   * Side-effect-free spend policy dry-run via `POST /v1/spend/preflight`.
   * Tenant scope comes from the authenticated API key only.
   */
  async spendPreflight(init: {
    intentId: string;
    operation?: string;
    requestedSpendCents?: number;
    vendorId?: string;
    toolName?: string;
    taskId?: string;
    workflowId?: string;
    toolCallId?: string;
    currency?: string;
    agentSubject?: string;
    approvalToken?: string;
  }): Promise<Record<string, unknown>> {
    const payload: Record<string, unknown> = {
      intent_id: init.intentId,
      operation: init.operation?.trim() || "*",
      requested_spend_cents: init.requestedSpendCents ?? 0,
    };
    if (init.vendorId?.trim()) {
      payload.vendor_id = init.vendorId.trim();
    }
    if (init.toolName?.trim()) {
      payload.tool_name = init.toolName.trim();
    }
    if (init.taskId?.trim()) {
      payload.task_id = init.taskId.trim();
    }
    if (init.workflowId?.trim()) {
      payload.workflow_id = init.workflowId.trim();
    }
    if (init.toolCallId?.trim()) {
      payload.tool_call_id = init.toolCallId.trim();
    }
    if (init.currency?.trim()) {
      payload.currency = init.currency.trim();
    }
    if (init.agentSubject?.trim()) {
      payload.agent_subject = init.agentSubject.trim();
    }
    if (init.approvalToken?.trim()) {
      payload.approval_token = init.approvalToken.trim();
    }
    return this.gateway.postJSON("/v1/spend/preflight", payload, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async getBudgetRemaining(init: {
    intentId: string;
    operation?: string;
    requestedSpendCents?: number;
    vendorId?: string;
    toolName?: string;
    taskId?: string;
    workflowId?: string;
    toolCallId?: string;
    currency?: string;
    agentSubject?: string;
    approvalToken?: string;
  }): Promise<Record<string, unknown>> {
    const body = await this.spendPreflight(init);
    return {
      remaining_cents: body.remaining_cents ?? null,
      spend_scope: body.spend_scope ?? null,
      policy_version: body.policy_version ?? null,
    };
  }

  async explainPolicy(init: {
    intentId: string;
    operation?: string;
    requestedSpendCents?: number;
    vendorId?: string;
    toolName?: string;
    taskId?: string;
    workflowId?: string;
    toolCallId?: string;
    currency?: string;
    agentSubject?: string;
    approvalToken?: string;
  }): Promise<Record<string, unknown>> {
    const body = await this.spendPreflight(init);
    const reasonCodes = Array.isArray(body.reason_codes)
      ? body.reason_codes.map((code) => String(code))
      : [];
    const outcome = normalizeExplainPolicyOutcome(
      String(body.outcome ?? ""),
      String(body.classification ?? ""),
    );
    const result: Record<string, unknown> = {
      outcome,
      reason_codes: reasonCodes,
      explanation: String(body.explanation ?? ""),
      remaining_cents: body.remaining_cents ?? null,
    };
    if (
      reasonCodes.includes("approval_threshold_exceeded") ||
      outcome === "approval_required"
    ) {
      result.approval_threshold_exceeded = reasonCodes.includes(
        "approval_threshold_exceeded",
      );
    }
    return result;
  }

  async bootstrapSandboxGuardrail(init: {
    operation: string;
    requestedSpendCents: number;
    currency?: string;
    evidenceSchema?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    const expectedTenant = await this.tenantId();
    const payload: Record<string, unknown> = {
      operation: init.operation,
      requested_spend_cents: init.requestedSpendCents,
    };
    if (init.currency?.trim()) {
      payload.currency = init.currency.trim();
    }
    if (init.evidenceSchema !== undefined) {
      payload.evidence_schema = init.evidenceSchema;
    }
    if (init.metadata !== undefined) {
      payload.metadata = init.metadata;
    }
    const body = await this.gateway.postJSON(
      "/v1/sandbox/guardrails/bootstrap",
      payload,
      optionalMutationHeaders(init.idempotencyKey),
    );
    assertSandboxGuardrailTenant(body, expectedTenant);
    stringArg(body.intent_id, "intent_id");
    stringArg(body.capability_token, "capability_token");
    stringArg(body.operation, "operation");
    intArg(body.requested_spend_cents, "requested_spend_cents");
    stringArg(body.sandbox_lifecycle_status, "sandbox_lifecycle_status");
    return body;
  }

  async submitSandboxGuardrailEvidence(init: {
    intentId: string;
    payload?: Record<string, unknown>;
    artifacts?: string[];
    operation?: string;
    requestedSpendCents?: number;
    metadata?: Record<string, unknown>;
    completionPresetId?: string;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    const extracted = extractSandboxGuardrailValidationInput({
      payload: init.payload,
      completionPresetId: init.completionPresetId,
    });
    this.requireEvidenceValidation(extracted);
    const expectedTenant = await this.tenantId();
    const payload: Record<string, unknown> = {};
    if (init.payload !== undefined) {
      payload.payload = init.payload;
    }
    if (init.artifacts !== undefined) {
      payload.artifacts = init.artifacts;
    }
    if (init.operation?.trim()) {
      payload.operation = init.operation.trim();
    }
    if (init.requestedSpendCents !== undefined) {
      payload.requested_spend_cents = init.requestedSpendCents;
    }
    if (init.metadata !== undefined) {
      payload.metadata = init.metadata;
    }
    const body = await this.gateway.postJSON(
      `/v1/sandbox/guardrails/${encodeURIComponent(init.intentId)}/evidence`,
      payload,
      optionalMutationHeaders(init.idempotencyKey),
    );
    assertSandboxGuardrailTenant(body, expectedTenant);
    const echoedIntent = stringArg(body.intent_id, "intent_id");
    if (echoedIntent !== init.intentId) {
      throw new Error(
        `sandbox guardrail intent mismatch: requested=${init.intentId} gateway=${echoedIntent}`,
      );
    }
    stringArg(body.operation, "operation");
    intArg(body.requested_spend_cents, "requested_spend_cents");
    stringArg(body.sandbox_lifecycle_status, "sandbox_lifecycle_status");
    return body;
  }

  async verifyAgentMandateV1(
    signedMandate: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      "/protocol/v2/mandates/verify",
      signedMandate,
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
  }

  async verifyAgentRecognitionProofV1(init: {
    proof: Record<string, unknown>;
    expectedPurpose: string;
    expectedRequest: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const verifier = {
      tenant_id: await this.tenantId(),
      verifier_id: DEFAULT_RECOGNITION_VERIFIER_ID,
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
    const authorization = ensureObject(
      mandate.authorization,
      "mandate.authorization",
    );
    const echoedTenant = String(authorization.tenant_id ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(
        `tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`,
      );
    }
    const echoedIntent = String(body.intent_id ?? "").trim();
    if (echoedIntent !== init.intentId) {
      throw new Error(
        `intent mismatch: requested=${init.intentId} gateway=${echoedIntent}`,
      );
    }
    return body;
  }

  async getSettlementReceiptV1(
    receiptId: string,
  ): Promise<Record<string, unknown>> {
    const body = await this.gateway.getJSON(
      `/protocol/v2/receipts/${encodeURIComponent(receiptId)}`,
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
    const expectedTenant = await this.tenantId();
    const echoedTenant = String(body.tenant_id ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(
        `tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`,
      );
    }
    const echoedReceipt = String(body.receipt_id ?? "").trim();
    if (echoedReceipt !== receiptId) {
      throw new Error(
        `receipt mismatch: requested=${receiptId} gateway=${echoedReceipt}`,
      );
    }
    return body;
  }

  async verifyProtocolReceiptV1(
    receipt: Record<string, unknown>,
  ): Promise<Record<string, unknown>> {
    return this.gateway.postJSON("/protocol/v2/receipts/verify", receipt, {
      "x-tenant-id": await this.tenantId(),
    });
  }

  async getAgentReceiptV1(receiptId: string): Promise<Record<string, unknown>> {
    const normalized = receiptId.trim().toLowerCase();
    const body = await this.gateway.getJSON(
      `/protocol/v2/agent-receipts/${encodeURIComponent(normalized)}`,
      {
        "x-tenant-id": await this.tenantId(),
      },
    );
    const expectedTenant = await this.tenantId();
    const echoedTenant = String(body.tenant_id ?? "").trim();
    if (echoedTenant !== expectedTenant) {
      throw new Error(
        `tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`,
      );
    }
    const echoedReceipt = String(body.receipt_id ?? "").trim().toLowerCase();
    if (echoedReceipt !== normalized) {
      throw new Error(
        `receipt mismatch: requested=${normalized} gateway=${echoedReceipt}`,
      );
    }
    return body;
  }

  async createHarborIntent(init: {
    body: Record<string, unknown>;
    recognitionProof: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    return this.gateway.postJSON(
      "/harbor/intents",
      init.body,
      gatewayMutationHeaders(
        await this.tenantId(),
        init.recognitionProof,
        optionalMutationHeaders(init.idempotencyKey),
      ),
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
        ...(init.paymentSignature?.trim()
          ? { "payment-signature": init.paymentSignature.trim() }
          : {}),
      }),
    );
  }

  async submitHarborEvidence(init: {
    intentId: string;
    body: Record<string, unknown>;
    recognitionProof: Record<string, unknown>;
    completionPresetId?: string;
    idempotencyKey?: string;
  }): Promise<Record<string, unknown>> {
    const extracted = extractHarborEvidenceValidationInput(
      init.body,
      init.completionPresetId,
    );
    this.requireEvidenceValidation(extracted);
    return this.gateway.postJSON(
      `/harbor/intents/${encodeURIComponent(init.intentId)}/evidence`,
      init.body,
      gatewayMutationHeaders(
        await this.tenantId(),
        init.recognitionProof,
        optionalMutationHeaders(init.idempotencyKey),
      ),
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
      gatewayMutationHeaders(
        await this.tenantId(),
        init.recognitionProof,
        optionalMutationHeaders(init.idempotencyKey),
      ),
    );
  }
}

function optionalMutationHeaders(
  idempotencyKey?: string,
): Record<string, string> {
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
    [agentRecognitionProofHeader]:
      encodeRecognitionProofHeader(recognitionProof),
  };
}

export function formatMcpStdioFrame(response: JSONRPCResponse): string {
  const body = JSON.stringify(response);
  return `Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`;
}

/** Newline-delimited JSON-RPC frame used by mcp-proxy and recent MCP SDKs. */
export function formatMcpNdjsonFrame(response: JSONRPCResponse): string {
  return `${JSON.stringify(response)}\n`;
}

type McpStdioFraming = "content-length" | "ndjson";

export class PaybondMCPServer {
  private readonly runtime: PaybondMCPRuntime;
  private readonly tools: MCPToolDefinition[];
  private readonly toolPolicy: McpToolPolicyConfig;
  private initialized = false;
  /** Framing negotiated from the first successfully parsed stdin message. */
  private stdioFraming: McpStdioFraming = "content-length";

  constructor(settings: PaybondMCPSettings) {
    if (!settings.apiKey.trim()) {
      throw new Error("PAYBOND_API_KEY is required");
    }
    this.toolPolicy = resolveMcpToolPolicy(
      settings.toolPolicy ?? { policy: null, allowlist: [] },
    );
    this.runtime = new PaybondMCPRuntime(settings);
    this.tools = this.buildTools(settings).filter((tool) =>
      toolAllowedByPolicy(tool.name, tool.annotations, this.toolPolicy),
    );
  }

  listResourceTemplates(): Array<Record<string, unknown>> {
    return [agentReceiptResourceTemplateDefinition()];
  }

  async readResource(uri: string): Promise<{
    uri: string;
    mimeType: string;
    text: string;
    _meta?: Record<string, unknown>;
  }> {
    const receiptId = parseAgentReceiptResourceUri(uri);
    const receipt = await this.runtime.getAgentReceiptV1(receiptId);
    let verified;
    try {
      verified = await verifyAgentReceiptV1FromJSON(receipt);
    } catch (err) {
      throw new Error(
        `agent receipt verification failed for ${receiptId}: ${formatError(err)}`,
      );
    }
    return {
      uri: agentReceiptResourceUri(receiptId),
      mimeType: MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
      text: JSON.stringify(receipt, null, 2),
      _meta: {
        verification: {
          valid: true,
          message_digest: verified.message_digest_sha256_hex,
        },
      },
    };
  }

  listTools(): Array<Record<string, unknown>> {
    return this.tools.map((tool) => ({
      name: tool.name,
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema,
      ...(tool.outputSchema === undefined
        ? {}
        : { outputSchema: tool.outputSchema }),
      ...(tool.annotations === undefined
        ? {}
        : { annotations: tool.annotations }),
    }));
  }

  async callTool(
    name: string,
    args: Record<string, unknown> = {},
  ): Promise<MCPCallToolResult> {
    const tool = this.tools.find((candidate) => candidate.name === name);
    if (!tool) {
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
    }
    if (!toolAllowedByPolicy(name, tool.annotations, this.toolPolicy)) {
      return {
        content: [
          {
            type: "text",
            text: `Tool blocked by ${MCP_TOOL_POLICY_ENV}=${this.toolPolicy.policy ?? "spend-write"}: ${name}`,
          },
        ],
        isError: true,
      };
    }
    try {
      await this.runtime.beginPolicyToolCall();
      try {
        const value = await tool.call(args);
        return toToolResult(
          this.runtime.prepareToolResponse(
            value === null ? null : (value as Record<string, unknown>),
            name,
          ),
        );
      } finally {
        await this.runtime.endPolicyToolCall();
      }
    } catch (err) {
      return {
        content: [{ type: "text", text: formatError(err) }],
        isError: true,
      };
    }
  }

  async handleMessage(
    message: JSONRPCRequest,
  ): Promise<JSONRPCResponse | null> {
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
        // Do not block the MCP handshake on Gateway principal preload. Registry
        // hosts time out initialize if egress is slow or blocked; principal is
        // resolved lazily on the first tool that needs it.
        void this.runtime.preloadPrincipal().catch(() => {
          // Best-effort warm cache; failures surface on subsequent tool calls.
        });
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities: {
              tools: {
                listChanged: false,
              },
              resources: {
                subscribe: false,
                listChanged: false,
              },
            },
            serverInfo: {
              name: SERVER_NAME,
              title: "Paybond MCP",
              version: SERVER_VERSION,
              description:
                "Tenant-bound Paybond gateway tools for agent spend controls, Harbor intents, Signal reputation, fraud review, and protocol verification.",
              websiteUrl: "https://paybond.ai",
            },
            instructions:
              "This MCP server is tenant-bound to the configured Paybond service-account API key. " +
              "Use paybond_create_spend_intent or paybond_bootstrap_sandbox_guardrail to obtain a funded intent_id, " +
              "then call paybond_authorize_agent_spend before side-effecting tools. Capability tokens are stored " +
              "inside this MCP server and are not returned to agent logs. It works with any MCP-compatible host " +
              "and does not assume a specific model provider.",
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
      case "resources/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            resources: [],
          },
        };
      case "resources/templates/list":
        return {
          jsonrpc: "2.0",
          id: message.id,
          result: {
            resourceTemplates: this.listResourceTemplates(),
          },
        };
      case "resources/read": {
        const params = ensureObject(message.params, "resources/read params");
        const uri = stringArg(params.uri, "uri");
        try {
          const contents = await this.readResource(uri);
          return {
            jsonrpc: "2.0",
            id: message.id,
            result: {
              contents: [contents],
            },
          };
        } catch (err) {
          return responseError(message.id, -32000, formatError(err));
        }
      }
      case "tools/call": {
        const params = ensureObject(message.params, "tools/call params");
        const name = stringArg(params.name, "name");
        const args =
          params.arguments === undefined
            ? {}
            : ensureObject(params.arguments, "arguments");
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
    let buffer = Buffer.alloc(0);
    process.stdin.on("data", (chunk: string | Buffer) => {
      buffer = Buffer.concat([
        buffer,
        Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8"),
      ]);
      // Prefer Content-Length frames when present (LSP-style MCP hosts).
      while (true) {
        const headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
          break;
        }
        const headerText = buffer.subarray(0, headerEnd).toString("ascii");
        const contentLength = Number.parseInt(
          headerText
            .split("\r\n")
            .find((line) => line.toLowerCase().startsWith("content-length:"))
            ?.split(":", 2)[1]
            ?.trim() ?? "",
          10,
        );
        if (!Number.isFinite(contentLength) || contentLength <= 0) {
          break;
        }
        const bodyStart = headerEnd + 4;
        const frameEnd = bodyStart + contentLength;
        if (buffer.length < frameEnd) {
          break;
        }
        const body = buffer.subarray(bodyStart, frameEnd).toString("utf8");
        buffer = buffer.subarray(frameEnd);
        this.stdioFraming = "content-length";
        void this.handleLine(body);
      }

      // Do not let NDJSON parsing consume an in-progress Content-Length frame.
      const preview = buffer
        .subarray(0, Math.min(buffer.length, 64))
        .toString("utf8")
        .trimStart()
        .toLowerCase();
      if (preview.startsWith("content-length:")) {
        return;
      }

      // Newline-delimited JSON-RPC (mcp-proxy / recent MCP SDKs).
      while (true) {
        const newline = buffer.indexOf("\n");
        if (newline < 0) {
          break;
        }
        const rawLine = buffer
          .subarray(0, newline)
          .toString("utf8")
          .replace(/\r$/, "");
        buffer = buffer.subarray(newline + 1);
        const line = rawLine.trim();
        if (!line.startsWith("{")) {
          continue;
        }
        this.stdioFraming = "ndjson";
        void this.handleLine(line);
      }
    });
    process.stdin.on("end", () => {
      if (buffer.length > 0) {
        void this.handleLine(buffer.toString("utf8"));
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
    const frame =
      this.stdioFraming === "ndjson"
        ? formatMcpNdjsonFrame(response)
        : formatMcpStdioFrame(response);
    process.stdout.write(frame);
  }

  private buildTools(settings: PaybondMCPSettings): MCPToolDefinition[] {
    const tools: MCPToolDefinition[] = [
      {
        name: "paybond_get_principal",
        description:
          "Use this when you need to confirm which tenant-bound service-account principal the configured PAYBOND_API_KEY authenticates as " +
          "(tenant_id, subject, and roles). Call early as a prerequisite before Harbor escrow, Signal reads, or other tenant-scoped tools when " +
          "tenant identity is unknown. Not required before every later call once tenant_id is already known from a prior principal response or host config. " +
          "Do not use this when you need Harbor intent escrow detail; use paybond_get_intent instead when you have an intent_id. " +
          "Do not use this for A2A discovery; use paybond_get_a2a_agent_card instead. " +
          "Makes one read-only external GET to the gateway principal endpoint; idempotent identity lookup with no side effects " +
          "(no mutations, spend reservations, escrow changes, or ledger writes); auth or gateway failures surface as tool errors.",
        inputSchema: emptyObjectSchema(),
        call: async () => this.runtime.principal(),
      },
      {
        name: "paybond_verify_capability",
        description:
          "Verify a capability token returned by a created or funded Paybond intent for one tenant-bound Harbor intent.",
        inputSchema: objectSchema(
          {
            intent_id: {
              type: "string",
              description: "Canonical Harbor intent UUID.",
            },
            token: {
              type: "string",
              description:
                "Optional capability token override. When omitted, the MCP server uses the token stored for intent_id.",
            },
            operation: {
              type: "string",
              description: "Delegated operation or tool name.",
            },
            requested_spend_cents: {
              type: "integer",
              description:
                "Optional requested spend in cents for this tool call.",
            },
          },
          ["intent_id", "operation"],
        ),
        call: async (args) => {
          const intentId = uuidArg(args.intent_id, "intent_id");
          return this.runtime.authorizeAgentSpend({
            intentId,
            token: await this.runtime.resolveCapabilityToken(
              intentId,
              optionalString(args.token),
            ),
            operation: stringArg(args.operation, "operation"),
            requestedSpendCents:
              args.requested_spend_cents === undefined
                ? undefined
                : intArg(args.requested_spend_cents, "requested_spend_cents"),
            toolName: stringArg(args.operation, "operation"),
          });
        },
      },
      {
        name: "paybond_authorize_agent_spend",
        description:
          "Provider-agnostic spend gate: verify the funded intent's capability token before a side-effecting tool, paid API, vendor action, or settlement workflow executes.",
        inputSchema: objectSchema(
          {
            intent_id: {
              type: "string",
              description: "Canonical Harbor intent UUID.",
            },
            token: {
              type: "string",
              description:
                "Optional capability token override. When omitted, the MCP server uses the token stored for intent_id.",
            },
            operation: {
              type: "string",
              description: "Delegated operation or tool name.",
            },
            requested_spend_cents: {
              type: "integer",
              description:
                "Optional requested spend in cents for this tool call.",
            },
          },
          ["intent_id", "operation"],
        ),
        call: async (args) => {
          const intentId = uuidArg(args.intent_id, "intent_id");
          return this.runtime.authorizeAgentSpend({
            intentId,
            token: await this.runtime.resolveCapabilityToken(
              intentId,
              optionalString(args.token),
            ),
            operation: stringArg(args.operation, "operation"),
            requestedSpendCents:
              args.requested_spend_cents === undefined
                ? undefined
                : intArg(args.requested_spend_cents, "requested_spend_cents"),
            toolName: stringArg(args.operation, "operation"),
          });
        },
      },
      {
        name: "paybond_get_budget_remaining",
        description:
          "Read-only dry-run of remaining spend budget for a tenant-bound intent via gateway spend preflight.",
        inputSchema: spendPreflightInputSchema(),
        call: async (args) =>
          this.runtime.getBudgetRemaining(parseSpendPreflightArgs(args)),
      },
      {
        name: "paybond_explain_policy",
        description:
          "Read-only dry-run explanation of whether proposed spend would allow, require approval, or deny under tenant spend policy.",
        inputSchema: spendPreflightInputSchema(),
        call: async (args) =>
          this.runtime.explainPolicy(parseSpendPreflightArgs(args)),
      },
      {
        name: "paybond_bootstrap_sandbox_guardrail",
        description:
          "Bootstrap a sandbox-only Paybond guardrail intent for a first paid-tool integration. Tenant scope is derived from the configured service-account API key and the route never touches live settlement rails.",
        inputSchema: objectSchema(
          {
            operation: {
              type: "string",
              description: "Delegated operation or paid tool name.",
            },
            requested_spend_cents: {
              type: "integer",
              description:
                "Sandbox spend amount in cents to authorize for the sample tool call.",
            },
            currency: {
              type: "string",
              description:
                "Optional ISO currency code; defaults at the gateway.",
            },
            evidence_schema: { type: "object", additionalProperties: true },
            metadata: { type: "object", additionalProperties: true },
            idempotency_key: { type: "string" },
          },
          ["operation", "requested_spend_cents"],
        ),
        call: async (args) =>
          this.runtime.bootstrapSandboxGuardrail({
            operation: stringArg(args.operation, "operation"),
            requestedSpendCents: intArg(
              args.requested_spend_cents,
              "requested_spend_cents",
            ),
            currency: optionalString(args.currency),
            evidenceSchema:
              args.evidence_schema === undefined
                ? undefined
                : ensureObject(args.evidence_schema, "evidence_schema"),
            metadata:
              args.metadata === undefined
                ? undefined
                : ensureObject(args.metadata, "metadata"),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_validate_completion_evidence",
        description:
          "Pre-validates completion evidence against the shared preset catalog. Call this before paybond_submit_*_evidence when PAYBOND_MCP_EVIDENCE_POLICY=strict.",
        inputSchema: objectSchema(
          {
            preset_id: { type: "string" },
            vendor_payload: { type: "object", additionalProperties: true },
            canonical_payload: { type: "object", additionalProperties: true },
            frozen_vendor_api_version: { type: "string" },
            frozen_vendor_schema_digest_hex: { type: "string" },
            frozen_canonical_schema_digest_hex: { type: "string" },
          },
          ["preset_id"],
        ),
        call: async (args) =>
          this.runtime.validateCompletionEvidence({
            presetId: stringArg(args.preset_id, "preset_id"),
            vendorPayload:
              args.vendor_payload === undefined
                ? undefined
                : ensureObject(args.vendor_payload, "vendor_payload"),
            canonicalPayload:
              args.canonical_payload === undefined
                ? undefined
                : ensureObject(args.canonical_payload, "canonical_payload"),
            frozenVendorApiVersion: optionalString(args.frozen_vendor_api_version),
            frozenVendorSchemaDigestHex: optionalString(args.frozen_vendor_schema_digest_hex),
            frozenCanonicalSchemaDigestHex: optionalString(args.frozen_canonical_schema_digest_hex),
          }),
      },
      {
        name: "paybond_submit_sandbox_guardrail_evidence",
        description:
          "Submit evidence for a sandbox-only Paybond guardrail intent. Tenant scope is derived from the configured service-account API key and simulator settlement remains sandbox-only.",
        inputSchema: objectSchema(
          {
            intent_id: {
              type: "string",
              description: "Sandbox guardrail intent UUID.",
            },
            payload: { type: "object", additionalProperties: true },
            artifacts: { type: "array", items: { type: "string" } },
            operation: {
              type: "string",
              description:
                "Optional operation override for the evidence record.",
            },
            requested_spend_cents: {
              type: "integer",
              description:
                "Optional sandbox spend amount override for the evidence record.",
            },
            metadata: { type: "object", additionalProperties: true },
            completion_preset_id: { type: "string" },
            idempotency_key: { type: "string" },
          },
          ["intent_id"],
        ),
        call: async (args) =>
          this.runtime.submitSandboxGuardrailEvidence({
            intentId: uuidArg(args.intent_id, "intent_id"),
            payload:
              args.payload === undefined
                ? undefined
                : ensureObject(args.payload, "payload"),
            artifacts:
              args.artifacts === undefined
                ? undefined
                : stringArrayArg(args.artifacts, "artifacts"),
            operation: optionalString(args.operation),
            requestedSpendCents:
              args.requested_spend_cents === undefined
                ? undefined
                : intArg(args.requested_spend_cents, "requested_spend_cents"),
            metadata:
              args.metadata === undefined
                ? undefined
                : ensureObject(args.metadata, "metadata"),
            completionPresetId: optionalString(args.completion_preset_id),
            idempotencyKey: optionalString(args.idempotency_key),
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
        description:
          "Fetch one tenant-scoped Harbor intent detail through the gateway operator view.",
        inputSchema: objectSchema(
          {
            intent_id: {
              type: "string",
              description: "Canonical Harbor intent UUID.",
            },
          },
          ["intent_id"],
        ),
        call: async (args) =>
          this.runtime.getIntent(uuidArg(args.intent_id, "intent_id")),
      },
      {
        name: "paybond_list_audit_exports",
        description:
          "List tenant-scoped compliance audit export jobs through the gateway operator view.",
        inputSchema: objectSchema({
          limit: { type: "integer", minimum: 1, maximum: 200 },
          cursor: { type: "string" },
        }),
        call: async (args) =>
          this.runtime.listAuditExports({
            limit: args.limit === undefined ? undefined : intArg(args.limit, "limit"),
            cursor: optionalString(args.cursor),
          }),
      },
      {
        name: "paybond_get_audit_export",
        description:
          "Fetch one tenant-scoped compliance audit export job detail through the gateway operator view.",
        inputSchema: objectSchema(
          {
            job_id: {
              type: "string",
              description: "Compliance audit export job identifier.",
            },
            issue_download: {
              type: "boolean",
              description: "When true, request a bundle download token for ready exports.",
            },
          },
          ["job_id"],
        ),
        call: async (args) =>
          this.runtime.getAuditExport(stringArg(args.job_id, "job_id"), {
            issueDownload: args.issue_download === true,
          }),
      },
      {
        name: "paybond_get_reputation_receipt",
        description: "Fetch the signed Signal receipt for one operator DID.",
        inputSchema: objectSchema(
          {
            operator_did: {
              type: "string",
              description:
                "Tenant-scoped operator DID whose signed Signal reputation receipt to fetch. Must belong to the authenticated tenant; do not invent tenant identifiers. Examples: did:web:vendor.example#booker-agent, did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.",
              examples: [
                "did:web:vendor.example#booker-agent",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              ],
            },
            score_version: {
              type: "string",
              description:
                "Optional Signal score model version to query. Omit to use the gateway default current model (1.0). Example: 1.0.",
              examples: ["1.0"],
            },
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
          score_version: {
            type: "string",
            description:
              "Optional Signal score model version to query. Omit to use the gateway default current model (1.0). Example: 1.0.",
            examples: ["1.0"],
          },
        }),
        call: async (args) =>
          (await this.runtime.signal()).getPortfolioSummary(
            optionalString(args.score_version),
          ),
      },
      {
        name: "paybond_get_signed_portfolio_artifact",
        description:
          "Fetch the tenant-scoped signed Signal portfolio artifact for portable verifier and partner sharing.",
        inputSchema: objectSchema({
          score_version: {
            type: "string",
            description:
              "Optional Signal score model version to query. Omit to use the gateway default current model (1.0). Example: 1.0.",
            examples: ["1.0"],
          },
        }),
        call: async (args) =>
          (await this.runtime.signal()).getSignedPortfolioArtifact(
            optionalString(args.score_version),
          ),
      },
      {
        name: "paybond_get_fraud_assessment",
        description:
          "Fetch the read-only fraud assessment for one tenant-scoped operator DID.",
        inputSchema: objectSchema(
          {
            operator_did: {
              type: "string",
              description:
                "Tenant-scoped operator DID to assess. Must belong to the authenticated tenant; do not invent tenant identifiers. Examples: did:web:vendor.example#booker-agent, did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.",
              examples: [
                "did:web:vendor.example#booker-agent",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
              ],
            },
            score_version: {
              type: "string",
              description:
                "Optional Signal score model version to query. Omit to use the gateway default current model. Example: 1.0.",
              examples: ["1.0"],
            },
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
        description:
          "Fetch tenant-scoped read-only fraud backtesting and monitoring metrics for a supported active window.",
        inputSchema: objectSchema({
          window: {
            type: "string",
            enum: ["24h", "7d", "30d"],
            description:
              "Rolling metrics window. Allowed values: 24h, 7d, 30d. Omit to use the gateway default 24h. Unsupported values fail with HTTP 400.",
            examples: ["24h", "7d", "30d"],
          },
          score_version: {
            type: "string",
            description:
              "Optional Signal score model version to query. Omit to use the gateway default current model (1.0). Example: 1.0.",
            examples: ["1.0"],
          },
        }),
        call: async (args) =>
          (await this.runtime.fraud()).getFraudMetrics({
            window: optionalString(args.window),
            scoreVersion: optionalString(args.score_version),
          }),
      },
      {
        name: "paybond_get_a2a_agent_card",
        description:
          "Fetch the published Paybond A2A discovery card for protocol-trust delegation.",
        inputSchema: objectSchema({}),
        call: async () => this.runtime.getA2AAgentCard(),
      },
      {
        name: "paybond_list_a2a_task_contracts",
        description:
          "Fetch the published catalog of Paybond A2A task contracts for delegated Harbor workflows.",
        inputSchema: objectSchema({}),
        call: async () => this.runtime.getA2ATaskContracts(),
      },
      {
        name: "paybond_get_a2a_task_contract",
        description:
          "Fetch one published Paybond A2A task contract by identifier.",
        inputSchema: objectSchema(
          {
            contract_id: { type: "string" },
          },
          ["contract_id"],
        ),
        call: async (args) =>
          this.runtime.getA2ATaskContract(
            stringArg(args.contract_id, "contract_id"),
          ),
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
          this.runtime.verifyAgentMandateV1(
            ensureObject(args.signed_mandate, "signed_mandate"),
          ),
      },
      {
        name: "paybond_verify_agent_recognition_proof_v1",
        description:
          "Verify a replay-safe AgentRecognitionProofV1 against an expected purpose and request envelope. " +
          "Verifier context (tenant_id, verifier_id) is derived from the authenticated MCP session only.",
        inputSchema: objectSchema(
          {
            proof: { type: "object", additionalProperties: true },
            expected_purpose: { type: "string" },
            expected_request: { type: "object", additionalProperties: true },
          },
          ["proof", "expected_purpose", "expected_request"],
        ),
        call: async (args) =>
          this.runtime.verifyAgentRecognitionProofV1({
            proof: ensureObject(args.proof, "proof"),
            expectedPurpose: stringArg(
              args.expected_purpose,
              "expected_purpose",
            ),
            expectedRequest: ensureObject(
              args.expected_request,
              "expected_request",
            ),
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
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            transportBinding:
              args.transport_binding === undefined
                ? undefined
                : ensureObject(args.transport_binding, "transport_binding"),
          }),
      },
      {
        name: "paybond_get_settlement_receipt_v1",
        description:
          "Fetch the signed protocol-v2 settlement receipt for one Harbor intent.",
        inputSchema: objectSchema(
          {
            receipt_id: { type: "string" },
          },
          ["receipt_id"],
        ),
        call: async (args) =>
          this.runtime.getSettlementReceiptV1(
            uuidArg(args.receipt_id, "receipt_id"),
          ),
      },
      {
        name: "paybond_get_agent_receipt_v1",
        description:
          "Fetch the signed paybond.agent_receipt_v1 for one receipt_id.",
        inputSchema: objectSchema(
          {
            receipt_id: {
              type: "string",
              description:
                "Agent receipt id: lowercase SHA-256 hex (action scope) or canonical UUID (intent_terminal). " +
                "Must belong to the authenticated tenant; do not invent tenant identifiers.",
            },
          },
          ["receipt_id"],
        ),
        call: async (args) =>
          this.runtime.getAgentReceiptV1(agentReceiptIdArg(args.receipt_id)),
      },
      {
        name: "paybond_verify_agent_receipt_v1",
        description:
          "Verify a signed paybond.agent_receipt_v1 offline (operational tier by default).",
        inputSchema: objectSchema(
          {
            receipt: {
              type: "object",
              additionalProperties: true,
              description:
                "Complete signed paybond.agent_receipt_v1 object (not a receipt_id string). " +
                "Obtain from paybond_get_agent_receipt_v1, paybond://receipt/{receipt_id}, " +
                "audit export (agent_receipts/{id}.json; PEF companions may also appear as *.pef.json), " +
                "or partner handoff—do not invent digests or signatures.",
            },
            validity_tier: {
              type: "string",
              description:
                "Optional validity bar: operational (default), primary, or attested. " +
                "Higher tiers are auditor-oriented; MCP handoff only requires operational.",
              enum: ["operational", "primary", "attested"],
            },
          },
          ["receipt"],
        ),
        call: async (args) => {
          const receipt = ensureObject(args.receipt, "receipt");
          const validityTier =
            args.validity_tier === undefined
              ? "operational"
              : stringArg(args.validity_tier, "validity_tier").toLowerCase();
          let verified;
          try {
            verified = await verifyAgentReceiptV1FromJSON(receipt, {
              requiredValidityTier: validityTier,
            });
          } catch (err) {
            throw new Error(
              `agent receipt verification failed: ${formatError(err)}`,
            );
          }
          return {
            valid: true,
            kind: AGENT_RECEIPT_KIND_V1,
            receipt_id: verified.receipt_id,
            tenant_id: verified.tenant_id,
            validity_tier: validityTier,
            receipt: verified as unknown as Record<string, unknown>,
          };
        },
      },
      {
        name: "paybond_verify_protocol_receipt_v1",
        description:
          "Verify a signed protocol-v2 authorization or settlement receipt through the gateway.",
        inputSchema: objectSchema(
          {
            receipt: {
              type: "object",
              additionalProperties: true,
              description:
                "Complete signed protocol receipt object posted as the verify request body (not a receipt_id string). " +
                "Discriminate on kind: paybond.protocol_authorization_receipt_v1 requires schema_version=1, receipt_version=\"1\", receipt_id, issued_at, status (authorized), intent_id, tenant_id, verifier_id, transport_binding, mandate_digest_sha256_hex, imported_mandate_signing_public_key_ed25519_hex, authorization, agent, allowed_actions, allowed_tools, spend_ceiling, settlement, constraint, expires_at, nonce, human_presence_mode, plus signing_algorithm=ed25519-sha256-json-v1, message_digest_sha256_hex, signing_public_key_ed25519_hex, and ed25519_signature_hex. " +
                "paybond.protocol_settlement_receipt_v1 requires schema_version=1, receipt_version=\"1\", receipt_id, issued_at, intent_id, tenant_id, verifier_id, transport_binding, authorization_receipt_id, mandate_digest_sha256_hex, harbor_state, settlement_rail, settlement_mode, principal_did, payee_did, currency, amount_cents, terminal_observed_at, optional predicate_passed, and the same Ed25519 signing fields. " +
                "Obtain receipts from mandate import, paybond_get_settlement_receipt_v1, audit export, or partner handoff—do not invent digests or signatures.",
            },
          },
          ["receipt"],
        ),
        call: async (args) =>
          this.runtime.verifyProtocolReceiptV1(
            ensureObject(args.receipt, "receipt"),
          ),
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
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_create_spend_intent",
        description:
          "Create a signed Paybond spend intent through the gateway /harbor route. Use this when an agent workflow needs bounded budget, allowed operations, evidence, and settlement review. If the selected rail funds immediately, use the returned intent_id and capability_token with paybond_authorize_agent_spend.",
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
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_fund_intent",
        description:
          "Advance Harbor funding through the gateway /harbor path with a replay-safe recognition proof. When funding succeeds, use the returned capability_token with intent_id in paybond_authorize_agent_spend.",
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
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
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
            completion_preset_id: { type: "string" },
            idempotency_key: { type: "string" },
          },
          ["intent_id", "body", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.submitHarborEvidence({
            intentId: uuidArg(args.intent_id, "intent_id"),
            body: ensureObject(args.body, "body"),
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            completionPresetId: optionalString(args.completion_preset_id),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
      {
        name: "paybond_submit_spend_evidence",
        description:
          "Submit signed evidence for a Paybond spend intent so release, refund, review, and receipt generation use the same audit-ready record.",
        inputSchema: objectSchema(
          {
            intent_id: { type: "string" },
            body: { type: "object", additionalProperties: true },
            recognition_proof: { type: "object", additionalProperties: true },
            completion_preset_id: { type: "string" },
            idempotency_key: { type: "string" },
          },
          ["intent_id", "body", "recognition_proof"],
        ),
        call: async (args) =>
          this.runtime.submitHarborEvidence({
            intentId: uuidArg(args.intent_id, "intent_id"),
            body: ensureObject(args.body, "body"),
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            completionPresetId: optionalString(args.completion_preset_id),
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
            recognitionProof: ensureObject(
              args.recognition_proof,
              "recognition_proof",
            ),
            idempotencyKey: optionalString(args.idempotency_key),
          }),
      },
    ];

    return tools.map((tool) => toolWithSelectionMetadata(tool));
  }
}

export function settingsFromEnv(
  env: Record<string, string | undefined> = process.env,
): PaybondMCPSettings {
  const envFile = optionalEnv(env.PAYBOND_ENV_FILE) ?? DEFAULT_ENV_FILE;
  const apiKey = String(
    env.PAYBOND_API_KEY ?? readEnvFileValue(envFile, "PAYBOND_API_KEY") ?? "",
  ).trim();
  if (!apiKey) {
    throw new Error(
      "PAYBOND_API_KEY is required; run paybond login or configure your MCP host environment",
    );
  }
  return {
    gatewayBaseUrl: requireSecureGatewayUrl(
      optionalEnv(env.PAYBOND_GATEWAY_URL) ??
        optionalEnv(env.PAYBOND_GATEWAY_BASE_URL) ??
        readEnvFileValue(envFile, "PAYBOND_GATEWAY_URL") ??
        readEnvFileValue(envFile, "PAYBOND_GATEWAY_BASE_URL") ??
        DEFAULT_PAYBOND_GATEWAY_BASE_URL,
    ),
    apiKey,
    principalPath:
      optionalEnv(env.PAYBOND_PRINCIPAL_PATH) ?? DEFAULT_PRINCIPAL_PATH,
    maxRetries: optionalEnv(env.PAYBOND_MCP_MAX_RETRIES)
      ? intArg(
          optionalEnv(env.PAYBOND_MCP_MAX_RETRIES),
          "PAYBOND_MCP_MAX_RETRIES",
        )
      : 3,
    toolPolicy: resolveMcpToolPolicy(
      mergeMcpToolPolicy(
        parseMcpToolPolicy(optionalEnv(env[MCP_TOOL_POLICY_ENV])),
        parseMcpToolAllowlist(optionalEnv(env[MCP_TOOL_ALLOWLIST_ENV])),
      ),
    ),
    evidencePolicy: parseMcpEvidencePolicy(optionalEnv(env[MCP_EVIDENCE_POLICY_ENV])),
    policyReload: parseMcpPolicyReloadConfig(env),
    capabilityTokenCache: parseMcpCapabilityTokenCacheConfig(env),
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
    process.stderr.write(
      "paybond-mcp-server does not accept positional arguments\n",
    );
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
  return requireSecureGatewayUrl(url);
}

function parseJSONObject(
  text: string,
  context: string,
): Record<string, unknown> {
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

function spendPreflightInputSchema(): Record<string, unknown> {
  return objectSchema(
    {
      intent_id: {
        type: "string",
        description: "Canonical Harbor intent UUID.",
      },
      operation: {
        type: "string",
        description:
          "Optional delegated operation or tool name. Defaults to * when omitted.",
      },
      requested_spend_cents: {
        type: "integer",
        description: "Optional proposed spend in cents for the dry-run evaluation.",
      },
      vendor_id: {
        type: "string",
        description: "Optional vendor scope hint for policy evaluation.",
      },
      tool_name: {
        type: "string",
        description: "Optional tool name scope hint for policy evaluation.",
      },
      task_id: {
        type: "string",
        description: "Optional task scope hint for policy evaluation.",
      },
      workflow_id: {
        type: "string",
        description: "Optional workflow scope hint for policy evaluation.",
      },
      tool_call_id: {
        type: "string",
        description: "Optional tool-call correlation id for policy evaluation.",
      },
      currency: {
        type: "string",
        description: "Optional ISO currency code for the proposed spend.",
      },
      agent_subject: {
        type: "string",
        description: "Optional agent subject for agent-scoped caps.",
      },
      approval_token: {
        type: "string",
        description:
          "Optional approval token to evaluate against pending approval state (not consumed).",
      },
    },
    ["intent_id"],
  );
}

function parseSpendPreflightArgs(args: Record<string, unknown>): {
  intentId: string;
  operation?: string;
  requestedSpendCents?: number;
  vendorId?: string;
  toolName?: string;
  taskId?: string;
  workflowId?: string;
  toolCallId?: string;
  currency?: string;
  agentSubject?: string;
  approvalToken?: string;
} {
  return {
    intentId: uuidArg(args.intent_id, "intent_id"),
    operation: optionalString(args.operation),
    requestedSpendCents:
      args.requested_spend_cents === undefined
        ? undefined
        : intArg(args.requested_spend_cents, "requested_spend_cents"),
    vendorId: optionalString(args.vendor_id),
    toolName: optionalString(args.tool_name),
    taskId: optionalString(args.task_id),
    workflowId: optionalString(args.workflow_id),
    toolCallId: optionalString(args.tool_call_id),
    currency: optionalString(args.currency),
    agentSubject: optionalString(args.agent_subject),
    approvalToken: optionalString(args.approval_token),
  };
}

/** Normalize gateway preflight outcomes to the agent-facing explain-policy set. */
function normalizeExplainPolicyOutcome(
  outcome: string,
  classification: string,
): "allow" | "approval_required" | "deny" {
  const normalized = outcome.trim().toLowerCase();
  if (normalized === "allow" || normalized === "anomaly_observe") {
    return "allow";
  }
  if (
    normalized === "approval_required" ||
    normalized === "anomaly_escalate"
  ) {
    return "approval_required";
  }
  if (normalized === "deny") {
    return "deny";
  }
  const classNorm = classification.trim().toLowerCase();
  if (classNorm === "allow") {
    return "allow";
  }
  if (classNorm === "hold") {
    return "approval_required";
  }
  return "deny";
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
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      raw,
    )
  ) {
    throw new Error(`${field} must be a canonical UUID`);
  }
  return raw;
}

/** Accept action-scope SHA-256 hex or intent-terminal UUID receipt ids. */
function agentReceiptIdArg(value: unknown): string {
  const raw = stringArg(value, "receipt_id").toLowerCase();
  // Validates via URI helper shared with resources/read.
  return parseAgentReceiptResourceUri(`paybond://receipt/${raw}`);
}

function stringArrayArg(value: unknown, field: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`);
  }
  return value.map((item, index) => stringArg(item, `${field}[${index}]`));
}

function assertSandboxGuardrailTenant(
  body: Record<string, unknown>,
  expectedTenant: string,
): void {
  const echoedTenant = stringArg(body.tenant_id, "tenant_id");
  if (echoedTenant !== expectedTenant) {
    throw new Error(
      `sandbox guardrail tenant mismatch: expected=${expectedTenant} gateway=${echoedTenant}`,
    );
  }
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

function outputObjectSchema(
  properties: Record<string, unknown>,
  required: string[] = [],
): Record<string, unknown> {
  return {
    type: "object",
    properties,
    additionalProperties: true,
    ...(required.length === 0 ? {} : { required }),
  };
}

function readOnlyToolAnnotations(title: string): MCPToolAnnotations {
  return {
    title,
    readOnlyHint: true,
    openWorldHint: false,
  };
}

function additiveMutationToolAnnotations(title: string): MCPToolAnnotations {
  return {
    title,
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
  };
}

function liveMutationToolAnnotations(title: string): MCPToolAnnotations {
  return {
    title,
    readOnlyHint: false,
    destructiveHint: true,
    idempotentHint: false,
    openWorldHint: true,
  };
}

function toolWithSelectionMetadata(tool: MCPToolDefinition): MCPToolDefinition {
  const metadata = TOOL_SELECTION_METADATA[tool.name];
  if (metadata === undefined) {
    throw new Error(`missing MCP tool selection metadata for ${tool.name}`);
  }
  return {
    ...tool,
    title: metadata.title,
    description: metadata.description ?? tool.description,
    outputSchema: metadata.outputSchema,
    annotations: metadata.annotations,
  };
}

function toToolResult(
  value: Record<string, unknown> | null,
): MCPCallToolResult {
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

function responseError(
  id: JSONRPCID,
  code: number,
  message: string,
): JSONRPCResponse {
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
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

function normalizeFileURL(url: string): string {
  return url.startsWith("file:///var/")
    ? url.replace("file:///var/", "file:///private/var/")
    : url;
}

async function invokedFromCLI(): Promise<boolean> {
  const scriptPath = process.argv[1];
  if (!scriptPath) {
    return false;
  }

  async function realFileURL(filePath: string): Promise<string> {
    let resolved = path.resolve(filePath);
    try {
      resolved = await fs.realpath(resolved);
    } catch {
      // If realpath fails, compare the absolute path. This keeps direct execution
      // working even when the script path disappears during process startup.
    }
    return normalizeFileURL(pathToFileURL(resolved).href);
  }

  return (
    (await realFileURL(scriptPath)) ===
    (await realFileURL(fileURLToPath(import.meta.url)))
  );
}

invokedFromCLI().then(
  (invoked) => {
    if (!invoked) {
      return;
    }
    const aliasWarning = deprecatedAliasWarning(process.argv[1]);
    if (aliasWarning) {
      process.stderr.write(`${aliasWarning}\n`);
    }
    process.exitCode = main(process.argv.slice(2));
  },
  (err) => {
    process.stderr.write(`${formatError(err)}\n`);
    process.exitCode = 1;
  },
);
