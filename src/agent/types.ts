import type { AgentReceiptExternalAttestationV1 } from "../agent-receipt.js";

/** Context passed to evidence mappers after a successful side-effecting tool call. */
export type PaybondToolCallContext = {
  toolName: string;
  toolCallId: string;
  operation: string;
  arguments: unknown;
};

/** Resolve requested spend from tool arguments at intercept time. */
export type PaybondSpendResolver<TArgs = unknown> = (args: TArgs) => number | undefined;

/** Customize auto-evidence payload extraction from a tool result. */
export type PaybondEvidenceMapper<TResult = unknown> = (
  result: TResult,
  ctx: PaybondToolCallContext,
) => Record<string, unknown>;

/** Optional partner attestation material for Agent Receipt `external_attestations`. */
export type PaybondExternalAttestationMapper<TResult = unknown> = (
  result: TResult,
  ctx: PaybondToolCallContext,
) => PaybondExternalAttestationInput | PaybondExternalAttestationInput[] | undefined;

/** Policy for one registered side-effecting tool. */
export type PaybondSideEffectingToolPolicy<TArgs = unknown, TResult = unknown> = {
  /** Harbor `allowed_tools` operation; defaults to the registry key (tool name). */
  operation?: string;
  spendCents?: number | PaybondSpendResolver<TArgs>;
  /** Required completion catalog preset id for auto-evidence. */
  evidencePreset: string;
  evidenceMapper?: PaybondEvidenceMapper<TResult>;
  externalAttestationMapper?: PaybondExternalAttestationMapper<TResult>;
};

export type PaybondToolRegistryConfig = {
  sideEffecting?: Record<string, PaybondSideEffectingToolPolicy>;
  /** When true, deny tool calls whose operation is in intent allowedTools but missing from the registry. */
  defaultDeny?: boolean;
};

export type PaybondSideEffectingToolEntry = {
  toolName: string;
  operation: string;
  spendCents?: number | PaybondSpendResolver;
  evidencePreset: string;
  evidenceMapper?: PaybondEvidenceMapper;
  externalAttestationMapper?: PaybondExternalAttestationMapper;
};

export type PaybondToolResolution =
  | { kind: "passthrough"; toolName: string }
  | {
      kind: "side_effecting";
      toolName: string;
      operation: string;
      entry: PaybondSideEffectingToolEntry;
    }
  | {
      kind: "denied";
      toolName: string;
      operation: string;
      reason: "unregistered_side_effecting";
    };

export class PaybondToolRegistryValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondToolRegistryValidationError";
  }
}

import type { PaybondToolRegistry } from "./registry.js";
import type { PaybondPolicySnapshot } from "../policy/snapshot.js";
import type { PaybondPolicyReloadBindConfig } from "../policy/reload.js";
import type { AgentReceiptV1 } from "../agent-receipt.js";
import type { PaybondExternalAttestationInput } from "../agent-receipt-external-attestations.js";

/** Spend authorization input forwarded to the run-bound guard. */
export type PaybondRunGuardAuthInput = {
  operation: string;
  requestedSpendCents?: number;
  vendorId?: string;
  taskId?: string;
  workflowId?: string;
  toolCallId?: string;
  toolName?: string;
  currency?: string;
  agentSubject?: string;
  approvalToken?: string;
  idempotencyKey?: string;
  /** Agent Receipt Standard context forwarded to Gateway `/verify` for audit correlation. */
  modelFamily?: string;
  configHashHex?: string;
  promptHashHex?: string;
};

/**
 * Materials to auto-compute `config_hash_hex` as `sha256(JCS({ system_prompt, tools_manifest,
 * policy_snapshot_id }))` per the Agent Receipt Standard spec. `policySnapshotId` defaults to
 * the bound policy snapshot digest (without the `sha256:` prefix) when omitted.
 */
export type PaybondRunConfigHashMaterials = {
  systemPrompt: string;
  toolsManifest: unknown;
  policySnapshotId?: string;
};

/**
 * Optional agent identity/config context for {@link PaybondAgentRun.bind}. Threaded onto every
 * spend verify call and used to compose the unsigned Agent Receipt Standard draft returned from
 * {@link PaybondToolInterceptor.wrapExecute}. Raw prompts are hashed locally and never retained
 * or transmitted; only `promptHashHex` is kept on the resolved binding.
 */
export type PaybondRunAgentContextInput = {
  modelFamily: string;
  modelInstanceId?: string;
  /** Precomputed sha256 hex digest; mutually exclusive with {@link configHashMaterials}. */
  configHashHex?: string;
  /** Auto-computed into `configHashHex` at bind time when `configHashHex` is omitted. */
  configHashMaterials?: PaybondRunConfigHashMaterials;
  /** Precomputed sha256 hex digest; mutually exclusive with {@link normalizedUserPrompt}. */
  promptHashHex?: string;
  /** Hashed locally at bind time into `promptHashHex`; never stored or transmitted raw. */
  normalizedUserPrompt?: string;
  /** Agent receipt `authorization.principal_did`; omitted from receipt drafts when unset. */
  principalDid?: string;
  /** Agent receipt `authorization.agent.operator_did`; omitted from receipt drafts when unset. */
  operatorDid?: string;
  /** Agent receipt `authorization.policy.template_id`; omitted from receipt drafts when unset. */
  policyTemplateId?: string;
};

/** Resolved agent context stored on the run binding after bind-time hash computation. */
export type PaybondRunAgentContext = {
  modelFamily: string;
  modelInstanceId?: string;
  configHashHex?: string;
  promptHashHex?: string;
  principalDid?: string;
  operatorDid?: string;
  policyTemplateId?: string;
};

/** Spend authorization result from Harbor verify. */
export type PaybondRunGuardAuthResult = {
  allow: boolean;
  auditId: string;
  decisionId?: string;
  approvalRequired?: boolean;
};

/** Sandbox bootstrap input for {@link PaybondAgentRun.bind}. */
export type PaybondRunBindingSandboxBootstrapInput = {
  kind: "sandbox";
  operation: string;
  requestedSpendCents: number;
  currency?: string;
  evidenceSchema?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
  completionPreset?: string;
  templateId?: string;
  parameters?: Record<string, unknown>;
};

/** Ed25519 credentials for production auto-evidence (payee binding + agent recognition proof). */
export type PaybondRunProductionEvidenceCredentials = {
  payeeDid: string;
  /** 32-byte Ed25519 seed matching the payee key bound on the intent. */
  payeeSigningSeed: Uint8Array;
  /** Tenant-registered trusted agent key id for recognition proofs. */
  agentRecognitionKeyId: string;
  /** 32-byte Ed25519 seed matching `agentRecognitionKeyId` in the trusted agent key registry. */
  agentRecognitionSigningSeed: Uint8Array;
};

/** Attach an existing funded intent for {@link PaybondAgentRun.bind}. */
export type PaybondRunBindingAttachInput = {
  intentId: string;
  capabilityToken: string;
  /** When omitted, allowed tools are loaded from Harbor for the bound intent. */
  allowedTools?: readonly string[];
  /** Rehydrate sandbox guardrails evidence routing for attach binds (for example CLI run store). */
  sandbox?: PaybondRunBinding["sandbox"];
  /** Required for production attach binds that submit auto-evidence through Gateway Harbor. */
  productionEvidence?: PaybondRunProductionEvidenceCredentials;
};

/** Spend guard handle stored on a run binding for interceptors. */
export type PaybondRunGuard = {
  assertSpendAuthorized(input: PaybondRunGuardAuthInput): Promise<PaybondRunGuardAuthResult>;
  completeSpendAuthorization(
    decisionId: string,
    outcome: "consumed" | "released",
  ): Promise<void>;
};

export type AgentReceiptComposeStatus = "composed" | "failed";

/** Structured Gateway compose outcome attached to Harbor evidence responses when signing is configured. */
export type AgentReceiptComposeResult = {
  composeStatus: AgentReceiptComposeStatus;
  receiptId?: string;
  scope?: string;
  warningCode?: string;
  warningMessage?: string;
};

export type PaybondInterceptEvidenceResult = {
  submitted: true;
  intentId: string;
  predicatePassed?: boolean | null;
  sandboxLifecycleStatus?: string;
  intentState?: string;
  /** sha256 hex digest of the submitted evidence payload, when returned by Harbor. */
  payloadDigestSha256Hex?: string;
  /** sha256 hex digest of submitted evidence artifacts, when returned by Harbor. */
  artifactsDigestSha256Hex?: string;
  /**
   * Gateway agent-receipt compose outcome when `PAYBOND_AGENT_RECEIPT_SIGNING_KEY_HEX` is
   * configured. `composeStatus: "failed"` is a structured warning — evidence still succeeded.
   */
  agentReceipt?: AgentReceiptComposeResult;
};

export type PaybondInterceptWrapExecuteResult<TResult> = {
  toolResult: TResult;
  authorization?: {
    allow: true;
    auditId?: string;
    decisionId?: string;
    policyDigest?: string;
  };
  evidence?: PaybondInterceptEvidenceResult;
  /**
   * Unsigned Agent Receipt Standard draft (Phase 1: composed locally, never signed or persisted).
   * Omitted when required context (agentContext hashes, principal/operator DID, policy template,
   * decision id) is unavailable — receipt composition is always best-effort and never throws.
   */
  receiptDraft?: AgentReceiptV1;
};

export type PaybondInterceptWrapExecuteInput<TResult> = {
  toolName: string;
  toolCallId: string;
  arguments: unknown;
  execute: () => TResult | Promise<TResult>;
  operation?: string;
  requestedSpendCents?: number;
  vendorId?: string;
  taskId?: string;
  workflowId?: string;
  currency?: string;
  agentSubject?: string;
  approvalToken?: string;
  idempotencyKey?: string;
};

/** Authorize-only input for pre-execution guard evaluation (no execute, no evidence). */
export type PaybondAuthorizeToolCallInput = {
  toolName: string;
  toolCallId: string;
  arguments: unknown;
  operation?: string;
  requestedSpendCents?: number;
  vendorId?: string;
  taskId?: string;
  workflowId?: string;
  currency?: string;
  agentSubject?: string;
  approvalToken?: string;
  idempotencyKey?: string;
};

export type PaybondToolInputGuardAllowDecision = {
  kind: "allow";
  /** True when the tool is read-only and Harbor verify was skipped. */
  passthrough?: boolean;
  operation?: string;
  auditId?: string;
  decisionId?: string;
  /** Policy digest pinned at authorize time for audit (Tier 7). */
  policyDigest?: string;
};

export type PaybondToolInputGuardDenyDecision = {
  kind: "deny";
  message: string;
  operation?: string;
  auditId?: string;
  code?: string;
};

export type PaybondToolInputGuardApprovalRequiredDecision = {
  kind: "approval_required";
  message: string;
  operation?: string;
  auditId?: string;
  code?: string;
};

/** Framework-neutral pre-execution spend decision. */
export type PaybondToolInputGuardDecision =
  | PaybondToolInputGuardAllowDecision
  | PaybondToolInputGuardDenyDecision
  | PaybondToolInputGuardApprovalRequiredDecision;

/** Structured middleware trace event (dev observability; opt-in via {@link PaybondAgentRunBindInput.traceSink}). */
export type PaybondTraceToolSelectedEvent = {
  type: "tool_selected";
  runId: string;
  toolName: string;
  toolCallId: string;
  operation: string;
  recordedAt: string;
};

export type PaybondTraceSpendAuthorizedEvent = {
  type: "spend_authorized";
  runId: string;
  toolCallId: string;
  operation: string;
  auditId: string;
  decisionId?: string;
  amountCents: number;
  recordedAt: string;
};

export type PaybondTraceSpendDeniedEvent = {
  type: "spend_denied";
  runId: string;
  toolCallId: string;
  operation: string;
  message: string;
  auditId?: string;
  code?: string;
  recordedAt: string;
};

export type PaybondTraceApprovalRequiredEvent = {
  type: "approval_required";
  runId: string;
  toolCallId: string;
  operation: string;
  message: string;
  auditId?: string;
  code?: string;
  recordedAt: string;
};

export type PaybondTraceToolExecutedEvent = {
  type: "tool_executed";
  runId: string;
  toolCallId: string;
  operation: string;
  durationMs: number;
  recordedAt: string;
};

export type PaybondTraceEvidenceSubmittedEvent = {
  type: "evidence_submitted";
  runId: string;
  toolCallId: string;
  operation: string;
  evidenceId: string;
  presetId: string;
  /** @deprecated Use {@link PaybondTraceEvidenceSubmittedEvent.presetId}. */
  evidencePreset?: string;
  sandboxLifecycleStatus?: string;
  predicatePassed?: boolean | null;
  externalAttestations?: AgentReceiptExternalAttestationV1[];
  recordedAt: string;
};

export type PaybondTraceSpendFinalizedEvent = {
  type: "spend_finalized";
  runId: string;
  toolCallId: string;
  operation: string;
  status: "consumed" | "released";
  recordedAt: string;
};

export type PaybondTraceEvent =
  | PaybondTraceToolSelectedEvent
  | PaybondTraceSpendAuthorizedEvent
  | PaybondTraceSpendDeniedEvent
  | PaybondTraceApprovalRequiredEvent
  | PaybondTraceToolExecutedEvent
  | PaybondTraceEvidenceSubmittedEvent
  | PaybondTraceSpendFinalizedEvent;

/** Optional dev observability sink; not enabled in production binds by default. */
export type PaybondTraceSink = (event: PaybondTraceEvent) => void;

/** Run-scoped middleware context: one intent + capability per agent task. */
export type PaybondRunBinding = {
  runId: string;
  tenantId: string;
  intentId: string;
  capabilityToken: string;
  guard: PaybondRunGuard;
  /** Mutable for Tier 7 hot-reload registry swap. */
  registry: PaybondToolRegistry;
  allowedTools: readonly string[];
  sandbox?: {
    operation: string;
    requestedSpendCents: number;
    sandboxLifecycleStatus: string;
  };
  /** Production attach credentials for signed payee evidence and recognition proofs. */
  productionEvidence?: PaybondRunProductionEvidenceCredentials;
  /** Mutable for Tier 7 hot-reload registry swap. */
  policySnapshot?: PaybondPolicySnapshot;
  /** Optional trace sink for dev observability (see {@link PaybondAgentRunBindInput.traceSink}). */
  onTrace?: PaybondTraceSink;
  /** Resolved Agent Receipt Standard context, when bound with {@link PaybondAgentRunBindInput.agentContext}. */
  agentContext?: PaybondRunAgentContext;
};

export type PaybondAgentRunBindInput = {
  bootstrap?: PaybondRunBindingSandboxBootstrapInput;
  attach?: PaybondRunBindingAttachInput;
  registry: PaybondToolRegistry;
  /** Optional versioned policy snapshot; registry is taken from the snapshot when set. */
  policySnapshot?: PaybondPolicySnapshot;
  /** Optional client correlation id; generated when omitted. */
  runId?: string;
  /** Policy file path for hot-reload (watch/poll/manual reload). */
  policyFile?: string;
  /** Enable file watcher and/or Gateway poll reload after bind. */
  reload?: PaybondPolicyReloadBindConfig;
  /**
   * Optional dev trace sink; omitted in production binds unless explicitly set.
   * When `paybond dev loop` activates a collector, bind resolves it automatically.
   */
  traceSink?: PaybondTraceSink;
  /** @deprecated Use {@link PaybondAgentRunBindInput.traceSink}. */
  onTrace?: PaybondTraceSink;
  /** Optional Agent Receipt Standard agent identity/config context (see {@link PaybondRunAgentContextInput}). */
  agentContext?: PaybondRunAgentContextInput;
};

export class PaybondAgentRunBindError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondAgentRunBindError";
  }
}

/** Raised when auto-evidence payload construction fails before submit. */
export class PaybondAutoEvidenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondAutoEvidenceError";
  }
}

/** Raised when auto-evidence submission fails after a successful tool execution. */
export class PaybondAutoEvidenceSubmitError extends Error {
  readonly toolResult: unknown;

  constructor(toolResult: unknown, cause: unknown) {
    const message =
      cause instanceof Error ? cause.message : "auto-evidence submission failed";
    super(message, cause instanceof Error ? { cause } : undefined);
    this.name = "PaybondAutoEvidenceSubmitError";
    this.toolResult = toolResult;
  }
}

/** @deprecated Use {@link PaybondAutoEvidenceSubmitError}. */
export const PaybondEvidenceSubmitError = PaybondAutoEvidenceSubmitError;

/** Raised when `defaultDeny` blocks a side-effecting tool that was not registered. */
export class PaybondUnregisteredSideEffectingToolError extends Error {
  readonly toolName: string;
  readonly operation: string;

  constructor(toolName: string, operation: string) {
    super(
      `side-effecting tool "${toolName}" (operation "${operation}") is in intent allowedTools but not registered`,
    );
    this.name = "PaybondUnregisteredSideEffectingToolError";
    this.toolName = toolName;
    this.operation = operation;
  }
}
