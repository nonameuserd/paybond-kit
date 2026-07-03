import {
  evictExpiredAuthorizationCache,
  takeValidCachedAuthorization,
  type CachedAuthorizationEntry,
} from "./authorization-cache.js";
import { buildAutoEvidencePayload } from "./evidence.js";
import type { PaybondAgentRunHost } from "./run.js";
import { signHarborEvidenceSubmitRecognitionProof } from "../agent-recognition.js";
import { signPayeeEvidenceBinding } from "../payee-evidence.js";
import {
  PaybondAuthorizeToolCallInput,
  PaybondAutoEvidenceSubmitError,
  PaybondInterceptEvidenceResult,
  PaybondInterceptWrapExecuteInput,
  PaybondInterceptWrapExecuteResult,
  PaybondRunBinding,
  PaybondRunGuardAuthResult,
  PaybondSideEffectingToolEntry,
  PaybondToolCallContext,
  PaybondToolInputGuardDecision,
  PaybondTraceEvent,
  PaybondUnregisteredSideEffectingToolError,
} from "./types.js";

export { PaybondAutoEvidenceSubmitError, PaybondEvidenceSubmitError } from "./types.js";

function nowRfc3339Seconds(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function traceTimestamp(): string {
  return new Date().toISOString();
}

function evidenceIdempotencyKey(intentId: string, toolCallId: string): string {
  return `evidence:${intentId}:${toolCallId}`;
}

function authorizationCacheKey(toolCallId: string, operation: string): string {
  return `${toolCallId}:${operation}`;
}

function assertOperationAllowed(operation: string, allowedTools: readonly string[]): void {
  if (!allowedTools.includes(operation)) {
    throw new Error(
      `operation "${operation}" is not in bound intent allowedTools (${allowedTools.join(", ")})`,
    );
  }
}

function mapSandboxEvidenceResult(result: {
  intent_id: string;
  sandbox_lifecycle_status: string;
  predicate_passed?: boolean | null;
}): PaybondInterceptEvidenceResult {
  return {
    submitted: true,
    intentId: result.intent_id,
    predicatePassed: result.predicate_passed ?? undefined,
    sandboxLifecycleStatus: result.sandbox_lifecycle_status,
  };
}

type ResolvedSideEffectingCall = {
  toolName: string;
  toolCallId: string;
  operation: string;
  requestedSpendCents: number;
  entry: PaybondSideEffectingToolEntry;
  authInput: {
    operation: string;
    requestedSpendCents: number;
    toolCallId: string;
    toolName: string;
    vendorId?: string;
    taskId?: string;
    workflowId?: string;
    currency?: string;
    agentSubject?: string;
    approvalToken?: string;
    idempotencyKey?: string;
  };
};

type SpendAuthorizationError = Error & {
  result?: {
    auditId?: string;
    code?: string;
    message?: string;
  };
};

function isSpendApprovalRequiredError(err: unknown): err is SpendAuthorizationError {
  return err instanceof Error && err.name === "PaybondSpendApprovalRequiredError";
}

function isSpendDeniedError(err: unknown): err is SpendAuthorizationError {
  return err instanceof Error && err.name === "PaybondSpendDeniedError";
}

function mapSpendErrorToDecision(
  err: SpendAuthorizationError,
  operation: string,
  kind: "deny" | "approval_required",
): PaybondToolInputGuardDecision {
  const result = err.result;
  const message =
    result?.message ??
    result?.code ??
    err.message ??
    (kind === "approval_required" ? "approval_required" : "denied");
  const base = {
    message,
    operation,
    auditId: result?.auditId,
    code: result?.code,
  };
  return kind === "approval_required"
    ? { kind: "approval_required", ...base }
    : { kind: "deny", ...base };
}

/**
 * Pre/post intercept for side-effecting tools: authorize, execute, finalize spend, auto-evidence.
 */
export class PaybondToolInterceptor {
  private readonly authorizedCalls = new Map<string, CachedAuthorizationEntry<PaybondRunGuardAuthResult>>();
  private _inFlightCount = 0;

  constructor(
    private readonly binding: PaybondRunBinding,
    private readonly host: PaybondAgentRunHost,
  ) {}

  /** Active in-flight authorize/execute cycles (blocks policy reload until zero). */
  get inFlightCount(): number {
    return this._inFlightCount;
  }

  private beginInFlight(): string | undefined {
    this._inFlightCount += 1;
    return this.binding.policySnapshot?.digest;
  }

  private endInFlight(): void {
    this._inFlightCount = Math.max(0, this._inFlightCount - 1);
  }

  private emitTrace(event: PaybondTraceEvent): void {
    this.binding.onTrace?.(event);
  }

  /** Authorize-only pre-execution check for framework tool input guardrails. */
  async authorizeToolCall(
    input: PaybondAuthorizeToolCallInput,
  ): Promise<PaybondToolInputGuardDecision> {
    const toolName = input.toolName.trim();
    const toolCallId = input.toolCallId.trim();
    if (!toolName) {
      throw new Error("toolName must be non-empty");
    }
    if (!toolCallId) {
      throw new Error("toolCallId must be non-empty");
    }

    const pinnedDigest = this.beginInFlight();
    try {
      const resolution = this.binding.registry.resolveTool(toolName, {
        allowedTools: this.binding.allowedTools,
      });

      if (resolution.kind === "passthrough") {
        return { kind: "allow", passthrough: true, operation: toolName };
      }

      if (resolution.kind === "denied") {
        return {
          kind: "deny",
          operation: resolution.operation,
          message: `side-effecting tool "${resolution.toolName}" (operation "${resolution.operation}") is in intent allowedTools but not registered`,
        };
      }

      let resolved: ResolvedSideEffectingCall;
      try {
        resolved = this.resolveSideEffectingCall(input, resolution.entry, resolution.operation);
      } catch (err) {
        if (err instanceof Error) {
          return { kind: "deny", message: err.message, operation: resolution.operation };
        }
        throw err;
      }

      this.emitTrace({
        type: "tool_selected",
        runId: this.binding.runId,
        toolName: resolved.toolName,
        toolCallId: resolved.toolCallId,
        operation: resolved.operation,
        recordedAt: traceTimestamp(),
      });

      try {
        const auth = await this.binding.guard.assertSpendAuthorized(resolved.authInput);
        evictExpiredAuthorizationCache(this.authorizedCalls);
        this.authorizedCalls.set(authorizationCacheKey(toolCallId, resolved.operation), {
          auth,
          policyDigest: pinnedDigest,
          operation: resolved.operation,
          requestedSpendCents: resolved.requestedSpendCents,
          toolName: resolved.toolName,
          cachedAtMs: Date.now(),
        });
        this.emitTrace({
          type: "spend_authorized",
          runId: this.binding.runId,
          toolCallId: resolved.toolCallId,
          operation: resolved.operation,
          auditId: auth.auditId,
          decisionId: auth.decisionId,
          amountCents: resolved.requestedSpendCents,
          recordedAt: traceTimestamp(),
        });
        return {
          kind: "allow",
          operation: resolved.operation,
          auditId: auth.auditId,
          decisionId: auth.decisionId,
          policyDigest: pinnedDigest,
        };
      } catch (err) {
        if (isSpendApprovalRequiredError(err)) {
          const decision = mapSpendErrorToDecision(err, resolved.operation, "approval_required");
          if (decision.kind === "approval_required") {
            this.emitTrace({
              type: "approval_required",
              runId: this.binding.runId,
              toolCallId: resolved.toolCallId,
              operation: resolved.operation,
              message: decision.message,
              auditId: decision.auditId,
              code: decision.code,
              recordedAt: traceTimestamp(),
            });
          }
          return decision;
        }
        if (isSpendDeniedError(err)) {
          const decision = mapSpendErrorToDecision(err, resolved.operation, "deny");
          if (decision.kind === "deny") {
            this.emitTrace({
              type: "spend_denied",
              runId: this.binding.runId,
              toolCallId: resolved.toolCallId,
              operation: resolved.operation,
              message: decision.message,
              auditId: decision.auditId,
              code: decision.code,
              recordedAt: traceTimestamp(),
            });
          }
          return decision;
        }
        throw err;
      }
    } finally {
      this.endInFlight();
    }
  }

  /** Run one tool through the middleware authorize → execute → evidence cycle. */
  async wrapExecute<TResult>(
    input: PaybondInterceptWrapExecuteInput<TResult>,
  ): Promise<PaybondInterceptWrapExecuteResult<TResult>> {
    const toolName = input.toolName.trim();
    const toolCallId = input.toolCallId.trim();
    if (!toolName) {
      throw new Error("toolName must be non-empty");
    }
    if (!toolCallId) {
      throw new Error("toolCallId must be non-empty");
    }

    const pinnedDigest = this.beginInFlight();
    try {
      const resolution = this.binding.registry.resolveTool(toolName, {
        allowedTools: this.binding.allowedTools,
      });

      if (resolution.kind === "passthrough") {
        return { toolResult: await input.execute() };
      }

      if (resolution.kind === "denied") {
        throw new PaybondUnregisteredSideEffectingToolError(resolution.toolName, resolution.operation);
      }

      const resolved = this.resolveSideEffectingCall(input, resolution.entry, resolution.operation);
      this.emitTrace({
        type: "tool_selected",
        runId: this.binding.runId,
        toolName: resolved.toolName,
        toolCallId: resolved.toolCallId,
        operation: resolved.operation,
        recordedAt: traceTimestamp(),
      });

      const cacheKey = authorizationCacheKey(toolCallId, resolved.operation);
      const cached = takeValidCachedAuthorization(this.authorizedCalls, cacheKey, {
        operation: resolved.operation,
        requestedSpendCents: resolved.requestedSpendCents,
        toolName: resolved.toolName,
      });

      const evidencePolicyDigest = cached?.policyDigest ?? pinnedDigest;
      let auth: PaybondRunGuardAuthResult;
      if (cached) {
        auth = cached.auth;
      } else {
        auth = await this.binding.guard.assertSpendAuthorized(resolved.authInput);
        this.emitTrace({
          type: "spend_authorized",
          runId: this.binding.runId,
          toolCallId: resolved.toolCallId,
          operation: resolved.operation,
          auditId: auth.auditId,
          decisionId: auth.decisionId,
          amountCents: resolved.requestedSpendCents,
          recordedAt: traceTimestamp(),
        });
      }

      const executeStartedAt = Date.now();
      try {
        const toolResult = await input.execute();
        this.emitTrace({
          type: "tool_executed",
          runId: this.binding.runId,
          toolCallId: resolved.toolCallId,
          operation: resolved.operation,
          durationMs: Date.now() - executeStartedAt,
          recordedAt: traceTimestamp(),
        });

        if (auth.decisionId) {
          await this.binding.guard.completeSpendAuthorization(auth.decisionId, "consumed");
          this.emitTrace({
            type: "spend_finalized",
            runId: this.binding.runId,
            toolCallId: resolved.toolCallId,
            operation: resolved.operation,
            status: "consumed",
            recordedAt: traceTimestamp(),
          });
        }

        const evidenceId = evidenceIdempotencyKey(this.binding.intentId, toolCallId);
        const evidence = await this.submitAutoEvidence({
          entry: resolved.entry,
          toolName,
          toolCallId,
          operation: resolved.operation,
          arguments: input.arguments,
          requestedSpendCents: resolved.requestedSpendCents,
          toolResult,
          auth,
          evidenceId,
        });
        this.emitTrace({
          type: "evidence_submitted",
          runId: this.binding.runId,
          toolCallId: resolved.toolCallId,
          operation: resolved.operation,
          evidenceId,
          presetId: resolved.entry.evidencePreset,
          evidencePreset: resolved.entry.evidencePreset,
          sandboxLifecycleStatus: evidence.sandboxLifecycleStatus,
          predicatePassed: evidence.predicatePassed,
          recordedAt: traceTimestamp(),
        });

        return {
          toolResult,
          authorization: {
            allow: true,
            auditId: auth.auditId,
            decisionId: auth.decisionId,
            policyDigest: evidencePolicyDigest,
          },
          evidence,
        };
      } catch (err) {
        if (err instanceof PaybondAutoEvidenceSubmitError) {
          throw err;
        }
        if (auth.decisionId) {
          try {
            await this.binding.guard.completeSpendAuthorization(auth.decisionId, "released");
            this.emitTrace({
              type: "spend_finalized",
              runId: this.binding.runId,
              toolCallId: resolved.toolCallId,
              operation: resolved.operation,
              status: "released",
              recordedAt: traceTimestamp(),
            });
          } catch {
            // Best-effort release when the guarded handler fails.
          }
        }
        throw err;
      }
    } finally {
      this.endInFlight();
    }
  }

  private resolveSideEffectingCall(
    input: PaybondAuthorizeToolCallInput,
    entry: PaybondSideEffectingToolEntry,
    defaultOperation: string,
  ): ResolvedSideEffectingCall {
    const toolName = input.toolName.trim();
    const toolCallId = input.toolCallId.trim();
    const operation = (input.operation ?? defaultOperation).trim();
    assertOperationAllowed(operation, this.binding.allowedTools);

    let requestedSpendCents = input.requestedSpendCents;
    if (requestedSpendCents === undefined) {
      requestedSpendCents = this.binding.registry.resolveSpendCents(toolName, input.arguments);
    }
    if (this.binding.sandbox !== undefined) {
      const sandboxSpend = this.binding.sandbox.requestedSpendCents;
      requestedSpendCents =
        requestedSpendCents === undefined
          ? sandboxSpend
          : Math.min(requestedSpendCents, sandboxSpend);
    }
    requestedSpendCents ??= 0;

    return {
      toolName,
      toolCallId,
      operation,
      requestedSpendCents,
      entry,
      authInput: {
        operation,
        requestedSpendCents,
        toolCallId,
        toolName,
        vendorId: input.vendorId,
        taskId: input.taskId,
        workflowId: input.workflowId,
        currency: input.currency,
        agentSubject: input.agentSubject,
        approvalToken: input.approvalToken,
        idempotencyKey: input.idempotencyKey,
      },
    };
  }

  private async submitAutoEvidence(options: {
    entry: PaybondSideEffectingToolEntry;
    toolName: string;
    toolCallId: string;
    operation: string;
    arguments: unknown;
    requestedSpendCents: number;
    toolResult: unknown;
    auth: { decisionId?: string; auditId: string };
    evidenceId: string;
  }): Promise<PaybondInterceptEvidenceResult> {
    const ctx: PaybondToolCallContext = {
      toolName: options.toolName,
      toolCallId: options.toolCallId,
      operation: options.operation,
      arguments: options.arguments,
    };

    let payload: Record<string, unknown>;
    try {
      payload = buildAutoEvidencePayload(options.entry, options.toolResult, ctx);
    } catch (err) {
      throw new PaybondAutoEvidenceSubmitError(options.toolResult, err);
    }

    const idempotencyKey = options.evidenceId;

    try {
      if (this.binding.sandbox) {
        const result = await this.host.guardrails.submitSandboxEvidence({
          intentId: this.binding.intentId,
          payload,
          operation: options.operation,
          requestedSpendCents: options.requestedSpendCents,
          metadata: {
            tool_name: options.toolName,
            tool_call_id: options.toolCallId,
            evidence_preset: options.entry.evidencePreset,
            decision_id: options.auth.decisionId,
          },
          idempotencyKey,
        });
        return mapSandboxEvidenceResult(result);
      }

      const productionEvidence = this.binding.productionEvidence;
      if (!productionEvidence) {
        throw new Error(
          "production agent run bind requires attach.productionEvidence for auto-evidence submission",
        );
      }

      const wire = signPayeeEvidenceBinding({
        tenantId: this.binding.tenantId,
        intentId: this.binding.intentId,
        payeeDid: productionEvidence.payeeDid,
        payload,
        artifactsBlake3Hex: [],
        submittedAtRfc3339: nowRfc3339Seconds(),
        payeeSigningSeed: productionEvidence.payeeSigningSeed,
      });
      const recognitionProof = signHarborEvidenceSubmitRecognitionProof({
        tenantId: this.binding.tenantId,
        intentId: this.binding.intentId,
        evidenceBody: wire,
        keyId: productionEvidence.agentRecognitionKeyId,
        signingSeed: productionEvidence.agentRecognitionSigningSeed,
      });

      const result = await this.host.harbor.submitEvidence(this.binding.intentId, wire, {
        idempotencyKey,
        recognitionProof,
      });

      const resultRecord = result as Record<string, unknown>;
      const intentState =
        typeof resultRecord.intent_state === "string"
          ? resultRecord.intent_state
          : typeof resultRecord.state === "string"
            ? resultRecord.state
            : undefined;
      const predicatePassed =
        typeof resultRecord.predicate_passed === "boolean"
          ? resultRecord.predicate_passed
          : typeof resultRecord.predicatePassed === "boolean"
            ? resultRecord.predicatePassed
            : undefined;

      return {
        submitted: true,
        intentId: this.binding.intentId,
        intentState,
        predicatePassed,
      };
    } catch (err) {
      if (err instanceof PaybondAutoEvidenceSubmitError) {
        throw err;
      }
      throw new PaybondAutoEvidenceSubmitError(options.toolResult, err);
    }
  }
}
