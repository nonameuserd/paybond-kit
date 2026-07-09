import { PaybondToolInterceptor } from "./interceptor.js";
import { PaybondToolRegistry } from "./registry.js";
import {
  PaybondAgentRunBindError,
  PaybondRunBinding,
  PaybondRunBindingAttachInput,
  PaybondAgentRunBindInput,
  PaybondRunBindingSandboxBootstrapInput,
  PaybondRunGuard,
  PaybondRunAgentContext,
  PaybondRunAgentContextInput,
  PaybondRunProductionEvidenceCredentials,
} from "./types.js";
import type { PaybondPolicySnapshot } from "../policy/snapshot.js";
import {
  configHashSha256Hex,
  promptHashSha256Hex,
  type AgentReceiptExternalAttestationV1,
} from "../agent-receipt.js";
import {
  reloadPolicyOnRun,
  type PaybondPolicyReloadFailedEvent,
  type PaybondPolicyReloadOptions,
  type PaybondPolicyReloadedEvent,
  type PaybondPolicyReloadResult,
} from "../policy/reload.js";
import { PaybondPolicyReloadController, type PolicyReloadRunner } from "../policy/watcher.js";
import { resolveDevTraceSink } from "../dev/trace-buffer.js";

type SandboxBootstrapResult = {
  tenant_id: string;
  intent_id: string;
  capability_token: string;
  operation: string;
  requested_spend_cents: number;
  sandbox_lifecycle_status: string;
};

type SandboxGuardrailEvidenceResult = {
  tenant_id: string;
  intent_id: string;
  sandbox_lifecycle_status: string;
  predicate_passed?: boolean | null;
  payload_digest?: string;
  artifacts_digest?: string;
};

export type PaybondSubmitProductionEvidenceInput = {
  intentId: string;
  payload: Record<string, unknown>;
  vendorPayload?: Record<string, unknown>;
  operation: string;
  requestedSpendCents: number;
  idempotencyKey: string;
};

type AgentRunHarbor = {
  tenantId: string;
  getIntent(intentId: string): Promise<Record<string, unknown>>;
  submitEvidence(
    intentId: string,
    evidenceBody: Record<string, unknown>,
    options: {
      idempotencyKey?: string;
      recognitionProof: Record<string, unknown>;
      agentReceiptAttestations?: AgentReceiptExternalAttestationV1[];
      agentReceiptSourceRunId?: string;
    },
  ): Promise<Record<string, unknown>>;
};

type AgentRunGuardrails = {
  bootstrapSandbox(input: {
    operation: string;
    requestedSpendCents: number;
    currency?: string;
    evidenceSchema?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    idempotencyKey?: string;
    completionPreset?: string;
    templateId?: string;
    parameters?: Record<string, unknown>;
  }): Promise<SandboxBootstrapResult>;
  submitSandboxEvidence(input: {
    intentId: string;
    payload?: Record<string, unknown>;
    vendorPayload?: Record<string, unknown>;
    operation?: string;
    requestedSpendCents?: number;
    metadata?: Record<string, unknown>;
    idempotencyKey?: string;
  }): Promise<SandboxGuardrailEvidenceResult>;
};

/** Minimal Paybond session surface required to bind an agent run. */
export type PaybondAgentRunHost = {
  harbor: AgentRunHarbor;
  guardrails: AgentRunGuardrails;
  spendGuard(intentId: string, capabilityToken: string): PaybondRunGuard;
};

type PolicyReloadEventMap = {
  policyReloaded: PaybondPolicyReloadedEvent;
  policyReloadFailed: PaybondPolicyReloadFailedEvent;
};

function newRunId(explicit?: string): string {
  const trimmed = explicit?.trim();
  if (trimmed) {
    return trimmed;
  }
  return globalThis.crypto.randomUUID();
}

function readAllowedTools(intent: Record<string, unknown>): string[] {
  const raw = intent.allowed_tools;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0);
}

function normalizeProductionEvidence(
  raw: PaybondRunProductionEvidenceCredentials | undefined,
  sandbox: PaybondRunBinding["sandbox"],
): PaybondRunProductionEvidenceCredentials | undefined {
  if (sandbox !== undefined) {
    return undefined;
  }
  if (!raw) {
    throw new PaybondAgentRunBindError(
      "attach.productionEvidence is required for production auto-evidence submission",
    );
  }

  const payeeDid = raw.payeeDid.trim();
  const agentRecognitionKeyId = raw.agentRecognitionKeyId.trim();
  if (!payeeDid) {
    throw new PaybondAgentRunBindError(
      "attach.productionEvidence requires a payee identity",
    );
  }
  if (!agentRecognitionKeyId) {
    throw new PaybondAgentRunBindError(
      "attach.productionEvidence.agentRecognitionKeyId must be non-empty",
    );
  }
  if (raw.payeeSigningSeed.length !== 32) {
    throw new PaybondAgentRunBindError(
      "attach.productionEvidence.payeeSigningSeed must be 32 bytes",
    );
  }
  if (raw.agentRecognitionSigningSeed.length !== 32) {
    throw new PaybondAgentRunBindError(
      "attach.productionEvidence.agentRecognitionSigningSeed must be 32 bytes",
    );
  }

  return {
    payeeDid,
    payeeSigningSeed: raw.payeeSigningSeed,
    agentRecognitionKeyId,
    agentRecognitionSigningSeed: raw.agentRecognitionSigningSeed,
  };
}

/** Strips the leading `sha256:` scheme from a policy snapshot digest, if present. */
function bareDigestHex(digest: string | undefined): string | undefined {
  if (!digest) {
    return undefined;
  }
  const trimmed = digest.trim();
  return trimmed.startsWith("sha256:") ? trimmed.slice("sha256:".length) : trimmed;
}

/**
 * Resolves optional Agent Receipt Standard agent context at bind time: auto-computes
 * `config_hash_hex` from {@link PaybondRunAgentContextInput.configHashMaterials} (per spec,
 * `sha256(JCS({ system_prompt, tools_manifest, policy_snapshot_id }))`) and `prompt_hash_hex`
 * from {@link PaybondRunAgentContextInput.normalizedUserPrompt} when precomputed hashes are not
 * supplied directly. Raw prompt text is hashed here and discarded; only the digest is retained.
 */
function resolveAgentContext(
  input: PaybondRunAgentContextInput | undefined,
  snapshot: PaybondPolicySnapshot | undefined,
): PaybondRunAgentContext | undefined {
  if (!input) {
    return undefined;
  }
  const modelFamily = input.modelFamily.trim();
  if (!modelFamily) {
    throw new PaybondAgentRunBindError("agentContext.modelFamily must be non-empty");
  }

  let configHashHex = input.configHashHex?.trim().toLowerCase();
  if (!configHashHex && input.configHashMaterials) {
    const policySnapshotId =
      input.configHashMaterials.policySnapshotId?.trim() || bareDigestHex(snapshot?.digest);
    if (!policySnapshotId) {
      throw new PaybondAgentRunBindError(
        "agentContext.configHashMaterials.policySnapshotId is required when no policySnapshot is bound",
      );
    }
    configHashHex = configHashSha256Hex({
      system_prompt: input.configHashMaterials.systemPrompt,
      tools_manifest: input.configHashMaterials.toolsManifest,
      policy_snapshot_id: policySnapshotId,
    });
  }

  let promptHashHex = input.promptHashHex?.trim().toLowerCase();
  if (!promptHashHex && input.normalizedUserPrompt !== undefined) {
    promptHashHex = promptHashSha256Hex(input.normalizedUserPrompt);
  }

  return {
    modelFamily,
    modelInstanceId: input.modelInstanceId?.trim() || undefined,
    configHashHex,
    promptHashHex,
    principalDid: input.principalDid?.trim() || undefined,
    operatorDid: input.operatorDid?.trim() || undefined,
    policyTemplateId: input.policyTemplateId?.trim() || undefined,
  };
}

function assertExclusiveBindMode(input: PaybondAgentRunBindInput): void {
  const hasBootstrap = input.bootstrap !== undefined;
  const hasAttach = input.attach !== undefined;
  if (hasBootstrap === hasAttach) {
    throw new PaybondAgentRunBindError(
      "agent run bind requires exactly one of bootstrap or attach",
    );
  }
}

async function resolveAttachBinding(
  paybond: PaybondAgentRunHost,
  attach: PaybondRunBindingAttachInput,
): Promise<{
  intentId: string;
  capabilityToken: string;
  allowedTools: readonly string[];
}> {
  const intentId = attach.intentId.trim();
  const capabilityToken = attach.capabilityToken.trim();
  if (!intentId) {
    throw new PaybondAgentRunBindError("attach.intentId must be non-empty");
  }
  if (!capabilityToken) {
    throw new PaybondAgentRunBindError("attach.capabilityToken must be non-empty");
  }

  let allowedTools = attach.allowedTools;
  if (allowedTools === undefined) {
    const intent = await paybond.harbor.getIntent(intentId);
    allowedTools = readAllowedTools(intent);
  }

  if (allowedTools.length === 0) {
    throw new PaybondAgentRunBindError(
      `attach: intent ${intentId} has no allowed_tools; pass attach.allowedTools explicitly`,
    );
  }

  return { intentId, capabilityToken, allowedTools };
}

async function resolveSandboxBootstrap(
  paybond: PaybondAgentRunHost,
  bootstrap: PaybondRunBindingSandboxBootstrapInput,
): Promise<{
  binding: Pick<PaybondRunBinding, "intentId" | "capabilityToken" | "allowedTools" | "sandbox">;
}> {
  if (bootstrap.kind !== "sandbox") {
    throw new PaybondAgentRunBindError('bootstrap.kind must be "sandbox"');
  }
  const operation = bootstrap.operation.trim();
  if (!operation) {
    throw new PaybondAgentRunBindError("bootstrap.operation must be non-empty");
  }
  if (!Number.isFinite(bootstrap.requestedSpendCents) || bootstrap.requestedSpendCents < 0) {
    throw new PaybondAgentRunBindError("bootstrap.requestedSpendCents must be a non-negative number");
  }

  const bootstrapResult = await paybond.guardrails.bootstrapSandbox({
    operation,
    requestedSpendCents: bootstrap.requestedSpendCents,
    currency: bootstrap.currency,
    evidenceSchema: bootstrap.evidenceSchema,
    metadata: bootstrap.metadata,
    idempotencyKey: bootstrap.idempotencyKey,
    completionPreset: bootstrap.completionPreset,
    templateId: bootstrap.templateId,
    parameters: bootstrap.parameters,
  });

  return {
    binding: {
      intentId: bootstrapResult.intent_id,
      capabilityToken: bootstrapResult.capability_token,
      allowedTools: [bootstrapResult.operation],
      sandbox: {
        operation: bootstrapResult.operation,
        requestedSpendCents: bootstrapResult.requested_spend_cents,
        sandboxLifecycleStatus: bootstrapResult.sandbox_lifecycle_status,
      },
    },
  };
}

/**
 * Run-scoped agent middleware context for one agent task.
 * Bind once per run; do not share across concurrent agent tasks.
 */
export class PaybondAgentRun {
  readonly binding: PaybondRunBinding;
  readonly interceptor: PaybondToolInterceptor;
  readonly policyFilePath?: string;
  private reloadController?: PaybondPolicyReloadController;

  private readonly approvalTokens = new Map<string, string>();
  private readonly listeners = new Map<
    keyof PolicyReloadEventMap,
    Set<(payload: PolicyReloadEventMap[keyof PolicyReloadEventMap]) => void>
  >();

  private constructor(
    binding: PaybondRunBinding,
    host: PaybondAgentRunHost,
    private _currentSnapshot?: PaybondPolicySnapshot,
    policyFilePath?: string,
  ) {
    this.binding = binding;
    this.interceptor = new PaybondToolInterceptor(binding, host);
    this.policyFilePath = policyFilePath;
  }

  /** Start file watcher and/or Gateway poll reload (called from bind when `reload` is set). */
  startPolicyReload(config: import("../policy/reload.js").PaybondPolicyReloadBindConfig): void {
    if (!this.policyFilePath) {
      throw new Error("startPolicyReload requires policyFilePath from bind");
    }
    this.stopPolicyReload();
    const runner: PolicyReloadRunner = {
      reloadPolicy: (options) => this.reloadPolicy(options),
    };
    this.reloadController = PaybondPolicyReloadController.start(runner, config, this.policyFilePath);
  }

  /** Active policy snapshot for this run (undefined when bind omitted policy tracking). */
  get currentSnapshot(): PaybondPolicySnapshot | undefined {
    return this._currentSnapshot;
  }

  /** `sha256:<hex>` digest of the active policy snapshot, when tracked. */
  get policyDigest(): string | undefined {
    return this._currentSnapshot?.digest;
  }

  /** `{policy_name}@{digest_short}` version label of the active snapshot. */
  get policyVersion(): string | undefined {
    return this._currentSnapshot?.version;
  }

  /** RFC3339 timestamp when the active policy snapshot was loaded. */
  get policyLoadedAt(): string | undefined {
    return this._currentSnapshot?.loadedAt;
  }

  /** Active in-flight authorize/execute cycles (blocks policy reload until zero). */
  get inFlightCount(): number {
    return this.interceptor.inFlightCount;
  }

  get runId(): string {
    return this.binding.runId;
  }

  get tenantId(): string {
    return this.binding.tenantId;
  }

  get intentId(): string {
    return this.binding.intentId;
  }

  get capabilityToken(): string {
    return this.binding.capabilityToken;
  }

  get guard(): PaybondRunGuard {
    return this.binding.guard;
  }

  get registry(): PaybondToolRegistry {
    return this.binding.registry;
  }

  get allowedTools(): readonly string[] {
    return this.binding.allowedTools;
  }

  /** Subscribe to policy reload lifecycle events. */
  on<K extends keyof PolicyReloadEventMap>(
    event: K,
    listener: (payload: PolicyReloadEventMap[K]) => void,
  ): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as (payload: PolicyReloadEventMap[keyof PolicyReloadEventMap]) => void);
  }

  /** Unsubscribe from policy reload lifecycle events. */
  off<K extends keyof PolicyReloadEventMap>(
    event: K,
    listener: (payload: PolicyReloadEventMap[K]) => void,
  ): void {
    this.listeners.get(event)?.delete(
      listener as (payload: PolicyReloadEventMap[keyof PolicyReloadEventMap]) => void,
    );
  }

  private emit<K extends keyof PolicyReloadEventMap>(
    event: K,
    payload: PolicyReloadEventMap[K],
  ): void {
    for (const listener of this.listeners.get(event) ?? []) {
      listener(payload);
    }
  }

  /** Atomically swap registry and snapshot on the run binding (Tier 7 hot-reload). */
  applyPolicySnapshot(snapshot: PaybondPolicySnapshot): void {
    this.binding.registry = snapshot.registry;
    this.binding.policySnapshot = snapshot;
    this._currentSnapshot = snapshot;
  }

  /** Reload policy from disk or Gateway effective resolution without re-binding the run. */
  async reloadPolicy(options: PaybondPolicyReloadOptions = {}): Promise<PaybondPolicyReloadResult> {
    try {
      const result = await reloadPolicyOnRun(this, options);
      if (result.applied && result.previousDigest && result.newDigest) {
        this.emit("policyReloaded", {
          previousDigest: result.previousDigest,
          newDigest: result.newDigest,
        });
      }
      return result;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      this.emit("policyReloadFailed", { error: err as PaybondPolicyReloadFailedEvent["error"] });
      throw error;
    }
  }

  /** Stop background reload watchers started at bind time. */
  stopPolicyReload(): void {
    this.reloadController?.stop();
  }

  /** Store an operator approval token for retry after a Harbor approval hold. */
  storeApprovalToken(toolCallId: string, token: string): void {
    const id = toolCallId.trim();
    const value = token.trim();
    if (!id) {
      throw new Error("toolCallId must be non-empty");
    }
    if (!value) {
      throw new Error("approval token must be non-empty");
    }
    this.approvalTokens.set(id, value);
  }

  /** Read a stored approval token for a tool call retry. */
  getApprovalToken(toolCallId: string): string | undefined {
    return this.approvalTokens.get(toolCallId.trim());
  }

  /** Bind a run-scoped middleware context via sandbox bootstrap or attach. */
  static async bind(
    paybond: PaybondAgentRunHost,
    input: PaybondAgentRunBindInput,
  ): Promise<PaybondAgentRun> {
    assertExclusiveBindMode(input);

    const runId = newRunId(input.runId);
    const tenantId = paybond.harbor.tenantId;

    let intentId: string;
    let capabilityToken: string;
    let allowedTools: readonly string[];
    let sandbox: PaybondRunBinding["sandbox"];
    let productionEvidence: PaybondRunBinding["productionEvidence"];

    if (input.bootstrap !== undefined) {
      const resolved = await resolveSandboxBootstrap(paybond, input.bootstrap);
      intentId = resolved.binding.intentId;
      capabilityToken = resolved.binding.capabilityToken;
      allowedTools = resolved.binding.allowedTools;
      sandbox = resolved.binding.sandbox;
      productionEvidence = undefined;
    } else {
      const resolved = await resolveAttachBinding(paybond, input.attach!);
      intentId = resolved.intentId;
      capabilityToken = resolved.capabilityToken;
      allowedTools = resolved.allowedTools;
      sandbox = input.attach!.sandbox;
      productionEvidence = normalizeProductionEvidence(
        input.attach!.productionEvidence,
        sandbox,
      );
    }

    const snapshot = input.policySnapshot;
    const registry = snapshot?.registry ?? input.registry;
    registry.validateForBind(allowedTools);

    const guard = paybond.spendGuard(intentId, capabilityToken);
    const agentContext = resolveAgentContext(input.agentContext, snapshot);
    const binding: PaybondRunBinding = {
      runId,
      tenantId,
      intentId,
      capabilityToken,
      guard,
      registry,
      allowedTools,
      sandbox,
      productionEvidence,
      policySnapshot: snapshot,
      onTrace: input.traceSink ?? input.onTrace ?? resolveDevTraceSink(),
      agentContext,
    };

    const policyFilePath = input.policyFile?.trim();
    const run = new PaybondAgentRun(binding, paybond, snapshot, policyFilePath);
    if (input.reload && policyFilePath) {
      run.startPolicyReload(input.reload);
    }
    return run;
  }
}

/** Facade exposed as `paybond.agentRun`. */
export class PaybondAgentRunFacade {
  constructor(private readonly paybond: PaybondAgentRunHost) {}

  bind(input: PaybondAgentRunBindInput): Promise<PaybondAgentRun> {
    return PaybondAgentRun.bind(this.paybond, input);
  }
}
