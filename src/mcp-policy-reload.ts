import { resolve } from "node:path";

import { PaybondUnregisteredSideEffectingToolError } from "./agent/types.js";
import {
  loadPolicySnapshotFromFile,
  reloadPolicyOnHandle,
  type PaybondPolicyReloadOptions,
  type PaybondPolicyReloadResult,
  type PolicyReloadHandle,
} from "./policy/reload.js";
import type { PaybondPolicySnapshot } from "./policy/snapshot.js";
import {
  parsePolicyEffectiveResolveResponse,
  type PolicyEffectiveResolveClient,
} from "./policy/load-effective.js";
import {
  parsePolicyRemoteValidateResponse,
  policyValidateQueryString,
  type PolicyRemoteValidateClient,
  type PolicyRemoteValidateOptions,
} from "./policy/validate-remote.js";
import { PaybondPolicyReloadController, type PolicyReloadRunner } from "./policy/watcher.js";

export const MCP_POLICY_FILE_ENV = "PAYBOND_POLICY_FILE";
export const MCP_POLICY_RELOAD_ENV = "PAYBOND_POLICY_RELOAD";
export const MCP_POLICY_RELOAD_ALLOW_LOOSEN_ENV = "PAYBOND_POLICY_RELOAD_ALLOW_LOOSEN";

export type McpPolicyReloadMode = "off" | "watch" | "poll";

export type McpPolicyReloadConfig = {
  policyFile: string;
  reloadMode: McpPolicyReloadMode;
  allowLoosen?: boolean;
  watchDebounceMs?: number;
  pollIntervalMs?: number;
};

export type McpPolicySpendGateInput = {
  toolName?: string;
  operation: string;
  allowedTools: readonly string[];
  arguments?: unknown;
  requestedSpendCents?: number;
};

export type McpPolicySpendGateResult = {
  operation: string;
  requestedSpendCents: number;
  policyDigest?: string;
};

export type McpPolicyReloadStatus = {
  enabled: boolean;
  policy_file?: string;
  policy_digest?: string;
  policy_loaded_at?: string;
  reload_mode: McpPolicyReloadMode;
  last_reload_at?: string;
  last_reload_error?: string;
};

export class McpPolicyReloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "McpPolicyReloadError";
  }
}

/** Gateway adapter for MCP poll reload with remote validation. */
export type McpPolicyGatewayClient = PolicyRemoteValidateClient & PolicyEffectiveResolveClient;

export function createMcpPolicyGatewayAdapter(client: {
  postJSON(
    path: string,
    payload: Record<string, unknown>,
    extraHeaders?: Record<string, string>,
  ): Promise<Record<string, unknown>>;
}): McpPolicyGatewayClient {
  return {
    async validatePolicy(document, options?: PolicyRemoteValidateOptions) {
      const qs = policyValidateQueryString(options ?? {});
      const body = await client.postJSON(`/v1/policy/validate${qs}`, document);
      return parsePolicyRemoteValidateResponse(body);
    },
    async resolvePolicyEffective(orgPolicyId, overlay, options?) {
      let path = `/v1/org-policies/${encodeURIComponent(orgPolicyId)}/effective`;
      const currentDigest = options?.currentDigest?.trim();
      if (currentDigest) {
        path += `?digest=${encodeURIComponent(currentDigest)}`;
      }
      const body = await client.postJSON(path, overlay);
      return parsePolicyEffectiveResolveResponse(body);
    },
  };
}

export function parseMcpPolicyReloadMode(raw: string | undefined): McpPolicyReloadMode {
  const value = (raw ?? "").trim().toLowerCase();
  if (!value || value === "off") {
    return "off";
  }
  if (value === "watch" || value === "poll") {
    return value;
  }
  throw new Error("invalid PAYBOND_POLICY_RELOAD (expected watch|poll|off)");
}

export function parseMcpPolicyReloadConfig(
  env: Record<string, string | undefined>,
): McpPolicyReloadConfig | null {
  const policyFile = (env[MCP_POLICY_FILE_ENV] ?? "").trim();
  if (!policyFile) {
    return null;
  }
  return {
    policyFile: resolve(policyFile),
    reloadMode: parseMcpPolicyReloadMode(env[MCP_POLICY_RELOAD_ENV]),
    allowLoosen: env[MCP_POLICY_RELOAD_ALLOW_LOOSEN_ENV] === "1",
  };
}

/** MCP reload controller shim — delegates to {@link McpPolicyReloadGate}. */
class McpPolicyReloadRunner implements PolicyReloadRunner {
  constructor(private readonly gate: McpPolicyReloadGate) {}

  reloadPolicy(options?: PaybondPolicyReloadOptions): Promise<PaybondPolicyReloadResult> {
    return this.gate.reloadPolicy(options);
  }
}

/**
 * Long-lived MCP policy gate: versioned snapshot, safe reload, and spend-gate registry checks.
 */
export class McpPolicyReloadGate implements PolicyReloadHandle {
  private _snapshot?: PaybondPolicySnapshot;
  private _inFlightCount = 0;
  private _lastAllowedTools: readonly string[] = [];
  private _controller?: PaybondPolicyReloadController;
  private _reloadDefaults: PaybondPolicyReloadOptions = {};
  readonly policyFilePath: string;
  lastReloadAt?: string;
  lastReloadError?: string;

  private constructor(
    readonly config: McpPolicyReloadConfig,
    snapshot: PaybondPolicySnapshot,
  ) {
    this.policyFilePath = config.policyFile;
    this._snapshot = snapshot;
  }

  static async open(
    config: McpPolicyReloadConfig,
    options?: { gateway?: McpPolicyGatewayClient },
  ): Promise<McpPolicyReloadGate> {
    const snapshot = await loadPolicySnapshotFromFile(config.policyFile);
    const gate = new McpPolicyReloadGate(config, snapshot);
    const runner = new McpPolicyReloadRunner(gate);
    gate._reloadDefaults = {
      file: config.policyFile,
      allowLoosen: config.allowLoosen,
      gateway: options?.gateway,
    };

    if (config.reloadMode === "watch") {
      gate._controller = PaybondPolicyReloadController.start(
        runner,
        { watch: { debounceMs: config.watchDebounceMs } },
        config.policyFile,
      );
    } else if (config.reloadMode === "poll") {
      gate._reloadDefaults.remote = true;
      gate._reloadDefaults.resolveInheritance = true;
      gate._controller = PaybondPolicyReloadController.start(
        runner,
        {
          poll: {
            intervalMs: config.pollIntervalMs,
            remote: true,
            resolveInheritance: true,
            gateway: options?.gateway,
          },
        },
        config.policyFile,
      );
    }
    return gate;
  }

  get currentSnapshot(): PaybondPolicySnapshot | undefined {
    return this._snapshot;
  }

  get policyDigest(): string | undefined {
    return this._snapshot?.digest;
  }

  get inFlightCount(): number {
    return this._inFlightCount;
  }

  get registry() {
    const snapshot = this._snapshot;
    if (!snapshot) {
      throw new McpPolicyReloadError("policy snapshot is not loaded");
    }
    return snapshot.registry;
  }

  applyPolicySnapshot(snapshot: PaybondPolicySnapshot): void {
    this._snapshot = snapshot;
  }

  async reloadPolicy(options: PaybondPolicyReloadOptions = {}): Promise<PaybondPolicyReloadResult> {
    try {
      const result = await reloadPolicyOnHandle(this, {
        ...this._reloadDefaults,
        ...options,
        allowedTools: this._lastAllowedTools,
      });
      if (result.applied) {
        this.lastReloadAt = new Date().toISOString();
        this.lastReloadError = undefined;
      }
      return result;
    } catch (err) {
      this.lastReloadError = err instanceof Error ? err.message : String(err);
      throw err;
    }
  }

  beginToolCall(): void {
    this._inFlightCount += 1;
  }

  endToolCall(): void {
    this._inFlightCount = Math.max(0, this._inFlightCount - 1);
  }

  /**
   * Enforce paybond.policy.yaml registry rules before Harbor spend authorization.
   * Pins policy_digest for the current MCP tool invocation.
   */
  assertSpendGate(input: McpPolicySpendGateInput): McpPolicySpendGateResult {
    const operation = input.operation.trim();
    const toolName = (input.toolName ?? operation).trim();
    if (!operation) {
      throw new McpPolicyReloadError("operation must be non-empty");
    }

    this._lastAllowedTools = input.allowedTools;
    const policyDigest = this._snapshot?.digest;

    const resolution = this.registry.resolveTool(toolName, {
      allowedTools: input.allowedTools,
    });

    if (resolution.kind === "passthrough") {
      return { operation, requestedSpendCents: 0, policyDigest };
    }

    if (resolution.kind === "denied") {
      throw new PaybondUnregisteredSideEffectingToolError(resolution.toolName, resolution.operation);
    }

    if (!input.allowedTools.includes(operation)) {
      throw new McpPolicyReloadError(
        `operation "${operation}" is not in intent allowed_tools (${input.allowedTools.join(", ")})`,
      );
    }

    const requestedSpendCents =
      input.requestedSpendCents ??
      this.registry.resolveSpendCents(toolName, input.arguments) ??
      0;

    return {
      operation: resolution.operation,
      requestedSpendCents,
      policyDigest,
    };
  }

  status(): McpPolicyReloadStatus {
    return {
      enabled: true,
      policy_file: this.policyFilePath,
      policy_digest: this.policyDigest,
      policy_loaded_at: this._snapshot?.loadedAt,
      reload_mode: this.config.reloadMode,
      last_reload_at: this.lastReloadAt ?? this._controller?.state.lastReloadAt,
      last_reload_error: this.lastReloadError ?? this._controller?.state.lastReloadError,
    };
  }

  stop(): void {
    this._controller?.stop();
    this._controller = undefined;
  }
}
