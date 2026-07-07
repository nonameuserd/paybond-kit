import { getCompletionPreset } from "../completion-catalog.js";
import {
  PaybondSideEffectingToolEntry,
  PaybondSideEffectingToolPolicy,
  PaybondToolRegistryConfig,
  PaybondToolRegistryValidationError,
  PaybondToolResolution,
} from "./types.js";

function normalizeSideEffecting(
  sideEffecting: Record<string, PaybondSideEffectingToolPolicy>,
): Map<string, PaybondSideEffectingToolEntry> {
  const entries = new Map<string, PaybondSideEffectingToolEntry>();
  const operations = new Map<string, string>();

  for (const [toolName, policy] of Object.entries(sideEffecting)) {
    if (!toolName.trim()) {
      throw new PaybondToolRegistryValidationError("side-effecting tool name must be non-empty");
    }

    const evidencePreset = policy.evidencePreset?.trim();
    if (!evidencePreset) {
      throw new PaybondToolRegistryValidationError(
        `side-effecting tool "${toolName}" must declare evidencePreset`,
      );
    }

    try {
      getCompletionPreset(evidencePreset);
    } catch {
      throw new PaybondToolRegistryValidationError(
        `side-effecting tool "${toolName}" references unknown evidencePreset "${evidencePreset}"`,
      );
    }

    const operation = (policy.operation?.trim() || toolName).trim();
    if (!operation) {
      throw new PaybondToolRegistryValidationError(
        `side-effecting tool "${toolName}" must resolve to a non-empty operation`,
      );
    }

    const previousTool = operations.get(operation);
    if (previousTool !== undefined && previousTool !== toolName) {
      throw new PaybondToolRegistryValidationError(
        `duplicate side-effecting operation "${operation}" for tools "${previousTool}" and "${toolName}"`,
      );
    }
    operations.set(operation, toolName);

    entries.set(toolName, {
      toolName,
      operation,
      spendCents: policy.spendCents,
      evidencePreset,
      evidenceMapper: policy.evidenceMapper,
      externalAttestationMapper: policy.externalAttestationMapper,
    });
  }

  return entries;
}

/**
 * Registry of side-effecting tools for agent middleware.
 * Read-only tools pass through without Harbor verify or evidence submission.
 */
export class PaybondToolRegistry {
  readonly defaultDeny: boolean;
  private readonly sideEffecting: Map<string, PaybondSideEffectingToolEntry>;
  private readonly operations: Set<string>;

  constructor(config: PaybondToolRegistryConfig) {
    this.defaultDeny = config.defaultDeny ?? false;
    this.sideEffecting = normalizeSideEffecting(config.sideEffecting ?? {});
    this.operations = new Set(
      [...this.sideEffecting.values()].map((entry) => entry.operation),
    );
  }

  /** Whether the tool is explicitly registered as side-effecting. */
  isSideEffecting(toolName: string): boolean {
    return this.sideEffecting.has(toolName);
  }

  /** Resolve Harbor operation for a tool name (defaults to tool name). */
  resolveOperation(toolName: string): string {
    return this.sideEffecting.get(toolName)?.operation ?? toolName;
  }

  /** Resolve requested spend cents for a registered side-effecting tool. */
  resolveSpendCents(toolName: string, args: unknown): number | undefined {
    const entry = this.sideEffecting.get(toolName);
    if (!entry?.spendCents) {
      return undefined;
    }
    if (typeof entry.spendCents === "number") {
      return entry.spendCents;
    }
    return entry.spendCents(args);
  }

  /** Lookup side-effecting entry by tool name. */
  getSideEffectingEntry(toolName: string): PaybondSideEffectingToolEntry | undefined {
    return this.sideEffecting.get(toolName);
  }

  /** Registered side-effecting tool names. */
  sideEffectingToolNames(): string[] {
    return [...this.sideEffecting.keys()];
  }

  /** Registered Harbor operations for side-effecting tools. */
  sideEffectingOperations(): string[] {
    return [...this.operations];
  }

  /**
   * Classify a tool call for interceptor routing.
   * When `defaultDeny` is true, unregistered tools whose operation is in `allowedTools` are denied.
   */
  resolveTool(
    toolName: string,
    options?: { allowedTools?: readonly string[] },
  ): PaybondToolResolution {
    const entry = this.sideEffecting.get(toolName);
    if (entry) {
      return {
        kind: "side_effecting",
        toolName,
        operation: entry.operation,
        entry,
      };
    }

    const operation = this.resolveOperation(toolName);
    if (
      this.defaultDeny &&
      options?.allowedTools !== undefined &&
      options.allowedTools.includes(operation)
    ) {
      return {
        kind: "denied",
        toolName,
        operation,
        reason: "unregistered_side_effecting",
      };
    }

    return { kind: "passthrough", toolName };
  }

  /**
   * Bind-time validation: when `defaultDeny` is enabled, every intent allowed operation
   * must have a registered side-effecting tool entry.
   */
  validateForBind(allowedTools: readonly string[]): void {
    if (!this.defaultDeny) {
      return;
    }
    for (const operation of allowedTools) {
      if (!this.operations.has(operation)) {
        throw new PaybondToolRegistryValidationError(
          `defaultDeny: operation "${operation}" is in intent allowedTools but not registered as side-effecting`,
        );
      }
    }
  }
}

/** Create a validated tool registry for agent middleware. */
export function createPaybondToolRegistry(config: PaybondToolRegistryConfig): PaybondToolRegistry {
  return new PaybondToolRegistry(config);
}
