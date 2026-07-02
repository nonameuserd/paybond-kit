import { readFile } from "node:fs/promises";

import type { PaybondAgentRun } from "../agent/run.js";
import type { PaybondToolInterceptor } from "../agent/interceptor.js";
import { PaybondPolicy } from "./load.js";
import { parsePolicyDocumentText } from "./parse-text.js";
import {
  isPaybondPolicyDocumentV2,
  isPaybondPolicyOverlay,
  parsePaybondPolicyDocument,
  parsePaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV1,
} from "./schema.js";
import {
  createPolicySnapshot,
  createPolicySnapshotFromEffective,
  type PaybondPolicySnapshot,
} from "./snapshot.js";
import { PolicyValidator } from "./validate.js";
import {
  validatePolicyRemote,
  type PolicyRemoteValidateClient,
} from "./validate-remote.js";
import type { PolicyEffectiveResolveClient } from "./load-effective.js";

/** Options for {@link PaybondAgentRun.reloadPolicy}. */
export type PaybondPolicyReloadOptions = {
  /** Policy file path; defaults to the path used at bind when omitted. */
  file?: string;
  /** Run Gateway `POST /v1/policy/validate` before applying (recommended in production). */
  remote?: boolean;
  /** Resolve org inheritance via Gateway effective endpoint before validate. */
  resolveInheritance?: boolean;
  /** Allow policy loosening (higher caps, new side-effecting tools). Default deny. */
  allowLoosen?: boolean;
  /** Gateway client for remote validate / effective resolution. */
  gateway?: PolicyRemoteValidateClient & PolicyEffectiveResolveClient;
};

export type PaybondPolicyReloadResult = {
  applied: boolean;
  previousDigest?: string;
  newDigest?: string;
  unchanged?: boolean;
};

export type PaybondPolicyReloadFailedEvent = {
  error: PaybondPolicyReloadError;
};

export type PaybondPolicyReloadedEvent = {
  previousDigest: string;
  newDigest: string;
};

/** Structured reload failure (parse, validate, loosening, intent drift). */
export class PaybondPolicyReloadError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PaybondPolicyReloadError";
    this.code = code;
  }
}

/** Thrown internally when poll/file reload finds an unchanged digest. */
export class PaybondPolicyReloadUnchangedError extends Error {
  constructor() {
    super("policy digest unchanged");
    this.name = "PaybondPolicyReloadUnchangedError";
  }
}

export type PaybondPolicyReloadBindConfig = {
  /** Watch the bound policy file and reload on change. */
  watch?: boolean | { debounceMs?: number; file?: string };
  /** Poll Gateway for effective inherited policy changes. */
  poll?: {
    intervalMs?: number;
    file?: string;
    remote?: boolean;
    resolveInheritance?: boolean;
    gateway?: PolicyRemoteValidateClient & PolicyEffectiveResolveClient;
  };
};

/** Load a versioned snapshot from a policy file path. */
export async function loadPolicySnapshotFromFile(filePath: string): Promise<PaybondPolicySnapshot> {
  const policy = await PaybondPolicy.load(filePath);
  const registry = policy.toToolRegistry();
  return createPolicySnapshot({
    document: policy.document,
    registry,
    source: "file",
  });
}

/** Poll Gateway effective resolution; returns unchanged when digest matches. */
export async function loadPolicySnapshotFromEffectivePoll(options: {
  overlayPath: string;
  gateway: PolicyEffectiveResolveClient;
  currentDigest?: string;
}): Promise<{ snapshot?: PaybondPolicySnapshot; unchanged: boolean }> {
  const text = await readFile(options.overlayPath, "utf8");
  const overlayDoc = parsePaybondPolicyDocument(parsePolicyDocumentText(text));
  if (!isPaybondPolicyDocumentV2(overlayDoc) || !isPaybondPolicyOverlay(overlayDoc)) {
    throw new PaybondPolicyReloadError(
      "invalid_overlay",
      "poll reload requires a v2 tenant overlay policy with extends.org_policy_id",
    );
  }
  const orgPolicyId = overlayDoc.extends?.org_policy_id?.trim();
  if (!orgPolicyId) {
    throw new PaybondPolicyReloadError(
      "invalid_overlay",
      "poll reload requires extends.org_policy_id on the overlay policy",
    );
  }

  const resolved = await options.gateway.resolvePolicyEffective(
    orgPolicyId,
    overlayDoc as unknown as Record<string, unknown>,
    { currentDigest: options.currentDigest },
  );
  if (resolved.unchanged) {
    return { unchanged: true };
  }

  const effective = parsePaybondPolicyDocumentV1(resolved.effective_policy);
  const policy = PaybondPolicy.fromDocument(effective);
  const registry = policy.toToolRegistry();
  const snapshot = createPolicySnapshotFromEffective({
    document: effective,
    registry,
    effectivePolicyDigest: resolved.effective_policy_digest,
  });
  return { snapshot, unchanged: false };
}

function readMaxSpendCents(entry: { max_spend_cents?: number }): number | undefined {
  return typeof entry.max_spend_cents === "number" ? entry.max_spend_cents : undefined;
}

/** Detect policy loosening between two effective documents. */
export function detectPolicyLoosening(
  previous: PaybondPolicyDocumentV1,
  next: PaybondPolicyDocumentV1,
): string[] {
  const reasons: string[] = [];
  if (previous.default_deny && !next.default_deny) {
    reasons.push("default_deny relaxed from true to false");
  }

  for (const [toolName, nextEntry] of Object.entries(next.tools)) {
    const prevEntry = previous.tools[toolName];
    if (!prevEntry) {
      if (nextEntry.side_effecting) {
        reasons.push(`new side-effecting tool "${toolName}"`);
      }
      continue;
    }

    const prevCap = readMaxSpendCents(prevEntry);
    const nextCap = readMaxSpendCents(nextEntry);
    if (prevCap !== undefined) {
      if (nextCap === undefined) {
        reasons.push(`tool "${toolName}" max_spend_cents cap removed`);
      } else if (nextCap > prevCap) {
        reasons.push(`tool "${toolName}" max_spend_cents increased from ${prevCap} to ${nextCap}`);
      }
    }

    if (!prevEntry.side_effecting && nextEntry.side_effecting) {
      reasons.push(`tool "${toolName}" became side-effecting`);
    }
  }

  return reasons;
}

/** True when reloaded policy requires operations outside the bound intent. */
export function requiresIntentRebind(
  document: PaybondPolicyDocumentV1,
  allowedTools: readonly string[],
): boolean {
  const intentTools = document.intent?.allowed_tools ?? [];
  for (const operation of intentTools) {
    if (!allowedTools.includes(operation)) {
      return true;
    }
  }

  for (const [toolName, entry] of Object.entries(document.tools)) {
    if (!entry.side_effecting) {
      continue;
    }
    const operation = entry.operation?.trim() || toolName;
    if (!allowedTools.includes(operation)) {
      return true;
    }
  }

  return false;
}

async function waitForInFlightInterceptors(
  interceptor: PaybondToolInterceptor,
  timeoutMs = 30_000,
): Promise<void> {
  await waitForInFlightCount(() => interceptor.inFlightCount, timeoutMs);
}

async function waitForInFlightCount(
  readCount: () => number,
  timeoutMs = 30_000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (readCount() > 0) {
    if (Date.now() > deadline) {
      throw new PaybondPolicyReloadError(
        "in_flight_timeout",
        "timed out waiting for in-flight tool calls before policy reload",
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** Mutable policy reload surface shared by agent runs and MCP servers. */
export type PolicyReloadHandle = {
  readonly policyFilePath?: string;
  readonly policyDigest?: string;
  readonly currentSnapshot?: PaybondPolicySnapshot;
  readonly inFlightCount: number;
  applyPolicySnapshot(snapshot: PaybondPolicySnapshot): void;
};

async function resolveReloadSnapshotForHandle(
  handle: PolicyReloadHandle,
  options: PaybondPolicyReloadOptions,
): Promise<PaybondPolicySnapshot> {
  const filePath = options.file?.trim() || handle.policyFilePath;
  if (!filePath) {
    throw new PaybondPolicyReloadError(
      "missing_policy_file",
      "reload requires a policy file path (pass file or bind with reload.watch/poll)",
    );
  }

  if (options.resolveInheritance && options.gateway) {
    const polled = await loadPolicySnapshotFromEffectivePoll({
      overlayPath: filePath,
      gateway: options.gateway,
      currentDigest: handle.policyDigest,
    });
    if (polled.unchanged) {
      throw new PaybondPolicyReloadUnchangedError();
    }
    if (!polled.snapshot) {
      throw new PaybondPolicyReloadError("effective_empty", "effective policy resolution returned no snapshot");
    }
    return polled.snapshot;
  }

  const snapshot = await loadPolicySnapshotFromFile(filePath);
  if (handle.policyDigest && handle.policyDigest === snapshot.digest) {
    throw new PaybondPolicyReloadUnchangedError();
  }
  return snapshot;
}

async function validateAndApplyPolicySnapshot(
  handle: PolicyReloadHandle,
  snapshot: PaybondPolicySnapshot,
  options: PaybondPolicyReloadOptions,
  allowedTools: readonly string[],
): Promise<PaybondPolicyReloadResult> {
  const previousDocument = handle.currentSnapshot?.document;
  const nextDocument = snapshot.document;
  const localReport = await PolicyValidator.validateDocument(nextDocument, {
    strict: PolicyValidator.isStrictFromEnv(),
  });
  if (!localReport.valid) {
    const first = localReport.errors[0];
    throw new PaybondPolicyReloadError(
      "local_validate_failed",
      first ? `${first.path}: ${first.message}` : "local policy validation failed",
    );
  }

  if (options.remote && options.gateway) {
    const remoteReport = await validatePolicyRemote(nextDocument, options.gateway, {
      resolveInheritance: options.resolveInheritance,
      strict: PolicyValidator.isStrictFromEnv(),
    });
    if (!remoteReport.valid) {
      const first = remoteReport.errors[0];
      throw new PaybondPolicyReloadError(
        "remote_validate_failed",
        first ? `${first.path}: ${first.message}` : "remote policy validation failed",
      );
    }
  }

  if (allowedTools.length > 0 && requiresIntentRebind(nextDocument, allowedTools)) {
    throw new PaybondPolicyReloadError(
      "intent_rebind_required",
      "reloaded policy requires allowed_tools outside the bound intent; re-bind with a new intent",
    );
  }

  if (previousDocument && !options.allowLoosen) {
    const loosening = detectPolicyLoosening(previousDocument, nextDocument);
    if (loosening.length > 0) {
      throw new PaybondPolicyReloadError(
        "loosening_denied",
        `policy loosening denied: ${loosening.join("; ")}`,
      );
    }
  }

  if (allowedTools.length > 0) {
    snapshot.registry.validateForBind(allowedTools);
  }

  const previousDigest = handle.policyDigest;
  if (previousDigest && previousDigest === snapshot.digest) {
    return { applied: false, previousDigest, newDigest: snapshot.digest, unchanged: true };
  }

  handle.applyPolicySnapshot(snapshot);
  return {
    applied: true,
    previousDigest: previousDigest ?? snapshot.digest,
    newDigest: snapshot.digest,
  };
}

/** Reload policy for any {@link PolicyReloadHandle} (agent run or MCP gate). */
export async function reloadPolicyOnHandle(
  handle: PolicyReloadHandle,
  options: PaybondPolicyReloadOptions & { allowedTools?: readonly string[] } = {},
): Promise<PaybondPolicyReloadResult> {
  await waitForInFlightCount(() => handle.inFlightCount);

  let snapshot: PaybondPolicySnapshot;
  try {
    snapshot = await resolveReloadSnapshotForHandle(handle, options);
  } catch (err) {
    if (err instanceof PaybondPolicyReloadUnchangedError) {
      return {
        applied: false,
        previousDigest: handle.policyDigest,
        newDigest: handle.policyDigest,
        unchanged: true,
      };
    }
    throw err;
  }

  const allowedTools =
    options.allowedTools ??
    handle.currentSnapshot?.document.intent?.allowed_tools ??
    [];
  return validateAndApplyPolicySnapshot(handle, snapshot, options, allowedTools);
}

/** Apply a validated snapshot to a run (atomic registry swap). */
export function applyPolicySnapshotToRun(
  run: PaybondAgentRun,
  snapshot: PaybondPolicySnapshot,
): PaybondPolicyReloadResult {
  const previousDigest = run.policyDigest;
  if (previousDigest && previousDigest === snapshot.digest) {
    return { applied: false, previousDigest, newDigest: snapshot.digest, unchanged: true };
  }

  run.applyPolicySnapshot(snapshot);
  return {
    applied: true,
    previousDigest: previousDigest ?? snapshot.digest,
    newDigest: snapshot.digest,
  };
}

/** Core reload pipeline: load, validate, guard, swap. */
export async function reloadPolicyOnRun(
  run: PaybondAgentRun,
  options: PaybondPolicyReloadOptions = {},
): Promise<PaybondPolicyReloadResult> {
  return reloadPolicyOnHandle(run, {
    ...options,
    allowedTools: run.allowedTools,
  });
}
