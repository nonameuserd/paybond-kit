import type { PaybondToolRegistry } from "../agent/registry.js";
import { canonicalPolicyDocumentDigest, policyVersionLabel } from "./digest.js";
import type { PaybondPolicyDocumentV1 } from "./schema.js";

export type PaybondPolicySnapshotSource = "file" | "remote" | "effective";

/** Versioned policy snapshot loaded at bind time (Tier 7 hot-reload foundation). */
export type PaybondPolicySnapshot = {
  /** `sha256:<hex>` digest of the canonical policy JSON. */
  digest: string;
  /** `{policy_name}@{digest_short}` label for audit and status output. */
  version: string;
  /** RFC3339 timestamp when this snapshot was loaded. */
  loadedAt: string;
  source: PaybondPolicySnapshotSource;
  registry: PaybondToolRegistry;
  /** Effective policy document backing this snapshot (used for reload loosening checks). */
  document: PaybondPolicyDocumentV1;
};

export type CreatePolicySnapshotInput = {
  document: PaybondPolicyDocumentV1;
  registry: PaybondToolRegistry;
  source: PaybondPolicySnapshotSource;
  /** When omitted, digest is computed locally from the document. */
  digest?: string;
  loadedAt?: string;
};

/** Build a policy snapshot for {@link PaybondAgentRun.bind}. */
export function createPolicySnapshot(input: CreatePolicySnapshotInput): PaybondPolicySnapshot {
  const digest = input.digest?.trim() || canonicalPolicyDocumentDigest(input.document);
  return {
    digest,
    version: policyVersionLabel(input.document.name, digest),
    loadedAt: input.loadedAt ?? new Date().toISOString(),
    source: input.source,
    registry: input.registry,
    document: input.document,
  };
}

/** Build a snapshot from a Gateway effective-policy resolution. */
export function createPolicySnapshotFromEffective(input: {
  document: PaybondPolicyDocumentV1;
  registry: PaybondToolRegistry;
  effectivePolicyDigest: string;
  loadedAt?: string;
}): PaybondPolicySnapshot {
  return createPolicySnapshot({
    document: input.document,
    registry: input.registry,
    source: "effective",
    digest: input.effectivePolicyDigest,
    loadedAt: input.loadedAt,
  });
}
