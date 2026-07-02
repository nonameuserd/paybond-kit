/**
 * Maps SEP-2828-style MCP decision/outcome execution records into artifact_attested evidence.
 *
 * Wire shapes follow the draft SEP-2828 pairing model: decision record (pre-side-effect) and
 * outcome record (post-execution) linked via backLink and outcomeDerived.decisionDigest.
 */

import { verifySep2828ReceiptPair } from "./sep2828-signature.js";

export type Sep2828BackLink = {
  attestationDigest: string;
  attestationNonce?: string;
};

export type Sep2828DecisionRecord = {
  backLink?: Sep2828BackLink;
  decisionDerived?: {
    decision?: "allow" | "block" | "escalate";
  };
};

export type Sep2828OutcomeRecord = {
  backLink?: Sep2828BackLink;
  outcomeDerived?: {
    status?: "executed" | "refused" | "errored";
    decisionDigest?: string;
    resultCommitment?: string;
    completedAt?: string;
  };
};

export type ArtifactAttestedEvidence = {
  artifact_blake3_hex: string[];
  operation: string;
  vendor_ref_id: string;
};

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function readBackLink(record: Record<string, unknown>): Sep2828BackLink | undefined {
  const backLink = readObject(record.backLink);
  if (!backLink) {
    return undefined;
  }
  const digest = backLink.attestationDigest;
  if (typeof digest !== "string" || digest.length === 0) {
    return undefined;
  }
  const nonce = backLink.attestationNonce;
  return {
    attestationDigest: digest,
    attestationNonce: typeof nonce === "string" ? nonce : undefined,
  };
}

/** Strips sha256:/blake3: prefixes so digests fit artifact_blake3_hex entries. */
export function stripDigestPrefix(digest: string): string {
  return digest.replace(/^(sha256|blake3):/i, "");
}

function pushDigest(hashes: string[], digest: unknown): void {
  if (typeof digest !== "string" || digest.length === 0) {
    return;
  }
  const normalized = stripDigestPrefix(digest);
  if (!hashes.includes(normalized)) {
    hashes.push(normalized);
  }
}

/**
 * Converts paired SEP-2828 decision and outcome records into artifact_attested evidence fields.
 */
export function mapSep2828ReceiptsToArtifactAttestedEvidence(
  decisionInput: Record<string, unknown>,
  outcomeInput: Record<string, unknown>,
): ArtifactAttestedEvidence {
  verifySep2828ReceiptPair(decisionInput, outcomeInput);

  const outcomeDerived = readObject(outcomeInput.outcomeDerived);
  const status = typeof outcomeDerived?.status === "string" ? outcomeDerived.status : "";
  const operation = status === "executed" ? "attested" : "pending";

  const backLink = readBackLink(outcomeInput) ?? readBackLink(decisionInput);
  const hashes: string[] = [];
  if (outcomeDerived) {
    pushDigest(hashes, outcomeDerived.decisionDigest);
    pushDigest(hashes, outcomeDerived.resultCommitment);
  }
  if (hashes.length === 0 && backLink) {
    pushDigest(hashes, backLink.attestationDigest);
  }

  const vendorRef = backLink?.attestationDigest ?? "mcp-unknown";
  return {
    artifact_blake3_hex: hashes,
    operation,
    vendor_ref_id: vendorRef,
  };
}
