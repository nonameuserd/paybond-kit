import { createHash } from "node:crypto";

import { verify } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";
import {
  AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
  type VerifyAgentReceiptV1Options,
} from "./agent-receipt.js";

export const AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1 =
  "paybond.agent_receipt_transparency_sth_v1";
export const AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1 =
  "paybond.agent_receipt_transparency_inclusion_proof_v1";
export const AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION = 1;

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

export type SignedTreeHeadV1 = {
  kind: string;
  schema_version: number;
  tenant_id: string;
  tree_size: number;
  root_hash_sha256_hex: string;
  issued_at: string;
  signing_algorithm: string;
  signing_public_key_ed25519_hex: string;
  message_digest_sha256_hex: string;
  ed25519_signature_hex: string;
};

export type InclusionProofV1 = {
  kind: string;
  schema_version: number;
  tenant_id: string;
  receipt_id: string;
  message_digest_sha256_hex: string;
  leaf_index: number;
  tree_size: number;
  leaf_hash_sha256_hex: string;
  audit_path_sha256_hex: string[];
  root_hash_sha256_hex: string;
  tree_head: SignedTreeHeadV1;
};

function requireHex64(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!HEX64_RE.test(normalized)) {
    throw new Error(
      `agent receipt transparency: ${field} must be a lowercase 64-byte hex SHA-256 digest`,
    );
  }
  return normalized;
}

function requireHex128(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!HEX128_RE.test(normalized)) {
    throw new Error(
      `agent receipt transparency: ${field} must be a lowercase 128-char hex Ed25519 signature`,
    );
  }
  return normalized;
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function largestPowerOfTwoLessThan(n: number): number {
  if (n <= 1) {
    return 0;
  }
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/** RFC 6962 leaf hash: SHA-256(0x00 || leafData). */
export function merkleLeafHashRFC6962(leafData: Uint8Array): Uint8Array {
  return createHash("sha256").update(Buffer.from([0x00])).update(leafData).digest();
}

/** RFC 6962 internal node hash: SHA-256(0x01 || left || right). */
export function merkleNodeHashRFC6962(left: Uint8Array, right: Uint8Array): Uint8Array {
  return createHash("sha256")
    .update(Buffer.from([0x01]))
    .update(left)
    .update(right)
    .digest();
}

function reconstructMerkleRoot(
  leafHash: Uint8Array,
  leafIndex: number,
  treeSize: number,
  auditPath: Uint8Array[],
): { root: Uint8Array; consumed: number } {
  if (treeSize === 1) {
    return { root: leafHash, consumed: 0 };
  }
  const k = largestPowerOfTwoLessThan(treeSize);
  if (leafIndex < k) {
    const left = reconstructMerkleRoot(leafHash, leafIndex, k, auditPath);
    if (left.consumed >= auditPath.length) {
      throw new Error("agent receipt transparency: audit path too short");
    }
    const right = auditPath[left.consumed]!;
    return {
      root: merkleNodeHashRFC6962(left.root, right),
      consumed: left.consumed + 1,
    };
  }
  const right = reconstructMerkleRoot(leafHash, leafIndex - k, treeSize - k, auditPath);
  if (right.consumed >= auditPath.length) {
    throw new Error("agent receipt transparency: audit path too short");
  }
  const left = auditPath[right.consumed]!;
  return {
    root: merkleNodeHashRFC6962(left, right.root),
    consumed: right.consumed + 1,
  };
}

function allowsSigningPublicKeyHex(
  keyHex: string,
  trusted: readonly string[] | undefined,
): boolean {
  if (!trusted || trusted.length === 0) {
    return true;
  }
  const normalized = keyHex.trim().toLowerCase();
  return trusted.some((item) => item.trim().toLowerCase() === normalized);
}

function canonicalSthBytes(sth: SignedTreeHeadV1): Buffer {
  const canonical = {
    kind: AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
    schema_version: AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
    tenant_id: sth.tenant_id.trim(),
    tree_size: sth.tree_size,
    root_hash_sha256_hex: sth.root_hash_sha256_hex.trim().toLowerCase(),
    issued_at: sth.issued_at.trim(),
    signing_algorithm: AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
  };
  return Buffer.from(JSON.stringify(canonical), "utf8");
}

/** Verifies a signed tree head (digest + Ed25519). */
export async function verifySignedTreeHeadV1(
  sth: SignedTreeHeadV1,
  options: VerifyAgentReceiptV1Options = {},
): Promise<SignedTreeHeadV1> {
  ensureEd25519Sha512Sync();
  if (sth.kind !== AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1) {
    throw new Error(
      `agent receipt transparency: kind must be ${AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1}`,
    );
  }
  if (sth.schema_version !== AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION) {
    throw new Error(
      `agent receipt transparency: schema_version must be ${AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION}`,
    );
  }
  if (!sth.tenant_id?.trim()) {
    throw new Error("agent receipt transparency: tenant_id is required");
  }
  if (!Number.isInteger(sth.tree_size) || sth.tree_size < 0) {
    throw new Error("agent receipt transparency: tree_size must be a non-negative integer");
  }
  if (sth.signing_algorithm !== AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519) {
    throw new Error(
      `agent receipt transparency: signing_algorithm must be ${AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519}`,
    );
  }
  const rootHash = requireHex64(sth.root_hash_sha256_hex, "root_hash_sha256_hex");
  const messageDigest = requireHex64(sth.message_digest_sha256_hex, "message_digest_sha256_hex");
  const publicKeyHex = requireHex64(
    sth.signing_public_key_ed25519_hex,
    "signing_public_key_ed25519_hex",
  );
  if (!allowsSigningPublicKeyHex(publicKeyHex, options.expectedSigningPublicKeys)) {
    throw new Error(
      "agent receipt transparency: signing_public_key_ed25519_hex is not in the configured trusted key set",
    );
  }
  const canonical = canonicalSthBytes({
    ...sth,
    root_hash_sha256_hex: rootHash,
  });
  const digest = createHash("sha256").update(canonical).digest();
  if (bytesToHex(digest) !== messageDigest) {
    throw new Error("agent receipt transparency: message digest mismatch");
  }
  const signature = hexToBytes(requireHex128(sth.ed25519_signature_hex, "ed25519_signature_hex"));
  const publicKey = hexToBytes(publicKeyHex);
  const valid = await verify(signature, digest, publicKey);
  if (!valid) {
    throw new Error("agent receipt transparency: ed25519 signature verification failed");
  }
  return {
    ...sth,
    tenant_id: sth.tenant_id.trim(),
    root_hash_sha256_hex: rootHash,
    message_digest_sha256_hex: messageDigest,
    signing_public_key_ed25519_hex: publicKeyHex,
    ed25519_signature_hex: sth.ed25519_signature_hex.trim().toLowerCase(),
    issued_at: sth.issued_at.trim(),
  };
}

/**
 * Verifies that a receipt message digest is included in a published signed tree head
 * via an RFC 6962 Merkle inclusion proof.
 */
export async function verifyAgentReceiptInclusion(
  proof: InclusionProofV1,
  options: VerifyAgentReceiptV1Options = {},
): Promise<InclusionProofV1> {
  if (proof.kind !== AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1) {
    throw new Error(
      `agent receipt transparency: kind must be ${AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1}`,
    );
  }
  if (proof.schema_version !== AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION) {
    throw new Error(
      `agent receipt transparency: schema_version must be ${AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION}`,
    );
  }
  if (!proof.tenant_id?.trim()) {
    throw new Error("agent receipt transparency: tenant_id is required");
  }
  if (!proof.receipt_id?.trim()) {
    throw new Error("agent receipt transparency: receipt_id is required");
  }
  if (!Number.isInteger(proof.tree_size) || proof.tree_size <= 0) {
    throw new Error("agent receipt transparency: tree_size must be a positive integer");
  }
  if (
    !Number.isInteger(proof.leaf_index) ||
    proof.leaf_index < 0 ||
    proof.leaf_index >= proof.tree_size
  ) {
    throw new Error("agent receipt transparency: leaf_index out of range");
  }

  const messageDigest = requireHex64(proof.message_digest_sha256_hex, "message_digest_sha256_hex");
  const leafHashHex = requireHex64(proof.leaf_hash_sha256_hex, "leaf_hash_sha256_hex");
  const rootHashHex = requireHex64(proof.root_hash_sha256_hex, "root_hash_sha256_hex");
  const sth = await verifySignedTreeHeadV1(proof.tree_head, options);
  if (sth.tenant_id !== proof.tenant_id.trim()) {
    throw new Error("agent receipt transparency: tree_head.tenant_id mismatch");
  }
  if (sth.tree_size !== proof.tree_size) {
    throw new Error("agent receipt transparency: tree_head.tree_size mismatch");
  }
  if (sth.root_hash_sha256_hex !== rootHashHex) {
    throw new Error("agent receipt transparency: tree_head.root_hash mismatch");
  }

  const leafHash = merkleLeafHashRFC6962(hexToBytes(messageDigest));
  if (bytesToHex(leafHash) !== leafHashHex) {
    throw new Error("agent receipt transparency: leaf_hash does not match message digest");
  }
  const auditPath = (proof.audit_path_sha256_hex ?? []).map((entry, index) =>
    hexToBytes(requireHex64(entry, `audit_path_sha256_hex[${index}]`)),
  );
  const { root, consumed } = reconstructMerkleRoot(
    leafHash,
    proof.leaf_index,
    proof.tree_size,
    auditPath,
  );
  if (consumed !== auditPath.length) {
    throw new Error("agent receipt transparency: audit path too long");
  }
  if (bytesToHex(root) !== rootHashHex) {
    throw new Error("agent receipt transparency: inclusion proof does not match root hash");
  }

  return {
    ...proof,
    tenant_id: proof.tenant_id.trim(),
    receipt_id: proof.receipt_id.trim(),
    message_digest_sha256_hex: messageDigest,
    leaf_hash_sha256_hex: leafHashHex,
    root_hash_sha256_hex: rootHashHex,
    audit_path_sha256_hex: auditPath.map((entry) => bytesToHex(entry)),
    tree_head: sth,
  };
}
