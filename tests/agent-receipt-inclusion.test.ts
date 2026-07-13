import { createHash, createPrivateKey, createPublicKey, sign as nodeSign } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  merkleLeafHashRFC6962,
  merkleNodeHashRFC6962,
  verifyAgentReceiptInclusion,
  type InclusionProofV1,
  type SignedTreeHeadV1,
  AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1,
  AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
  AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
} from "../src/agent-receipt-inclusion.js";
import { AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519 } from "../src/agent-receipt.js";

function largestPowerOfTwoLessThan(n: number): number {
  if (n <= 1) return 0;
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

function merkleRoot(leafHashes: Uint8Array[]): Uint8Array {
  const n = leafHashes.length;
  if (n === 0) return createHash("sha256").update(Buffer.alloc(0)).digest();
  if (n === 1) return leafHashes[0]!;
  const k = largestPowerOfTwoLessThan(n);
  return merkleNodeHashRFC6962(merkleRoot(leafHashes.slice(0, k)), merkleRoot(leafHashes.slice(k)));
}

function inclusionPath(leafHashes: Uint8Array[], leafIndex: number): Uint8Array[] {
  const n = leafHashes.length;
  if (n === 1) return [];
  const k = largestPowerOfTwoLessThan(n);
  if (leafIndex < k) {
    return [...inclusionPath(leafHashes.slice(0, k), leafIndex), merkleRoot(leafHashes.slice(k))];
  }
  return [
    ...inclusionPath(leafHashes.slice(k), leafIndex - k),
    merkleRoot(leafHashes.slice(0, k)),
  ];
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function signSth(seed: Buffer, tenantId: string, treeSize: number, rootHex: string): SignedTreeHeadV1 {
  const keyObject = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      seed.subarray(0, 32),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const canonical = {
    kind: AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
    schema_version: AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
    tenant_id: tenantId,
    tree_size: treeSize,
    root_hash_sha256_hex: rootHex,
    issued_at: "2026-01-01T00:00:00.000Z",
    signing_algorithm: AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
  };
  const canonicalBytes = Buffer.from(JSON.stringify(canonical), "utf8");
  const digest = createHash("sha256").update(canonicalBytes).digest();
  const signature = nodeSign(null, digest, keyObject);
  const pub = createPublicKey(keyObject).export({ type: "spki", format: "der" }) as Buffer;
  const publicKeyHex = pub.subarray(pub.length - 32).toString("hex");
  return {
    kind: AGENT_RECEIPT_TRANSPARENCY_STH_KIND_V1,
    schema_version: AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
    tenant_id: tenantId,
    tree_size: treeSize,
    root_hash_sha256_hex: rootHex,
    issued_at: "2026-01-01T00:00:00.000Z",
    signing_algorithm: AGENT_RECEIPT_SIGNING_ALGORITHM_ED25519,
    signing_public_key_ed25519_hex: publicKeyHex,
    message_digest_sha256_hex: digest.toString("hex"),
    ed25519_signature_hex: signature.toString("hex"),
  };
}

describe("agent receipt inclusion verify", () => {
  it("verifies a multi-leaf inclusion proof against a signed tree head", async () => {
    const digests: string[] = [];
    const leafHashes: Uint8Array[] = [];
    for (let i = 0; i < 5; i += 1) {
      const digest = createHash("sha256").update(Buffer.from([i + 3])).digest();
      digests.push(digest.toString("hex"));
      leafHashes.push(merkleLeafHashRFC6962(digest));
    }
    const root = merkleRoot(leafHashes);
    const rootHex = bytesToHex(root);
    const seed = createHash("sha256").update("ts-agent-receipt-inclusion").digest();
    const sth = signSth(seed, "tenant.example", leafHashes.length, rootHex);
    const leafIndex = 2;
    const path = inclusionPath(leafHashes, leafIndex);
    const proof: InclusionProofV1 = {
      kind: AGENT_RECEIPT_TRANSPARENCY_INCLUSION_PROOF_KIND_V1,
      schema_version: AGENT_RECEIPT_TRANSPARENCY_SCHEMA_VERSION,
      tenant_id: "tenant.example",
      receipt_id: "receipt-2",
      message_digest_sha256_hex: digests[leafIndex]!,
      leaf_index: leafIndex,
      tree_size: leafHashes.length,
      leaf_hash_sha256_hex: bytesToHex(leafHashes[leafIndex]!),
      audit_path_sha256_hex: path.map(bytesToHex),
      root_hash_sha256_hex: rootHex,
      tree_head: sth,
    };
    const verified = await verifyAgentReceiptInclusion(proof);
    expect(verified.leaf_index).toBe(2);
    expect(verified.tree_head.tree_size).toBe(5);
  });
});
