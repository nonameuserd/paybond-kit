import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import type { AgentReceiptV1 } from "../src/agent-receipt.js";
import { verifyAgentReceiptV1 } from "../src/agent-receipt.js";
import {
  AGENT_RECEIPT_OWNER_DISCLOSURE_INFO,
  AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1,
  decryptOwnerDisclosurePackage,
  deriveOwnerDisclosurePlaintext,
  encryptOwnerDisclosurePackage,
  generateX25519KeyPairHex,
  openHpkeBaseX25519Aes128Gcm,
  sealHpkeBaseX25519Aes128Gcm,
} from "../src/agent-receipt-owner-disclosure.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "agent-receipt");

describe("agent receipt owner disclosure", () => {
  it("hpke base round-trips", () => {
    const { privateKeyHex, publicKeyHex } = generateX25519KeyPairHex();
    const info = Buffer.from(AGENT_RECEIPT_OWNER_DISCLOSURE_INFO, "utf8");
    const aad = Buffer.from("aad");
    const pt = Buffer.from("hello");
    const { enc, ciphertext } = sealHpkeBaseX25519Aes128Gcm(
      Buffer.from(publicKeyHex, "hex"),
      info,
      aad,
      pt,
    );
    const opened = openHpkeBaseX25519Aes128Gcm(
      Buffer.from(privateKeyHex, "hex"),
      enc,
      info,
      aad,
      ciphertext,
    );
    expect(opened.toString("utf8")).toBe("hello");
  });

  it("encrypt/decrypt round-trips", () => {
    const receipt = JSON.parse(
      readFileSync(join(root, "conformance", "signed-action-receipt-v1.json"), "utf8"),
    ) as AgentReceiptV1;
    const plaintext = deriveOwnerDisclosurePlaintext({
      receipt,
      derivedAt: new Date("2026-07-12T18:00:00Z"),
    });
    const { privateKeyHex, publicKeyHex } = generateX25519KeyPairHex();
    const pkg = encryptOwnerDisclosurePackage({
      plaintext,
      recipientPublicKeyX25519Hex: publicKeyHex,
    });
    expect(pkg.kind).toBe(AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1);
    const opened = decryptOwnerDisclosurePackage({
      package: pkg,
      recipientPrivateKeyX25519Hex: privateKeyHex,
    });
    expect(opened.receipt_id).toBe(plaintext.receipt_id);
  });

  it("rejects malformed tee/zk digests on verify", async () => {
    const receipt = JSON.parse(
      readFileSync(join(root, "conformance", "signed-action-receipt-v1.json"), "utf8"),
    ) as AgentReceiptV1;
    expect(receipt.execution).toBeTruthy();
    receipt.execution!.tee_attestation_digest_sha256_hex = "nope";
    await expect(verifyAgentReceiptV1(receipt)).rejects.toThrow(
      /tee_attestation_digest_sha256_hex/,
    );
    receipt.execution!.tee_attestation_digest_sha256_hex = "ab".repeat(32);
    receipt.authorization.zk_policy_proof_digest_sha256_hex = "not-hex";
    await expect(verifyAgentReceiptV1(receipt)).rejects.toThrow(
      /zk_policy_proof_digest_sha256_hex/,
    );
  });
});
