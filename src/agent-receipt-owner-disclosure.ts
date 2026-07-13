/**
 * Confidential HPKE owner disclosure package for Agent Receipt Standard.
 *
 * Separate artifact from the public `paybond.agent_receipt_v1` body. Encrypt /
 * decrypt helpers are always available library exports; this is not part of the
 * signed public ARS body.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
} from "node:crypto";

import type { AgentReceiptV1 } from "./agent-receipt.js";
import { canonicalAgentReceiptBytes } from "./agent-receipt.js";

export const AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1 =
  "paybond.agent_receipt_owner_disclosure_v1";
export const AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1 =
  "paybond.agent_receipt_owner_disclosure_plaintext_v1";
export const AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION = 1;
export const AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE =
  "DHKEM_X25519_HKDF_SHA256/HKDF_SHA256/AES_128_GCM";
export const AGENT_RECEIPT_OWNER_DISCLOSURE_INFO =
  "paybond.agent_receipt_owner_disclosure_v1";

const HPKE_KEM_ID = 0x0020;
const HPKE_KDF_ID = 0x0001;
const HPKE_AEAD_ID = 0x0001;
const HPKE_MODE_BASE = 0x00;
const HPKE_NH = 32;
const HPKE_NK = 16;
const HPKE_NN = 12;
const HPKE_NSECRET = 32;

export type AgentReceiptOwnerDisclosurePlaintextV1 = {
  kind: typeof AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1;
  schema_version: number;
  receipt_id: string;
  message_digest_sha256_hex: string;
  tenant_id: string;
  scope: string;
  derived_at: string;
  authorization: unknown;
  execution?: unknown;
  evidence?: unknown;
  outcome: unknown;
  references: unknown;
  extensions?: unknown;
};

export type AgentReceiptOwnerDisclosureV1 = {
  kind: typeof AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1;
  schema_version: number;
  hpke_suite: typeof AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE;
  info: typeof AGENT_RECEIPT_OWNER_DISCLOSURE_INFO;
  recipient_public_key_x25519_hex: string;
  encapsulated_key_hex: string;
  ciphertext_hex: string;
  aad_sha256_hex: string;
  receipt_id: string;
  message_digest_sha256_hex: string;
  plaintext_content_type: string;
};

function i2osp(n: number, length: number): Buffer {
  const out = Buffer.alloc(length);
  if (length === 1) {
    out[0] = n & 0xff;
  } else if (length === 2) {
    out.writeUInt16BE(n, 0);
  } else {
    throw new Error("hpke: unsupported I2OSP length");
  }
  return out;
}

function suiteIdKem(): Buffer {
  return Buffer.concat([Buffer.from("KEM"), i2osp(HPKE_KEM_ID, 2)]);
}

function suiteIdHpke(): Buffer {
  return Buffer.concat([
    Buffer.from("HPKE"),
    i2osp(HPKE_KEM_ID, 2),
    i2osp(HPKE_KDF_ID, 2),
    i2osp(HPKE_AEAD_ID, 2),
  ]);
}

function labeledExtract(
  suiteId: Buffer,
  salt: Buffer | null,
  label: Buffer,
  ikm: Buffer,
): Buffer {
  const labeledIkm = Buffer.concat([Buffer.from("HPKE-v1"), suiteId, label, ikm]);
  const effectiveSalt = salt && salt.length > 0 ? salt : Buffer.alloc(HPKE_NH);
  return createHmac("sha256", effectiveSalt).update(labeledIkm).digest();
}

function labeledExpand(
  suiteId: Buffer,
  prk: Buffer,
  label: Buffer,
  info: Buffer,
  length: number,
): Buffer {
  const labeledInfo = Buffer.concat([
    i2osp(length, 2),
    Buffer.from("HPKE-v1"),
    suiteId,
    label,
    info,
  ]);
  // HKDF-Expand
  const hashLen = HPKE_NH;
  const n = Math.ceil(length / hashLen);
  let prev = Buffer.alloc(0);
  const out: Buffer[] = [];
  for (let i = 1; i <= n; i++) {
    prev = createHmac("sha256", prk)
      .update(Buffer.concat([prev, labeledInfo, Buffer.from([i])]))
      .digest();
    out.push(prev);
  }
  return Buffer.concat(out).subarray(0, length);
}

function extractAndExpand(dh: Buffer, kemContext: Buffer): Buffer {
  const suiteId = suiteIdKem();
  const eaePrk = labeledExtract(suiteId, null, Buffer.from("eae_prk"), dh);
  return labeledExpand(
    suiteId,
    eaePrk,
    Buffer.from("shared_secret"),
    kemContext,
    HPKE_NSECRET,
  );
}

function x25519Dh(privateKeyRaw: Buffer, publicKeyRaw: Buffer): Buffer {
  const priv = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b656e04220420", "hex"),
      privateKeyRaw,
    ]),
    format: "der",
    type: "pkcs8",
  });
  const pub = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b656e032100", "hex"),
      publicKeyRaw,
    ]),
    format: "der",
    type: "spki",
  });
  return diffieHellman({ privateKey: priv, publicKey: pub });
}

function encap(pkR: Buffer): { sharedSecret: Buffer; enc: Buffer } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const skE = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32);
  const enc = publicKey.export({ type: "spki", format: "der" }).subarray(-32);
  const dh = x25519Dh(skE, pkR);
  const kemContext = Buffer.concat([enc, pkR]);
  return { sharedSecret: extractAndExpand(dh, kemContext), enc };
}

function decap(skR: Buffer, enc: Buffer): Buffer {
  if (enc.length !== 32) {
    throw new Error("owner disclosure: encapsulated key must be 32 bytes");
  }
  const dh = x25519Dh(skR, enc);
  const pkR = (
    createPublicKey(
      createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b656e04220420", "hex"),
          skR,
        ]),
        format: "der",
        type: "pkcs8",
      }),
    ).export({ type: "spki", format: "der" }) as Buffer
  ).subarray(-32);
  const kemContext = Buffer.concat([enc, pkR]);
  return extractAndExpand(dh, kemContext);
}

function keyScheduleBase(sharedSecret: Buffer, info: Buffer): { key: Buffer; baseNonce: Buffer } {
  const suiteId = suiteIdHpke();
  const pskIdHash = labeledExtract(suiteId, null, Buffer.from("psk_id_hash"), Buffer.alloc(0));
  const infoHash = labeledExtract(suiteId, null, Buffer.from("info_hash"), info);
  const keyScheduleContext = Buffer.concat([
    Buffer.from([HPKE_MODE_BASE]),
    pskIdHash,
    infoHash,
  ]);
  const secret = labeledExtract(suiteId, sharedSecret, Buffer.from("secret"), Buffer.alloc(0));
  const key = labeledExpand(suiteId, secret, Buffer.from("key"), keyScheduleContext, HPKE_NK);
  const baseNonce = labeledExpand(
    suiteId,
    secret,
    Buffer.from("base_nonce"),
    keyScheduleContext,
    HPKE_NN,
  );
  return { key, baseNonce };
}

function nonce(baseNonce: Buffer, seq = 0): Buffer {
  const out = Buffer.from(baseNonce);
  for (let i = 0; i < 8; i++) {
    out[out.length - 1 - i]! ^= (seq >>> (8 * i)) & 0xff;
  }
  return out;
}

/** Seal plaintext to a 32-byte X25519 public key. */
export function sealHpkeBaseX25519Aes128Gcm(
  recipientPublicKey: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): { enc: Buffer; ciphertext: Buffer } {
  if (recipientPublicKey.length !== 32) {
    throw new Error("owner disclosure: recipient public key must be 32 bytes");
  }
  const { sharedSecret, enc } = encap(Buffer.from(recipientPublicKey));
  const { key, baseNonce } = keyScheduleBase(sharedSecret, Buffer.from(info));
  const cipher = createCipheriv("aes-128-gcm", key, nonce(baseNonce));
  cipher.setAAD(Buffer.from(aad));
  const encrypted = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { enc, ciphertext: Buffer.concat([encrypted, tag]) };
}

/** Open HPKE ciphertext for a 32-byte X25519 private key. */
export function openHpkeBaseX25519Aes128Gcm(
  recipientPrivateKey: Uint8Array,
  enc: Uint8Array,
  info: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
): Buffer {
  if (recipientPrivateKey.length !== 32) {
    throw new Error("owner disclosure: recipient private key must be 32 bytes");
  }
  const sharedSecret = decap(Buffer.from(recipientPrivateKey), Buffer.from(enc));
  const { key, baseNonce } = keyScheduleBase(sharedSecret, Buffer.from(info));
  const ct = Buffer.from(ciphertext);
  if (ct.length < 16) {
    throw new Error("owner disclosure: ciphertext too short");
  }
  const body = ct.subarray(0, ct.length - 16);
  const tag = ct.subarray(ct.length - 16);
  const decipher = createDecipheriv("aes-128-gcm", key, nonce(baseNonce));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

/** Generate lowercase hex X25519 key pair. */
export function generateX25519KeyPairHex(): { privateKeyHex: string; publicKeyHex: string } {
  const { privateKey, publicKey } = generateKeyPairSync("x25519");
  const privateKeyHex = privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32).toString("hex");
  const publicKeyHex = publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
  return { privateKeyHex, publicKeyHex };
}

function ownerDisclosureAad(receiptId: string, messageDigest: string): Buffer {
  return Buffer.from(
    createHash("sha256")
      .update(`${receiptId.trim()}\0${messageDigest.trim().toLowerCase()}`, "utf8")
      .digest(),
  );
}

function formatRfc3339Seconds(value: Date): string {
  return value.toISOString().replace(/\.\d{3}Z$/, "Z");
}

/**
 * Derive a hash-only disclosure plaintext from a public ARS receipt.
 */
export function deriveOwnerDisclosurePlaintext(input: {
  receipt: AgentReceiptV1;
  derivedAt?: Date;
  extensions?: unknown;
}): AgentReceiptOwnerDisclosurePlaintextV1 {
  const receipt = input.receipt;
  const digest =
    receipt.message_digest_sha256_hex?.trim().toLowerCase() ||
    createHash("sha256").update(canonicalAgentReceiptBytes(receipt)).digest("hex");
  const derivedAt = input.derivedAt ?? new Date();
  const out: AgentReceiptOwnerDisclosurePlaintextV1 = {
    kind: AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1,
    schema_version: AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION,
    receipt_id: receipt.receipt_id,
    message_digest_sha256_hex: digest,
    tenant_id: receipt.tenant_id,
    scope: receipt.scope,
    derived_at: formatRfc3339Seconds(derivedAt),
    authorization: receipt.authorization,
    outcome: receipt.outcome,
    references: receipt.references,
  };
  if (receipt.execution) {
    out.execution = receipt.execution;
  }
  if (receipt.evidence) {
    out.evidence = receipt.evidence;
  }
  if (input.extensions !== undefined) {
    out.extensions = input.extensions;
  }
  return out;
}

/** HPKE-encrypt a derived disclosure plaintext to an owner X25519 public key. */
export function encryptOwnerDisclosurePackage(input: {
  plaintext: AgentReceiptOwnerDisclosurePlaintextV1;
  recipientPublicKeyX25519Hex: string;
}): AgentReceiptOwnerDisclosureV1 {
  if (input.plaintext.kind !== AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1) {
    throw new Error(
      `owner disclosure: plaintext kind must be ${AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1}`,
    );
  }
  const pubHex = input.recipientPublicKeyX25519Hex.trim().toLowerCase();
  if (pubHex.length !== 64) {
    throw new Error("owner disclosure: recipient_public_key_x25519_hex must be 32-byte hex");
  }
  const body = Buffer.from(JSON.stringify(input.plaintext), "utf8");
  const aad = ownerDisclosureAad(
    input.plaintext.receipt_id,
    input.plaintext.message_digest_sha256_hex,
  );
  const { enc, ciphertext } = sealHpkeBaseX25519Aes128Gcm(
    Buffer.from(pubHex, "hex"),
    Buffer.from(AGENT_RECEIPT_OWNER_DISCLOSURE_INFO, "utf8"),
    aad,
    body,
  );
  return {
    kind: AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1,
    schema_version: AGENT_RECEIPT_OWNER_DISCLOSURE_SCHEMA_VERSION,
    hpke_suite: AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE,
    info: AGENT_RECEIPT_OWNER_DISCLOSURE_INFO,
    recipient_public_key_x25519_hex: pubHex,
    encapsulated_key_hex: enc.toString("hex"),
    ciphertext_hex: ciphertext.toString("hex"),
    aad_sha256_hex: aad.toString("hex"),
    receipt_id: input.plaintext.receipt_id,
    message_digest_sha256_hex: input.plaintext.message_digest_sha256_hex.toLowerCase(),
    plaintext_content_type: `application/json; charset=utf-8; profile=${AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1}`,
  };
}

/** Decrypt an HPKE owner disclosure package. */
export function decryptOwnerDisclosurePackage(input: {
  package: AgentReceiptOwnerDisclosureV1;
  recipientPrivateKeyX25519Hex: string;
}): AgentReceiptOwnerDisclosurePlaintextV1 {
  const pkg = input.package;
  if (pkg.kind !== AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1) {
    throw new Error(`owner disclosure: kind must be ${AGENT_RECEIPT_OWNER_DISCLOSURE_KIND_V1}`);
  }
  if (pkg.hpke_suite !== AGENT_RECEIPT_OWNER_DISCLOSURE_HPKE_SUITE) {
    throw new Error(`owner disclosure: unsupported hpke_suite ${JSON.stringify(pkg.hpke_suite)}`);
  }
  if (pkg.info !== AGENT_RECEIPT_OWNER_DISCLOSURE_INFO) {
    throw new Error("owner disclosure: info mismatch");
  }
  const privHex = input.recipientPrivateKeyX25519Hex.trim().toLowerCase();
  const priv = Buffer.from(privHex, "hex");
  if (priv.length !== 32) {
    throw new Error("owner disclosure: recipient private key must be 32-byte hex");
  }
  const enc = Buffer.from(pkg.encapsulated_key_hex.trim().toLowerCase(), "hex");
  const ciphertext = Buffer.from(pkg.ciphertext_hex.trim().toLowerCase(), "hex");
  const aad = ownerDisclosureAad(pkg.receipt_id, pkg.message_digest_sha256_hex);
  if (aad.toString("hex") !== pkg.aad_sha256_hex.trim().toLowerCase()) {
    throw new Error("owner disclosure: aad_sha256_hex mismatch");
  }
  const plaintextBytes = openHpkeBaseX25519Aes128Gcm(
    priv,
    enc,
    Buffer.from(AGENT_RECEIPT_OWNER_DISCLOSURE_INFO, "utf8"),
    aad,
    ciphertext,
  );
  const plaintext = JSON.parse(
    plaintextBytes.toString("utf8"),
  ) as AgentReceiptOwnerDisclosurePlaintextV1;
  if (plaintext.kind !== AGENT_RECEIPT_OWNER_DISCLOSURE_PLAINTEXT_KIND_V1) {
    throw new Error("owner disclosure: decrypted kind mismatch");
  }
  if (plaintext.receipt_id !== pkg.receipt_id) {
    throw new Error("owner disclosure: decrypted receipt binding mismatch");
  }
  return plaintext;
}
