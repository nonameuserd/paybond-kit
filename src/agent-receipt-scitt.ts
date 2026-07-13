/**
 * SCITT COSE_Sign1 export adapter for verified ARS digests.
 *
 * Wraps the ARS `message_digest_sha256` as a COSE_Sign1 Signed Statement
 * payload suitable for registration with an external Transparency Service.
 * ARS itself stays JSON-native; this adapter does not change compose/sign.
 *
 * Implements a minimal deterministic CBOR encoder for EdDSA COSE_Sign1
 * (RFC 9052) without introducing a large COSE dependency.
 */

import { createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";

/** Export envelope kind for Kit/Go/Rust parity. */
export const AGENT_RECEIPT_SCITT_EXPORT_KIND_V1 =
  "paybond.agent_receipt_scitt_export_v1";

/** Statement kind encoded as the COSE_Sign1 payload (JCS JSON bytes). */
export const AGENT_RECEIPT_SCITT_STATEMENT_KIND_V1 =
  "paybond.agent_receipt_scitt_statement_v1";

/** COSE algorithm identifier for EdDSA (RFC 9053). */
export const COSE_ALG_EDDSA = -8;

/** COSE header label: alg. */
const COSE_HEADER_ALG = 1;
/** COSE header label: kid. */
const COSE_HEADER_KID = 4;
/** COSE header label: CWT Claims (RFC 9597). */
const COSE_HEADER_CWT_CLAIMS = 15;
/** CWT claim: iss. */
const CWT_CLAIM_ISS = 1;
/** CWT claim: sub. */
const CWT_CLAIM_SUB = 2;

export type AgentReceiptScittStatementV1 = {
  kind: typeof AGENT_RECEIPT_SCITT_STATEMENT_KIND_V1;
  receipt_id: string;
  message_digest_sha256_hex: string;
};

export type BuildAgentReceiptScittExportInput = {
  receiptId: string;
  messageDigestSha256Hex: string;
  /** 32-byte Ed25519 seed or PKCS8-compatible raw seed via Node crypto. */
  signingPrivateKeySeedHex: string;
  /** Issuer claim (iss) for SCITT CWT claims. */
  issuer: string;
  /** Optional key id placed in protected header `kid`. */
  kid?: string;
};

export type AgentReceiptScittExportV1 = {
  kind: typeof AGENT_RECEIPT_SCITT_EXPORT_KIND_V1;
  receipt_id: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  issuer: string;
  kid?: string;
  /** Tagged COSE_Sign1 (CBOR tag 18) as lowercase hex. */
  cose_sign1_tag18_hex: string;
  statement: AgentReceiptScittStatementV1;
};

function canonicalizeJson(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalizeJson(item));
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      out[key] = canonicalizeJson(record[key]);
    }
    return out;
  }
  return value;
}

function jcsBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(canonicalizeJson(value)));
}

function requireHex64(value: string, field: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`scitt export: ${field} must be a lowercase 64-char hex digest`);
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

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeCborUint(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0) {
    throw new Error("scitt export: CBOR uint must be a non-negative integer");
  }
  if (value < 24) {
    return Uint8Array.of(value);
  }
  if (value < 0x100) {
    return Uint8Array.of(24, value);
  }
  if (value < 0x10000) {
    return Uint8Array.of(25, (value >> 8) & 0xff, value & 0xff);
  }
  if (value < 0x100000000) {
    return Uint8Array.of(
      26,
      (value >>> 24) & 0xff,
      (value >>> 16) & 0xff,
      (value >>> 8) & 0xff,
      value & 0xff,
    );
  }
  throw new Error("scitt export: CBOR uint too large");
}

function encodeCborNint(value: number): Uint8Array {
  // Major type 1: -1 - n
  const n = -1 - value;
  if (n < 24) {
    return Uint8Array.of(0x20 | n);
  }
  if (n < 0x100) {
    return Uint8Array.of(0x38, n);
  }
  if (n < 0x10000) {
    return Uint8Array.of(0x39, (n >> 8) & 0xff, n & 0xff);
  }
  throw new Error("scitt export: CBOR nint too large");
}

function encodeCborInt(value: number): Uint8Array {
  if (!Number.isInteger(value)) {
    throw new Error("scitt export: CBOR int must be an integer");
  }
  return value >= 0 ? encodeCborUint(value) : encodeCborNint(value);
}

function encodeCborBstr(bytes: Uint8Array): Uint8Array {
  const header =
    bytes.length < 24
      ? Uint8Array.of(0x40 | bytes.length)
      : bytes.length < 0x100
        ? Uint8Array.of(0x58, bytes.length)
        : bytes.length < 0x10000
          ? Uint8Array.of(0x59, (bytes.length >> 8) & 0xff, bytes.length & 0xff)
          : (() => {
              throw new Error("scitt export: CBOR bstr too large");
            })();
  return concatBytes(header, bytes);
}

function encodeCborTstr(value: string): Uint8Array {
  const bytes = new TextEncoder().encode(value);
  const header =
    bytes.length < 24
      ? Uint8Array.of(0x60 | bytes.length)
      : bytes.length < 0x100
        ? Uint8Array.of(0x78, bytes.length)
        : bytes.length < 0x10000
          ? Uint8Array.of(0x79, (bytes.length >> 8) & 0xff, bytes.length & 0xff)
          : (() => {
              throw new Error("scitt export: CBOR tstr too large");
            })();
  return concatBytes(header, bytes);
}

function encodeCborArray(items: Uint8Array[]): Uint8Array {
  const header =
    items.length < 24
      ? Uint8Array.of(0x80 | items.length)
      : Uint8Array.of(0x98, items.length);
  return concatBytes(header, ...items);
}

function encodeCborMap(entries: Array<[number | string, Uint8Array]>): Uint8Array {
  // Deterministic: sort by encoded key bytes (RFC 8949 §4.2.1).
  const encoded = entries.map(([key, value]) => {
    const keyBytes =
      typeof key === "number" ? encodeCborInt(key) : encodeCborTstr(key);
    return { keyBytes, value };
  });
  encoded.sort((a, b) => {
    const min = Math.min(a.keyBytes.length, b.keyBytes.length);
    for (let i = 0; i < min; i += 1) {
      const diff = a.keyBytes[i]! - b.keyBytes[i]!;
      if (diff !== 0) {
        return diff;
      }
    }
    return a.keyBytes.length - b.keyBytes.length;
  });
  const header =
    encoded.length < 24
      ? Uint8Array.of(0xa0 | encoded.length)
      : Uint8Array.of(0xb8, encoded.length);
  return concatBytes(header, ...encoded.flatMap((entry) => [entry.keyBytes, entry.value]));
}

function encodeCborTag(tag: number, item: Uint8Array): Uint8Array {
  const header =
    tag < 24
      ? Uint8Array.of(0xc0 | tag)
      : tag < 0x100
        ? Uint8Array.of(0xd8, tag)
        : (() => {
            throw new Error("scitt export: CBOR tag too large");
          })();
  return concatBytes(header, item);
}

function ed25519KeyFromSeed(seedHex: string): {
  privateKey: ReturnType<typeof createPrivateKey>;
  publicKeyHex: string;
} {
  const seed = hexToBytes(requireHex64(seedHex, "signing_private_key_seed_hex"));
  const privateKey = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.from(seed),
    ]),
    format: "der",
    type: "pkcs8",
  });
  const pub = createPublicKey(privateKey).export({ type: "spki", format: "der" }) as Buffer;
  return {
    privateKey,
    publicKeyHex: pub.subarray(pub.length - 32).toString("hex"),
  };
}

function buildProtectedHeader(issuer: string, subject: string, kid?: string): Uint8Array {
  const cwtClaims = encodeCborMap([
    [CWT_CLAIM_ISS, encodeCborTstr(issuer)],
    [CWT_CLAIM_SUB, encodeCborTstr(subject)],
  ]);
  const entries: Array<[number | string, Uint8Array]> = [
    [COSE_HEADER_ALG, encodeCborInt(COSE_ALG_EDDSA)],
    [COSE_HEADER_CWT_CLAIMS, cwtClaims],
  ];
  if (kid && kid.trim()) {
    entries.push([COSE_HEADER_KID, encodeCborTstr(kid.trim())]);
  }
  return encodeCborMap(entries);
}

/**
 * Builds a SCITT-oriented COSE_Sign1 export for a verified ARS message digest.
 */
export function buildAgentReceiptScittExport(
  input: BuildAgentReceiptScittExportInput,
): AgentReceiptScittExportV1 {
  ensureEd25519Sha512Sync();
  const receiptId = input.receiptId.trim();
  if (!receiptId) {
    throw new Error("scitt export: receipt_id is required");
  }
  const issuer = input.issuer.trim();
  if (!issuer) {
    throw new Error("scitt export: issuer is required");
  }
  const messageDigest = requireHex64(
    input.messageDigestSha256Hex,
    "message_digest_sha256_hex",
  );
  const statement: AgentReceiptScittStatementV1 = {
    kind: AGENT_RECEIPT_SCITT_STATEMENT_KIND_V1,
    receipt_id: receiptId,
    message_digest_sha256_hex: messageDigest,
  };
  const payload = jcsBytes(statement);
  // SCITT subject is receipt_id; iss is the configured issuer.
  const protectedHeader = buildProtectedHeader(issuer, receiptId, input.kid);
  const protectedBstr = encodeCborBstr(protectedHeader);
  const payloadBstr = encodeCborBstr(payload);
  const sigStructure = encodeCborArray([
    encodeCborTstr("Signature1"),
    protectedBstr,
    encodeCborBstr(new Uint8Array(0)),
    payloadBstr,
  ]);
  const { privateKey, publicKeyHex } = ed25519KeyFromSeed(input.signingPrivateKeySeedHex);
  const signature = nodeSign(null, Buffer.from(sigStructure), privateKey);
  const coseSign1 = encodeCborArray([
    encodeCborBstr(protectedHeader),
    encodeCborMap([]),
    encodeCborBstr(payload),
    encodeCborBstr(new Uint8Array(signature)),
  ]);
  const tagged = encodeCborTag(18, coseSign1);
  const exportDoc: AgentReceiptScittExportV1 = {
    kind: AGENT_RECEIPT_SCITT_EXPORT_KIND_V1,
    receipt_id: receiptId,
    message_digest_sha256_hex: messageDigest,
    signing_public_key_ed25519_hex: publicKeyHex,
    issuer,
    cose_sign1_tag18_hex: bytesToHex(tagged),
    statement,
  };
  if (input.kid?.trim()) {
    exportDoc.kid = input.kid.trim();
  }
  return exportDoc;
}

type DecodedCoseSign1 = {
  protectedRaw: Uint8Array;
  payload: Uint8Array;
  signature: Uint8Array;
};

function readCborLength(
  bytes: Uint8Array,
  offset: number,
  additional: number,
): { length: number; next: number } {
  if (additional < 24) {
    return { length: additional, next: offset };
  }
  if (additional === 24) {
    return { length: bytes[offset]!, next: offset + 1 };
  }
  if (additional === 25) {
    return {
      length: (bytes[offset]! << 8) | bytes[offset + 1]!,
      next: offset + 2,
    };
  }
  throw new Error("scitt export: unsupported CBOR length");
}

function decodeCborItem(
  bytes: Uint8Array,
  offset: number,
): { value: unknown; next: number; raw: Uint8Array } {
  const initial = bytes[offset]!;
  const major = initial >> 5;
  const additional = initial & 0x1f;
  let cursor = offset + 1;
  if (major === 0) {
    const { length, next } = readCborLength(bytes, cursor, additional);
    return { value: length, next, raw: bytes.subarray(offset, next) };
  }
  if (major === 1) {
    const { length, next } = readCborLength(bytes, cursor, additional);
    return { value: -1 - length, next, raw: bytes.subarray(offset, next) };
  }
  if (major === 2 || major === 3) {
    const { length, next } = readCborLength(bytes, cursor, additional);
    const end = next + length;
    const slice = bytes.subarray(next, end);
    return {
      value: major === 2 ? slice : new TextDecoder().decode(slice),
      next: end,
      raw: bytes.subarray(offset, end),
    };
  }
  if (major === 4) {
    const { length, next } = readCborLength(bytes, cursor, additional);
    cursor = next;
    const items: unknown[] = [];
    const start = offset;
    for (let i = 0; i < length; i += 1) {
      const decoded = decodeCborItem(bytes, cursor);
      items.push(decoded.value);
      cursor = decoded.next;
    }
    return { value: items, next: cursor, raw: bytes.subarray(start, cursor) };
  }
  if (major === 5) {
    const { length, next } = readCborLength(bytes, cursor, additional);
    cursor = next;
    const map = new Map<unknown, unknown>();
    const start = offset;
    for (let i = 0; i < length; i += 1) {
      const key = decodeCborItem(bytes, cursor);
      const val = decodeCborItem(bytes, key.next);
      map.set(key.value, val.value);
      cursor = val.next;
    }
    return { value: map, next: cursor, raw: bytes.subarray(start, cursor) };
  }
  if (major === 6) {
    const { length: tag, next } = readCborLength(bytes, cursor, additional);
    const inner = decodeCborItem(bytes, next);
    return {
      value: { tag, value: inner.value },
      next: inner.next,
      raw: bytes.subarray(offset, inner.next),
    };
  }
  throw new Error(`scitt export: unsupported CBOR major type ${major}`);
}

function decodeTaggedCoseSign1(taggedHex: string): DecodedCoseSign1 {
  const bytes = hexToBytes(taggedHex.trim().toLowerCase());
  const decoded = decodeCborItem(bytes, 0);
  const tagged = decoded.value as { tag: number; value: unknown };
  if (!tagged || tagged.tag !== 18 || !Array.isArray(tagged.value) || tagged.value.length !== 4) {
    throw new Error("scitt export: expected CBOR tag 18 COSE_Sign1 array");
  }
  const [protectedRaw, , payload, signature] = tagged.value as [
    Uint8Array,
    unknown,
    Uint8Array,
    Uint8Array,
  ];
  if (!(protectedRaw instanceof Uint8Array) || !(payload instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    throw new Error("scitt export: COSE_Sign1 fields must be bstrs");
  }
  return { protectedRaw, payload, signature };
}

/**
 * Verifies a SCITT export envelope: COSE_Sign1 EdDSA over the statement payload.
 */
export function verifyAgentReceiptScittExport(exportDoc: AgentReceiptScittExportV1): void {
  ensureEd25519Sha512Sync();
  if (exportDoc.kind !== AGENT_RECEIPT_SCITT_EXPORT_KIND_V1) {
    throw new Error("scitt export: unexpected kind");
  }
  const digest = requireHex64(
    exportDoc.message_digest_sha256_hex,
    "message_digest_sha256_hex",
  );
  if (exportDoc.statement.message_digest_sha256_hex !== digest) {
    throw new Error("scitt export: statement digest mismatch");
  }
  if (exportDoc.statement.receipt_id !== exportDoc.receipt_id) {
    throw new Error("scitt export: statement receipt_id mismatch");
  }
  const expectedPayload = jcsBytes(exportDoc.statement);
  const { protectedRaw, payload, signature } = decodeTaggedCoseSign1(
    exportDoc.cose_sign1_tag18_hex,
  );
  if (bytesToHex(payload) !== bytesToHex(expectedPayload)) {
    throw new Error("scitt export: COSE payload mismatch");
  }
  const sigStructure = encodeCborArray([
    encodeCborTstr("Signature1"),
    encodeCborBstr(protectedRaw),
    encodeCborBstr(new Uint8Array(0)),
    encodeCborBstr(payload),
  ]);
  const pub = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(hexToBytes(requireHex64(exportDoc.signing_public_key_ed25519_hex, "signing_public_key_ed25519_hex"))),
    ]),
    format: "der",
    type: "spki",
  });
  const ok = nodeVerify(null, Buffer.from(sigStructure), pub, Buffer.from(signature));
  if (!ok) {
    throw new Error("scitt export: COSE_Sign1 signature invalid");
  }
}
