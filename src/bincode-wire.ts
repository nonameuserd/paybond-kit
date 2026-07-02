/**
 * bincode 2 `config::standard()` serde wire helpers.
 * Matches `crates/paybond-evidence/src/wire.rs` (`encode_wire`).
 */

import { parse as parseUuid } from "uuid";

const SINGLE_BYTE_MAX = 250;
const U16_BYTE = 251;
const U32_BYTE = 252;
const U64_BYTE = 253;

/** Signed payload revision for evidence binding (`EvidenceSignV1.version`). */
export const EVIDENCE_SIGN_VERSION = 2;

/** Completion contract tail revision (`CompletionContractSignV1.version`). */
export const COMPLETION_CONTRACT_SIGN_VERSION = 2;

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function zigzagU64(n: bigint): bigint {
  if (n < 0n) {
    return BigInt.asUintN(64, ~n) * 2n + 1n;
  }
  return n * 2n;
}

/** bincode 2 standard unsigned varint (little-endian multi-byte tails). */
export function encodeVarintU64(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error("encodeVarintU64: expected non-negative value");
  }
  if (value <= BigInt(SINGLE_BYTE_MAX)) {
    return new Uint8Array([Number(value)]);
  }
  if (value <= 65535n) {
    const out = new Uint8Array(3);
    out[0] = U16_BYTE;
    new DataView(out.buffer).setUint16(1, Number(value), true);
    return out;
  }
  if (value <= 4294967295n) {
    const out = new Uint8Array(5);
    out[0] = U32_BYTE;
    new DataView(out.buffer).setUint32(1, Number(value), true);
    return out;
  }
  if (value <= 18446744073709551615n) {
    const out = new Uint8Array(9);
    out[0] = U64_BYTE;
    new DataView(out.buffer).setBigUint64(1, value, true);
    return out;
  }
  throw new Error("encodeVarintU64: value exceeds u64 range");
}

export function encodeVarintU32(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) {
    throw new Error("encodeVarintU32: expected non-negative integer");
  }
  return encodeVarintU64(BigInt(n));
}

export function encodeVarintI64(n: number): Uint8Array {
  if (!Number.isInteger(n)) {
    throw new Error("encodeVarintI64: expected integer");
  }
  return encodeVarintU64(zigzagU64(BigInt(n)));
}

export function encodeU8(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 255) {
    throw new Error("encodeU8: expected u8");
  }
  return new Uint8Array([n]);
}

export function encodeBincodeString(s: string): Uint8Array {
  const utf8 = new TextEncoder().encode(s);
  return concatBytes(encodeVarintU64(BigInt(utf8.length)), utf8);
}

/** UUID serializes as varint-prefixed 16 raw bytes under bincode 2 serde. */
export function encodeBincodeUuid(intentId: string): Uint8Array {
  const intentBytes = parseUuid(intentId);
  if (intentBytes.length !== 16) {
    throw new Error("intentId must be a UUID string");
  }
  return concatBytes(encodeVarintU64(16n), intentBytes);
}

export function encodeFixed32(bytes: Uint8Array): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error("encodeFixed32: expected 32 bytes");
  }
  return bytes;
}
