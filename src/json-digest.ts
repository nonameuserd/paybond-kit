/**
 * Canonical JSON normalization and BLAKE3 digest (matches `paybond-evidence` / Harbor signing).
 */

import { hash } from "blake3";

/** Recursively sort object keys for stable JSON serialization. */
export function normalizeJson(value: unknown): unknown {
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => normalizeJson(item));
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const out: Record<string, unknown> = {};
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) {
      out[k] = normalizeJson(obj[k]);
    }
  }
  return out;
}

/** BLAKE3 digest (32 bytes) over compact JSON of {@link normalizeJson}. */
export function jsonValueDigest(value: unknown): Uint8Array {
  const normalized = normalizeJson(value);
  const text = JSON.stringify(normalized);
  const buf = hash(text, { length: 32 });
  return new Uint8Array(buf);
}
