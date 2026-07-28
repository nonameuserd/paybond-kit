/** x402 Signed Offer & Receipt extension signature verification. */

import { createHash, createPublicKey, verify as cryptoVerify, type JsonWebKey as NodeJsonWebKey } from "node:crypto";

import { keccak_256 } from "@noble/hashes/sha3";
import { Signature } from "@noble/secp256k1";

export type SignedX402Receipt = {
  format: "eip712" | "jws";
  payload?: Record<string, unknown>;
  signature: string;
};

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function readString(record: Record<string, unknown>, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}

function base64UrlToBytes(input: string): Uint8Array {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
  return Uint8Array.from(Buffer.from(normalized + pad, "base64"));
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function keccakHex(data: Uint8Array): Uint8Array {
  return keccak_256(data);
}

function encodeType(typeName: string, fields: Array<{ name: string; type: string }>): string {
  return `${typeName}(${fields.map((field) => `${field.type} ${field.name}`).join(",")})`;
}

function encodeValue(type: string, value: unknown): Uint8Array {
  if (type === "string") {
    return keccakHex(new TextEncoder().encode(String(value ?? "")));
  }
  if (type === "uint256") {
    const bigint = typeof value === "bigint" ? value : BigInt(String(value ?? 0));
    const hex = bigint.toString(16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  throw new Error(`unsupported EIP-712 type ${type}`);
}

function hashStruct(
  typeName: string,
  fields: Array<{ name: string; type: string }>,
  data: Record<string, unknown>,
): Uint8Array {
  const encoded = [
    keccakHex(new TextEncoder().encode(encodeType(typeName, fields))),
    ...fields.map((field) => encodeValue(field.type, data[field.name])),
  ];
  return keccakHex(Buffer.concat(encoded.map((part) => Buffer.from(part))));
}

const RECEIPT_FIELDS = [
  { name: "version", type: "uint256" },
  { name: "network", type: "string" },
  { name: "resourceUrl", type: "string" },
  { name: "payer", type: "string" },
  { name: "issuedAt", type: "uint256" },
  { name: "transaction", type: "string" },
] as const;

function normalizeReceiptPayload(payload: Record<string, unknown>): Record<string, unknown> {
  const transaction = payload.transaction;
  return {
    ...payload,
    transaction: typeof transaction === "string" ? transaction : "",
  };
}

function eip712ReceiptDigest(payload: Record<string, unknown>): Uint8Array {
  const domainFields = [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
  ];
  const domain = {
    name: "x402 receipt",
    version: "1",
    chainId: 1,
  };
  const normalized = normalizeReceiptPayload(payload);
  const domainSeparator = hashStruct("EIP712Domain", domainFields, domain);
  const structHash = hashStruct("Receipt", [...RECEIPT_FIELDS], normalized);
  return keccakHex(Buffer.concat([Buffer.from([0x19, 0x01]), Buffer.from(domainSeparator), Buffer.from(structHash)]));
}

function parseEip712Signature(signature: string): { r: bigint; s: bigint; v: number } {
  const trimmed = signature.trim();
  if (!/^0x[0-9a-fA-F]{130}$/.test(trimmed)) {
    throw new Error("x402 EIP-712 signature must be 0x-prefixed 65-byte hex");
  }
  const body = trimmed.slice(2);
  const r = BigInt(`0x${body.slice(0, 64)}`);
  const s = BigInt(`0x${body.slice(64, 128)}`);
  const v = Number.parseInt(body.slice(128, 130), 16);
  return { r, s, v };
}

function recoverEip712Signer(digest: Uint8Array, signature: string): string {
  const { r, s, v } = parseEip712Signature(signature);
  const recovery = v >= 27 ? v - 27 : v;
  const sigBytes = new Uint8Array(64);
  sigBytes.set(Uint8Array.from(Buffer.from(r.toString(16).padStart(64, "0"), "hex")), 0);
  sigBytes.set(Uint8Array.from(Buffer.from(s.toString(16).padStart(64, "0"), "hex")), 32);
  const publicKey = Signature.fromCompact(sigBytes).addRecoveryBit(recovery).recoverPublicKey(digest);
  const uncompressed = publicKey.toBytes(false);
  const addressBytes = keccakHex(uncompressed.slice(1)).slice(-20);
  return `0x${Buffer.from(addressBytes).toString("hex")}`;
}

/**
 * RFC 7638 SHA-256 JWK thumbprint (base64url, no padding) over the required
 * members only. Used to pin a JWS receipt to an expected signing key, since the
 * signing key is embedded in the (attacker-controllable) JWS header.
 */
function jwkThumbprint(jwk: Record<string, unknown>): string {
  const kty = typeof jwk.kty === "string" ? jwk.kty : undefined;
  let canonical: string;
  if (kty === "OKP") {
    const crv = String(jwk.crv ?? "");
    const x = String(jwk.x ?? "");
    // Members in lexicographic order per RFC 7638: crv, kty, x.
    canonical = JSON.stringify({ crv, kty: "OKP", x });
  } else if (kty === "EC") {
    const crv = String(jwk.crv ?? "");
    const x = String(jwk.x ?? "");
    const y = String(jwk.y ?? "");
    // Members in lexicographic order per RFC 7638: crv, kty, x, y.
    canonical = JSON.stringify({ crv, kty: "EC", x, y });
  } else {
    throw new Error("x402 JWS expectedSigner check requires an OKP or EC jwk");
  }
  return createHash("sha256").update(new TextEncoder().encode(canonical)).digest("base64url");
}

/**
 * Enforce a caller-supplied `expectedSigner` against the JWS header's embedded
 * key. Because the JWS carries its own verification key, a valid signature
 * alone proves only that the token is internally self-consistent — not that it
 * came from a trusted party. `expectedSigner` must equal either the RFC 7638
 * JWK thumbprint (base64url SHA-256) or, for OKP keys, the raw base64url `x`.
 */
function assertJwsExpectedSigner(jwk: Record<string, unknown>, expectedSigner: string): void {
  const expected = expectedSigner.trim();
  if (!expected) {
    return;
  }
  const thumbprint = jwkThumbprint(jwk);
  const rawX = typeof jwk.x === "string" ? jwk.x.trim() : "";
  if (expected === thumbprint || (rawX !== "" && expected === rawX)) {
    return;
  }
  throw new Error("x402 JWS embedded key does not match expected signer");
}

function verifyJwsCompactSignature(
  signature: string,
  options?: { expectedSigner?: string },
): Record<string, unknown> {
  const parts = signature.split(".");
  if (parts.length !== 3) {
    throw new Error("x402 JWS signature must use compact serialization");
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(Buffer.from(base64UrlToBytes(headerB64)).toString("utf8")) as Record<string, unknown>;
  const payload = JSON.parse(Buffer.from(base64UrlToBytes(payloadB64)).toString("utf8")) as Record<string, unknown>;
  const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signatureBytes = base64UrlToBytes(sigB64);
  const expectedSigner = options?.expectedSigner?.trim();

  const alg = header.alg;
  if (alg === "EdDSA" || alg === "Ed25519") {
    const jwk = readObject(header.jwk);
    const x = jwk ? readString(jwk, "x") : undefined;
    if (!jwk || !x) {
      throw new Error("x402 JWS Ed25519 verification requires embedded jwk.x");
    }
    const publicKey = createPublicKey({
      key: jwk as NodeJsonWebKey,
      format: "jwk",
    });
    if (!cryptoVerify(null, signingInput, publicKey, signatureBytes)) {
      throw new Error("x402 JWS Ed25519 signature verification failed");
    }
    if (expectedSigner) {
      assertJwsExpectedSigner(jwk, expectedSigner);
    }
    return payload;
  }

  if (alg === "ES256") {
    const jwk = readObject(header.jwk);
    if (!jwk) {
      throw new Error("x402 JWS ES256 verification requires embedded jwk");
    }
    const publicKey = createPublicKey({
      key: jwk as NodeJsonWebKey,
      format: "jwk",
    });
    if (!cryptoVerify("sha256", signingInput, publicKey, signatureBytes)) {
      throw new Error("x402 JWS ES256 signature verification failed");
    }
    if (expectedSigner) {
      assertJwsExpectedSigner(jwk, expectedSigner);
    }
    return payload;
  }

  throw new Error(`unsupported x402 JWS alg ${String(alg)}`);
}

/** Locates a signed x402 receipt artifact in common wire envelopes. */
export function extractSignedX402Receipt(input: Record<string, unknown>): SignedX402Receipt {
  const extensions = readObject(input.extensions);
  if (extensions) {
    const offerReceipt = readObject(extensions["offer-receipt"]) ?? readObject(extensions.offerReceipt);
    const info = offerReceipt ? readObject(offerReceipt.info) : undefined;
    const receipt = info ? readObject(info.receipt) : undefined;
    if (receipt && typeof receipt.format === "string" && typeof receipt.signature === "string") {
      return {
        format: receipt.format === "jws" ? "jws" : "eip712",
        payload: readObject(receipt.payload),
        signature: receipt.signature,
      };
    }
    if (offerReceipt) {
      const nested = readObject(offerReceipt.receipt) ?? offerReceipt;
      if (nested && typeof nested.format === "string" && typeof nested.signature === "string") {
        return {
          format: nested.format === "jws" ? "jws" : "eip712",
          payload: readObject(nested.payload),
          signature: nested.signature,
        };
      }
    }
  }

  const receipt = readObject(input.receipt);
  if (receipt && typeof receipt.format === "string" && typeof receipt.signature === "string") {
    return {
      format: receipt.format === "jws" ? "jws" : "eip712",
      payload: readObject(receipt.payload),
      signature: receipt.signature,
    };
  }

  if (typeof input.format === "string" && typeof input.signature === "string") {
    return {
      format: input.format === "jws" ? "jws" : "eip712",
      payload: readObject(input.payload),
      signature: input.signature,
    };
  }

  throw new Error("x402 receipt input missing signed offer-receipt artifact (format and signature required)");
}

/**
 * Cryptographically verifies an x402 signed receipt before digest mapping.
 *
 * SECURITY: An x402 receipt carries its own verification key (the JWS embedded
 * `jwk`, or the recoverable EIP-712 signer). A structurally valid signature
 * therefore proves only that the artifact is internally self-consistent — it
 * does NOT establish that the receipt was issued by any trusted party. This
 * function therefore **requires** `options.expectedSigner` and fails closed
 * when it is missing or empty; a receipt can only be trusted once it is pinned
 * to a known issuer key:
 *
 * - `eip712`: a 0x-prefixed Ethereum address (checksum-insensitive).
 * - `jws`: the RFC 7638 JWK thumbprint (base64url SHA-256) or, for OKP keys,
 *   the raw base64url `x` coordinate.
 *
 * @param signed - The extracted signed x402 receipt (JWS or EIP-712).
 * @param options - Must supply a non-empty `expectedSigner` to pin the issuer.
 * @returns The verified receipt payload.
 * @throws {Error} If `expectedSigner` is missing/empty, the signature is
 *   invalid, or the recovered/embedded key does not match `expectedSigner`.
 */
export function verifySignedX402Receipt(
  signed: SignedX402Receipt,
  options: { expectedSigner: string },
): Record<string, unknown> {
  const expectedSigner = options?.expectedSigner?.trim();
  if (!expectedSigner) {
    throw new Error(
      "x402 receipt verification requires a non-empty expectedSigner to authenticate the issuer",
    );
  }

  if (signed.format === "jws") {
    return verifyJwsCompactSignature(signed.signature, { expectedSigner });
  }

  if (!signed.payload) {
    throw new Error("x402 EIP-712 receipt requires payload alongside signature");
  }
  const digest = eip712ReceiptDigest(signed.payload);
  const recovered = recoverEip712Signer(digest, signed.signature);
  if (recovered.toLowerCase() !== expectedSigner.toLowerCase()) {
    throw new Error("x402 EIP-712 recovered signer does not match expected signer");
  }
  return signed.payload;
}
