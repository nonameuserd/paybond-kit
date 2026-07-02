import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import { getPublicKey, sign } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "../../src/ed25519-sync.js";
import { normalizeJson } from "../../src/json-digest.js";

const SIGNATURE_KEYS = new Set([
  "signature",
  "ed25519_signature_hex",
  "message_digest_sha256_hex",
  "signing_public_key_ed25519_hex",
]);
const ASSERTED_BLOCKS = ["issuerAsserted", "receiptAsserted"] as const;

function stripSignatureFields(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (SIGNATURE_KEYS.has(key)) {
      continue;
    }
    if ((ASSERTED_BLOCKS as readonly string[]).includes(key) && value && typeof value === "object") {
      const asserted = value as Record<string, unknown>;
      const stripped: Record<string, unknown> = {};
      for (const [innerKey, innerValue] of Object.entries(asserted)) {
        if (!SIGNATURE_KEYS.has(innerKey)) {
          stripped[innerKey] = innerValue;
        }
      }
      if (Object.keys(stripped).length > 0) {
        out[key] = stripped;
      }
      continue;
    }
    out[key] = value;
  }
  return out;
}

function canonicalJsonBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(normalizeJson(value)));
}

export async function signSep2828Record(
  record: Record<string, unknown>,
  block: "issuerAsserted" | "receiptAsserted",
): Promise<Record<string, unknown>> {
  ensureEd25519Sha512Sync();
  const seed = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
  const publicKeyHex = Buffer.from(getPublicKey(seed)).toString("hex");
  const signed: Record<string, unknown> = {
    ...record,
    [block]: {
      iss: "did:example:mcp-server",
      signing_public_key_ed25519_hex: publicKeyHex,
    },
  };
  const digest = createHash("sha256").update(canonicalJsonBytes(stripSignatureFields(signed))).digest();
  const signatureHex = Buffer.from(await sign(digest, seed)).toString("hex");
  (signed[block] as Record<string, unknown>).ed25519_signature_hex = signatureHex;
  return signed;
}

export async function signedSep2828Pair(): Promise<{
  decision: Record<string, unknown>;
  outcome: Record<string, unknown>;
}> {
  const decisionBody = {
    backLink: { attestationDigest: "sha256:deadbeef", attestationNonce: "nonce-1" },
    decisionDerived: { decision: "allow" },
  };
  const decision = await signSep2828Record(decisionBody, "issuerAsserted");
  const decisionDigest = createHash("sha256")
    .update(canonicalJsonBytes(stripSignatureFields(decision)))
    .digest("hex");
  const outcomeBody = {
    backLink: { attestationDigest: "sha256:deadbeef", attestationNonce: "nonce-1" },
    outcomeDerived: {
      status: "executed",
      decisionDigest: `sha256:${decisionDigest}`,
      resultCommitment: "blake3:22222222",
    },
  };
  const outcome = await signSep2828Record(outcomeBody, "receiptAsserted");
  return { decision, outcome };
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function signedJwsX402Receipt(payload: Record<string, unknown>): Record<string, unknown> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
  const header = { alg: "EdDSA", jwk };
  const headerB64 = base64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signatureB64 = base64Url(cryptoSign(null, Buffer.from(signingInput), privateKey));
  return {
    extensions: {
      "offer-receipt": {
        info: {
          receipt: {
            format: "jws",
            signature: `${headerB64}.${payloadB64}.${signatureB64}`,
          },
        },
      },
    },
  };
}
