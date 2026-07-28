import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  type SignedX402Receipt,
  verifySignedX402Receipt,
} from "../src/x402-receipt-signature.js";

const PAYLOAD = {
  version: 1,
  network: "eip155:84532",
  resourceUrl: "https://api.vendor.example/job/123",
  payer: "0xabc123",
  issuedAt: 1710000000,
  transaction: "0xdeadbeef",
};

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Build a JWS-format signed receipt with a fresh Ed25519 key; returns the receipt + key identity. */
function signedJws(payload: Record<string, unknown>): {
  signed: SignedX402Receipt;
  jwkX: string;
  thumbprint: string;
} {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" }) as { crv: string; kty: string; x: string };
  const header = { alg: "EdDSA", jwk };
  const headerB64 = base64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = base64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signatureB64 = base64Url(cryptoSign(null, Buffer.from(signingInput), privateKey));
  const canonical = JSON.stringify({ crv: jwk.crv, kty: "OKP", x: jwk.x });
  const thumbprint = createHash("sha256").update(new TextEncoder().encode(canonical)).digest("base64url");
  return {
    signed: { format: "jws", signature: `${headerB64}.${payloadB64}.${signatureB64}` },
    jwkX: jwk.x,
    thumbprint,
  };
}

describe("verifySignedX402Receipt (JWS expectedSigner)", () => {
  it("fails closed when no expected signer is pinned", () => {
    const { signed } = signedJws(PAYLOAD);
    // A self-consistent JWS proves nothing about the issuer without a pin.
    expect(() => verifySignedX402Receipt(signed, { expectedSigner: "" })).toThrow(
      /requires a non-empty expectedSigner/,
    );
  });

  it("accepts a matching expected signer by raw jwk x", () => {
    const { signed, jwkX } = signedJws(PAYLOAD);
    expect(verifySignedX402Receipt(signed, { expectedSigner: jwkX })).toMatchObject({
      resourceUrl: PAYLOAD.resourceUrl,
    });
  });

  it("accepts a matching expected signer by RFC 7638 thumbprint", () => {
    const { signed, thumbprint } = signedJws(PAYLOAD);
    expect(verifySignedX402Receipt(signed, { expectedSigner: thumbprint })).toMatchObject({
      resourceUrl: PAYLOAD.resourceUrl,
    });
  });

  it("rejects a receipt whose embedded key does not match the expected signer", () => {
    const { signed } = signedJws(PAYLOAD);
    // Attacker forged a self-consistent receipt with their own key: pinning must reject it.
    expect(() =>
      verifySignedX402Receipt(signed, { expectedSigner: "not-the-real-signer-thumbprint" }),
    ).toThrow(/does not match expected signer/);
  });

  it("still rejects a tampered signature regardless of expected signer", () => {
    const { signed, jwkX } = signedJws(PAYLOAD);
    const tampered: SignedX402Receipt = {
      format: "jws",
      signature: signed.signature.slice(0, -4) + "AAAA",
    };
    expect(() => verifySignedX402Receipt(tampered, { expectedSigner: jwkX })).toThrow();
  });
});
