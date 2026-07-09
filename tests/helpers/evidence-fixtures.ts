import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";

import { getPublicKey, sign } from "@noble/ed25519";

import { signAgentMandateV1, type SignedAgentMandateV1 } from "../../src/agent-mandate.js";
import { ensureEd25519Sha512Sync } from "../../src/ed25519-sync.js";
import { normalizeJson } from "../../src/json-digest.js";
import {
  PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
  PROTOCOL_SOURCE_AP2,
  signProtocolAuthorizationReceiptV1,
  signProtocolSettlementReceiptV1,
  type ProtocolAuthorizationReceiptV1,
  type ProtocolSettlementReceiptV1,
  type ProtocolTransportBindingV1,
} from "../../src/protocol-receipt.js";

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

const AP2_MANDATE_SEED = createHash("sha256").update("evidence-fixtures-ap2-mandate").digest();
const AP2_AUTHORIZATION_RECEIPT_SEED = createHash("sha256")
  .update("evidence-fixtures-ap2-authorization-receipt")
  .digest();
const AP2_SETTLEMENT_RECEIPT_SEED = createHash("sha256")
  .update("evidence-fixtures-ap2-settlement-receipt")
  .digest();

export const AP2_TEST_INTENT_ID = "550e8400-e29b-41d4-a716-446655440000";
export const AP2_TEST_AUTHORIZATION_RECEIPT_ID = "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7";

function testAp2AgentMandate(expiresAt: string): Record<string, unknown> {
  return {
    authorization: {
      kind: " principal ",
      tenant_id: " acme-pilot ",
      principal_subject: " user-123 ",
      principal_type: " User ",
    },
    agent: {
      subject: " did:paybond:travel-booker ",
      issuer: " urn:orchestrator:example ",
      key_id: " kid-1 ",
      display_name: " Travel Booker ",
    },
    allowed_actions: [" tool.use ", "intent.create"],
    allowed_tools: [" Stripe/Capture ", "travel.book", "travel.book"],
    spend_ceiling: {
      amount_minor: 250000,
      currency: " USD ",
    },
    settlement: {
      default_rail: " STRIPE_CONNECT ",
      allowed_rails: ["x402_usdc_base", "stripe_connect", "stripe_connect"],
    },
    constraint: {
      kind: " policy ",
      id: " travel_hold ",
      version: " v3 ",
    },
    expires_at: expiresAt,
    nonce: " nonce-123 ",
    human_presence_mode: " HUMAN_PRESENT ",
  };
}

function authorizationReceiptInput(
  signed: SignedAgentMandateV1,
  transport: ProtocolTransportBindingV1,
): Record<string, unknown> {
  return {
    receipt_id: AP2_TEST_AUTHORIZATION_RECEIPT_ID,
    issued_at: "2026-05-17T18:00:00.000Z",
    status: PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
    intent_id: AP2_TEST_INTENT_ID,
    tenant_id: signed.authorization.tenant_id,
    verifier_id: "paybond-gateway",
    transport_binding: transport,
    mandate_digest_sha256_hex: signed.message_digest_sha256_hex,
    imported_mandate_signing_public_key_ed25519_hex: signed.signing_public_key_ed25519_hex,
    authorization: signed.authorization,
    agent: signed.agent,
    allowed_actions: signed.allowed_actions,
    allowed_tools: signed.allowed_tools,
    spend_ceiling: signed.spend_ceiling,
    settlement: signed.settlement,
    constraint: signed.constraint,
    expires_at: signed.expires_at,
    nonce: signed.nonce,
    human_presence_mode: signed.human_presence_mode,
  };
}

/** Far-future signed AP2 agent mandate for external attestation tests. */
export function signedAp2Mandate(): SignedAgentMandateV1 {
  return signAgentMandateV1(AP2_MANDATE_SEED, testAp2AgentMandate("2030-01-02T03:04:05Z"));
}

/** Signed AP2 protocol authorization receipt derived from {@link signedAp2Mandate}. */
export function signedProtocolAuthorizationReceipt(): ProtocolAuthorizationReceiptV1 {
  const signedMandate = signedAp2Mandate();
  return signProtocolAuthorizationReceiptV1(
    AP2_AUTHORIZATION_RECEIPT_SEED,
    authorizationReceiptInput(signedMandate, {
      source_protocol: PROTOCOL_SOURCE_AP2,
      partner_platform: "Partner Travel Hub",
      external_authorization_id: "authz-123",
      request_id: "req-123",
    }),
  );
}

/** Signed AP2 protocol settlement receipt for external attestation tests. */
export function signedProtocolSettlementReceipt(): ProtocolSettlementReceiptV1 {
  const signedMandate = signedAp2Mandate();
  return signProtocolSettlementReceiptV1(AP2_SETTLEMENT_RECEIPT_SEED, {
    receipt_id: AP2_TEST_INTENT_ID,
    issued_at: "2026-05-17T18:05:00.000Z",
    intent_id: AP2_TEST_INTENT_ID,
    tenant_id: signedMandate.authorization.tenant_id,
    verifier_id: "paybond-gateway",
    transport_binding: {
      source_protocol: PROTOCOL_SOURCE_AP2,
      partner_platform: "Partner Travel Hub",
    },
    authorization_receipt_id: AP2_TEST_AUTHORIZATION_RECEIPT_ID,
    mandate_digest_sha256_hex: signedMandate.message_digest_sha256_hex,
    harbor_state: "released",
    predicate_passed: true,
    settlement_rail: "stripe_connect",
    settlement_mode: "managed",
    principal_did: "did:principal:alice",
    payee_did: "did:payee:hotel",
    currency: "usd",
    amount_cents: 250000,
    terminal_observed_at: "2026-05-17T18:04:00.000Z",
  });
}
