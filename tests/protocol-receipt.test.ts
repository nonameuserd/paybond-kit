import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { signAgentMandateV1, type SignedAgentMandateV1 } from "../src/agent-mandate.js";
import {
  PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
  PROTOCOL_SOURCE_AP2,
  signProtocolAuthorizationReceiptV1,
  signProtocolSettlementReceiptV1,
  verifyProtocolAuthorizationReceiptV1,
  verifyProtocolSettlementReceiptV1,
  type ProtocolAuthorizationReceiptV1,
  type ProtocolTransportBindingV1,
} from "../src/protocol-receipt.js";

function ed25519Seed(label: string): Uint8Array {
  return createHash("sha256").update(label).digest();
}

function testAgentMandate(expiresAt: string): Record<string, unknown> {
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

function signedTestAgentMandate(expiresAt: string): SignedAgentMandateV1 {
  const seed = ed25519Seed("protocol-signed-agent-mandate");
  return signAgentMandateV1(seed, testAgentMandate(expiresAt));
}

function authorizationReceiptInput(
  signed: SignedAgentMandateV1,
  transport: ProtocolTransportBindingV1,
): Record<string, unknown> {
  return {
    receipt_id: "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
    issued_at: "2026-05-17T18:00:00.000Z",
    status: PROTOCOL_RECEIPT_STATUS_AUTHORIZED,
    intent_id: "550e8400-e29b-41d4-a716-446655440000",
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

describe("verifyProtocolAuthorizationReceiptV1", () => {
  it("round-trips sign and verify", () => {
    const seed = ed25519Seed("protocol-authorization-receipt");
    const signedMandate = signedTestAgentMandate("2026-05-18T00:00:00.000Z");
    const receipt = signProtocolAuthorizationReceiptV1(
      seed,
      authorizationReceiptInput(signedMandate, {
        source_protocol: "AP2",
        partner_platform: "Partner Travel Hub",
        external_authorization_id: "authz-123",
        request_id: "req-123",
      }),
    );

    const verified = verifyProtocolAuthorizationReceiptV1(receipt);

    expect(verified.status).toBe(PROTOCOL_RECEIPT_STATUS_AUTHORIZED);
    expect(verified.transport_binding.source_protocol).toBe(PROTOCOL_SOURCE_AP2);
    expect(verified.intent_id).toBe("550e8400-e29b-41d4-a716-446655440000");
    expect(verified.message_digest_sha256_hex).toHaveLength(64);
  });

  it("rejects tampering after signing", () => {
    const seed = ed25519Seed("protocol-authorization-receipt-tamper");
    const signedMandate = signedTestAgentMandate("2026-05-18T00:00:00.000Z");
    const receipt = signProtocolAuthorizationReceiptV1(
      seed,
      authorizationReceiptInput(signedMandate, { source_protocol: PROTOCOL_SOURCE_AP2 }),
    );

    const tampered: ProtocolAuthorizationReceiptV1 = {
      ...receipt,
      transport_binding: { ...receipt.transport_binding, partner_platform: "other" },
    };

    expect(() => verifyProtocolAuthorizationReceiptV1(tampered)).toThrow(/message digest mismatch/);
  });
});

describe("verifyProtocolSettlementReceiptV1", () => {
  it("round-trips sign and verify", () => {
    const seed = ed25519Seed("protocol-settlement-receipt");
    const receipt = signProtocolSettlementReceiptV1(seed, {
      receipt_id: "550e8400-e29b-41d4-a716-446655440000",
      issued_at: "2026-05-17T18:05:00.000Z",
      intent_id: "550e8400-e29b-41d4-a716-446655440000",
      tenant_id: "acme-pilot",
      verifier_id: "paybond-gateway",
      transport_binding: {
        source_protocol: PROTOCOL_SOURCE_AP2,
        partner_platform: "Partner Travel Hub",
      },
      authorization_receipt_id: "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
      mandate_digest_sha256_hex: "ab".repeat(32),
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

    const verified = verifyProtocolSettlementReceiptV1(receipt);

    expect(verified.harbor_state).toBe("released");
    expect(verified.authorization_receipt_id).toBe("db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7");
    expect(verified.predicate_passed).toBe(true);
    expect(verified.message_digest_sha256_hex).toHaveLength(64);
  });

  it("rejects non-terminal harbor state", () => {
    const seed = ed25519Seed("protocol-settlement-receipt-invalid");
    expect(() =>
      signProtocolSettlementReceiptV1(seed, {
        receipt_id: "550e8400-e29b-41d4-a716-446655440000",
        issued_at: "2026-05-17T18:05:00.000Z",
        intent_id: "550e8400-e29b-41d4-a716-446655440000",
        tenant_id: "acme-pilot",
        verifier_id: "paybond-gateway",
        transport_binding: { source_protocol: PROTOCOL_SOURCE_AP2 },
        authorization_receipt_id: "db233f4d-50a7-51d7-9c0b-f7bd7ee5fbf7",
        mandate_digest_sha256_hex: "ab".repeat(32),
        harbor_state: "funded",
        settlement_rail: "stripe_connect",
        settlement_mode: "managed",
        principal_did: "did:principal:alice",
        payee_did: "did:payee:hotel",
        currency: "usd",
        amount_cents: 250000,
        terminal_observed_at: "2026-05-17T18:04:00.000Z",
      }),
    ).toThrow(/harbor_state must be released, refunded, resolved_split, or escalated_external/);
  });
});
