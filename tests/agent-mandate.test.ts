import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  agentMandateDigestSha256Hex,
  canonicalAgentMandateJsonBytes,
  normalizeAgentMandateV1,
  signAgentMandateV1,
  verifySignedAgentMandateV1,
} from "../src/agent-mandate.js";

const FIXTURE_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../go/gateway/internal/protocolv2/testdata/agent_mandate_canonical_v1.json",
);

type AgentMandateCanonicalFixtureFile = {
  version: number;
  cases: Array<{
    name: string;
    mandate: Record<string, unknown>;
    canonical_json: string;
    canonical_json_hex: string;
    digest_sha256_hex: string;
  }>;
};

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

describe("agent mandate canonical fixtures", () => {
  const fixtures = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as AgentMandateCanonicalFixtureFile;

  it("loads Go gateway fixture file version 1", () => {
    expect(fixtures.version).toBe(1);
    expect(fixtures.cases.length).toBeGreaterThan(0);
  });

  it.each(fixtures.cases.map((fixture) => [fixture.name, fixture] as const))(
    "matches Go canonical JSON and digest for %s",
    (_name, fixture) => {
      const body = canonicalAgentMandateJsonBytes(fixture.mandate);
      const digest = agentMandateDigestSha256Hex(fixture.mandate);
      const expectedBytes = Buffer.from(fixture.canonical_json_hex, "hex");

      expect(new TextDecoder().decode(body)).toBe(fixture.canonical_json);
      expect(Buffer.from(body)).toEqual(expectedBytes);
      expect(digest).toBe(fixture.digest_sha256_hex);
    },
  );
});

describe("normalizeAgentMandateV1", () => {
  it("canonicalizes representative fields", () => {
    const normalized = normalizeAgentMandateV1(testAgentMandate("2030-01-02T03:04:05Z"));

    expect(normalized.kind).toBe("paybond.agent_mandate_v1");
    expect(normalized.authorization.kind).toBe("principal");
    expect(normalized.authorization.tenant_id).toBe("acme-pilot");
    expect(normalized.authorization.principal_type).toBe("user");
    expect(normalized.allowed_actions).toEqual(["intent.create", "tool.use"]);
    expect(normalized.allowed_tools).toEqual(["stripe/capture", "travel.book"]);
    expect(normalized.spend_ceiling.currency).toBe("usd");
    expect(normalized.settlement.default_rail).toBe("stripe_connect");
    expect(normalized.settlement.allowed_rails).toEqual(["stripe_connect", "x402_usdc_base"]);
    expect(normalized.constraint.kind).toBe("policy");
    expect(normalized.human_presence_mode).toBe("human_present");
    expect(normalized.nonce).toBe("nonce-123");
  });

  it("returns the same digest before and after normalization", () => {
    const raw = testAgentMandate("2030-01-02T03:04:05Z");
    const normalized = normalizeAgentMandateV1(raw);
    expect(agentMandateDigestSha256Hex(raw)).toBe(agentMandateDigestSha256Hex(normalized));
  });

  it("rejects tenant-scoped mandates with principal fields", () => {
    const mandate = testAgentMandate("2030-01-02T03:04:05Z");
    const authorization = mandate.authorization as Record<string, unknown>;
    authorization.kind = "tenant";
    expect(() => normalizeAgentMandateV1(mandate)).toThrow(/tenant-scoped mandates/);
  });

  it("accepts adyen_manual_capture settlement rail", () => {
    const mandate = testAgentMandate("2030-01-02T03:04:05Z");
    const settlement = mandate.settlement as Record<string, unknown>;
    settlement.default_rail = "adyen_manual_capture";
    settlement.allowed_rails = ["adyen_manual_capture", "stripe_connect"];

    const normalized = normalizeAgentMandateV1(mandate);
    expect(normalized.settlement.default_rail).toBe("adyen_manual_capture");
    expect(normalized.settlement.allowed_rails).toEqual(["adyen_manual_capture", "stripe_connect"]);
  });

  it("rejects unknown settlement rails", () => {
    const mandate = testAgentMandate("2030-01-02T03:04:05Z");
    const settlement = mandate.settlement as Record<string, unknown>;
    settlement.allowed_rails = ["stripe_connect", "not_a_rail"];

    expect(() => normalizeAgentMandateV1(mandate)).toThrow(/unknown settlement rail/);
  });
});

describe("verifySignedAgentMandateV1", () => {
  it("round-trips sign and verify", () => {
    const seed = ed25519Seed("agent-mandate-sign-roundtrip");
    const now = new Date("2026-05-17T16:00:00.000Z");
    const signed = signAgentMandateV1(seed, testAgentMandate("2026-05-17T18:00:00.000Z"));

    expect(signed.signing_algorithm).toBe("ed25519-sha256-json-v1");
    expect(signed.message_digest_sha256_hex).toHaveLength(64);

    expect(() => verifySignedAgentMandateV1(signed, now)).not.toThrow();
  });

  it("rejects expired mandates", () => {
    const seed = ed25519Seed("agent-mandate-expired");
    const now = new Date("2026-05-17T16:00:00.000Z");
    const signed = signAgentMandateV1(seed, testAgentMandate("2026-05-17T15:59:00.000Z"));

    expect(() => verifySignedAgentMandateV1(signed, now)).toThrow(/expired at/);
  });

  it("rejects tampered mandate bodies", () => {
    const seed = ed25519Seed("agent-mandate-tamper");
    const now = new Date("2026-05-17T16:00:00.000Z");
    const signed = signAgentMandateV1(seed, testAgentMandate("2026-05-17T18:00:00.000Z"));
    signed.allowed_tools = ["travel.cancel"];

    expect(() => verifySignedAgentMandateV1(signed, now)).toThrow(/message digest mismatch/);
  });
});
