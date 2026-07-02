import { describe, expect, it } from "vitest";

import { redactSensitiveFields } from "../../src/cli/redact.js";

describe("redactSensitiveFields", () => {
  it("masks capability tokens", () => {
    expect(redactSensitiveFields({ capability_token: "secret-token", intent_id: "intent-1" })).toEqual({
      capability_token: "[redacted]",
      intent_id: "intent-1",
    });
  });

  it("masks signing seed fields", () => {
    const seedBytes = new Uint8Array(32).fill(7);
    expect(
      redactSensitiveFields({
        payee_signing_seed: "a".repeat(64),
        payee_signing_seed_hex: "b".repeat(64),
        agent_recognition_signing_seed: seedBytes,
        agent_recognition_signing_seed_hex: "c".repeat(64),
        principal_signing_seed: seedBytes,
        intent_id: "intent-1",
      }),
    ).toEqual({
      payee_signing_seed: "[redacted]",
      payee_signing_seed_hex: "[redacted]",
      agent_recognition_signing_seed: "[redacted]",
      agent_recognition_signing_seed_hex: "[redacted]",
      principal_signing_seed: "[redacted]",
      intent_id: "intent-1",
    });
  });

  it("masks nested signing seed fields", () => {
    expect(
      redactSensitiveFields({
        production_evidence: {
          payee_signing_seed_hex: "d".repeat(64),
          payee_did: "did:example:payee",
        },
      }),
    ).toEqual({
      production_evidence: {
        payee_signing_seed_hex: "[redacted]",
        payee_did: "did:example:payee",
      },
    });
  });
});
