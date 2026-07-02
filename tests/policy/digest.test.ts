import { describe, expect, it } from "vitest";

import { canonicalPolicyDocumentDigest, policyVersionLabel } from "../../src/policy/digest.js";
import { parsePaybondPolicyDocumentV1 } from "../../src/policy/schema.js";

const TRAVEL_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: 20000,
      evidence_preset: "cost_and_completion",
    },
  },
} as const;

describe("canonicalPolicyDocumentDigest", () => {
  it("returns a stable sha256 digest for the same document", () => {
    const document = parsePaybondPolicyDocumentV1(TRAVEL_POLICY);
    const first = canonicalPolicyDocumentDigest(document);
    const second = canonicalPolicyDocumentDigest(document);
    expect(first).toBe(second);
    expect(first).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("policyVersionLabel", () => {
  it("formats name and digest short", () => {
    const digest = "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    expect(policyVersionLabel("travel-agent-v1", digest)).toBe("travel-agent-v1@abcdef01");
  });
});
