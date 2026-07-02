import { describe, expect, it } from "vitest";

import {
  McpEvidencePolicyError,
  McpEvidenceValidationGate,
  completionEvidenceValidationOk,
  evidenceValidationGateKey,
  parseMcpEvidencePolicy,
} from "../src/mcp-evidence-policy.js";

describe("mcp evidence policy", () => {
  it("defaults to strict policy", () => {
    expect(parseMcpEvidencePolicy(undefined)).toBe("strict");
  });

  it("records and requires matching validation passes", () => {
    const gate = new McpEvidenceValidationGate("strict");
    const canonicalPayload = {
      http_status: 200,
      vendor_ref_id: "job-123",
      response_digest: "blake3:abc",
    };
    const gateKey = evidenceValidationGateKey({
      presetId: "api_response_ok",
      canonicalPayload,
    });
    gate.recordPass(gateKey);
    expect(() =>
      gate.requirePass({
        presetId: "api_response_ok",
        canonicalPayload,
      }),
    ).not.toThrow();
  });

  it("blocks submit without a prior validation pass", () => {
    const gate = new McpEvidenceValidationGate("strict");
    expect(() =>
      gate.requirePass({
        presetId: "api_response_ok",
        canonicalPayload: {
          http_status: 200,
          vendor_ref_id: "job-123",
          response_digest: "blake3:abc",
        },
      }),
    ).toThrow(McpEvidencePolicyError);
  });

  it("validateAndRecord accepts passing archetype evidence", () => {
    const gate = new McpEvidenceValidationGate("strict");
    const canonicalPayload = {
      http_status: 200,
      vendor_ref_id: "job-123",
      response_digest: "blake3:abc",
    };
    const report = gate.validateAndRecord({
      presetId: "api_response_ok",
      canonicalPayload,
    });
    expect(completionEvidenceValidationOk(report)).toBe(true);
    expect(() =>
      gate.requirePass({
        presetId: "api_response_ok",
        canonicalPayload,
      }),
    ).not.toThrow();
  });
});
