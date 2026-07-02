import { describe, expect, it } from "vitest";

import { createPaybondToolRegistry } from "../../src/agent/registry.js";
import { createPolicySnapshot } from "../../src/policy/snapshot.js";
import { parsePaybondPolicyDocumentV1 } from "../../src/policy/schema.js";

describe("createPolicySnapshot", () => {
  it("builds digest, version, and registry from a policy document", () => {
    const document = parsePaybondPolicyDocumentV1({
      version: 1,
      name: "travel-agent-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          evidence_preset: "cost_and_completion",
        },
      },
    });
    const registry = createPaybondToolRegistry({
      sideEffecting: {
        "travel.book_hotel": { evidencePreset: "cost_and_completion" },
      },
    });

    const snapshot = createPolicySnapshot({
      document,
      registry,
      source: "file",
      loadedAt: "2030-01-01T00:00:00.000Z",
    });

    expect(snapshot.source).toBe("file");
    expect(snapshot.loadedAt).toBe("2030-01-01T00:00:00.000Z");
    expect(snapshot.digest).toMatch(/^sha256:/);
    expect(snapshot.version).toBe(`travel-agent-v1@${snapshot.digest.slice(7, 15)}`);
    expect(snapshot.registry).toBe(registry);
  });
});
