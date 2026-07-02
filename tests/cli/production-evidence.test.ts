import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  productionEvidenceToPersisted,
  resolveProductionEvidenceForReattach,
  resolveProductionEvidenceFromCli,
} from "../../src/cli/agent/production-evidence.js";

const PAYEE_SEED_HEX = "01".repeat(32);
const AGENT_SEED_HEX = "02".repeat(32);

describe("resolveProductionEvidenceFromCli", () => {
  it("resolves credentials from flags", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-prod-evidence-"));
    const credentials = await resolveProductionEvidenceFromCli({
      cwd,
      envFile: ".env.local",
      payeeDid: "did:web:vendor.example",
      payeeSigningSeedHex: PAYEE_SEED_HEX,
      agentRecognitionKeyId: "kid-1",
      agentRecognitionSigningSeedHex: AGENT_SEED_HEX,
    });
    expect(credentials.payeeDid).toBe("did:web:vendor.example");
    expect(credentials.agentRecognitionKeyId).toBe("kid-1");
    expect(credentials.payeeSigningSeed).toHaveLength(32);
    expect(credentials.agentRecognitionSigningSeed).toHaveLength(32);
  });

  it("falls back to APP_* env file values", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-prod-evidence-env-"));
    await writeFile(
      join(cwd, ".env.local"),
      [
        "APP_PAYEE_DID=did:web:vendor.example",
        `APP_PAYEE_SEED_HEX=${PAYEE_SEED_HEX}`,
        "APP_AGENT_RECOGNITION_KEY_ID=kid-1",
        `APP_AGENT_RECOGNITION_SEED_HEX=${AGENT_SEED_HEX}`,
      ].join("\n"),
      "utf8",
    );
    const credentials = await resolveProductionEvidenceFromCli({
      cwd,
      envFile: ".env.local",
    });
    expect(credentials.payeeDid).toBe("did:web:vendor.example");
    expect(credentials.agentRecognitionKeyId).toBe("kid-1");
  });

  it("rejects incomplete production attach credentials", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-prod-evidence-missing-"));
    await expect(
      resolveProductionEvidenceFromCli({
        cwd,
        envFile: ".env.local",
        payeeDid: "did:web:vendor.example",
      }),
    ).rejects.toMatchObject({ code: "cli.agent.production_evidence_incomplete" });
  });
});

describe("production evidence persistence", () => {
  it("persists metadata only", () => {
    const credentials = {
      payeeDid: "did:web:vendor.example",
      payeeSigningSeed: Uint8Array.from({ length: 32 }, (_, i) => i + 1),
      agentRecognitionKeyId: "kid-1",
      agentRecognitionSigningSeed: Uint8Array.from({ length: 32 }, (_, i) => i + 33),
    };
    const persisted = productionEvidenceToPersisted(credentials);
    expect(persisted).toEqual({
      payee_did: "did:web:vendor.example",
      agent_recognition_key_id: "kid-1",
    });
    expect(persisted).not.toHaveProperty("payee_signing_seed_hex");
    expect(persisted).not.toHaveProperty("agent_recognition_signing_seed_hex");
  });

  it("requires fresh signing seeds on re-attach", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-prod-evidence-reattach-"));
    await expect(
      resolveProductionEvidenceForReattach({
        cwd,
        envFile: ".env.local",
        persisted: {
          payee_did: "did:web:vendor.example",
          agent_recognition_key_id: "kid-1",
        },
      }),
    ).rejects.toMatchObject({ code: "cli.agent.production_signing_seed_required" });
  });

  it("merges persisted metadata with freshly supplied seeds", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-prod-evidence-merge-"));
    const restored = await resolveProductionEvidenceForReattach({
      cwd,
      envFile: ".env.local",
      persisted: {
        payee_did: "did:web:vendor.example",
        agent_recognition_key_id: "kid-1",
      },
      payeeSigningSeedHex: PAYEE_SEED_HEX,
      agentRecognitionSigningSeedHex: AGENT_SEED_HEX,
    });
    expect(restored.payeeDid).toBe("did:web:vendor.example");
    expect(restored.agentRecognitionKeyId).toBe("kid-1");
    expect(restored.payeeSigningSeed).toHaveLength(32);
    expect(restored.agentRecognitionSigningSeed).toHaveLength(32);
  });
});
