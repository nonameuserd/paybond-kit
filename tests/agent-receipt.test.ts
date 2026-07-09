import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  actionReceiptId,
  attachOperatorAttestationV1,
  configHashSha256Hex,
  valueDigestSha256Hex,
  verifyAgentReceiptV1,
  verifyAgentReceiptV1FromJSON,
  type AgentReceiptV1,
} from "../src/agent-receipt.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CONFORMANCE_DIR = join(MODULE_DIR, "../../agent-receipt/conformance");

describe("agent receipt verify", () => {
  it("verifies the signed conformance vector", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const receipt = JSON.parse(raw) as AgentReceiptV1;
    const verified = await verifyAgentReceiptV1(receipt);
    expect(verified.receipt_id).toBe(
      "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484",
    );
  });

  it("verifies the signed intent_terminal conformance vector", async () => {
    const raw = readFileSync(
      join(CONFORMANCE_DIR, "signed-intent-terminal-receipt-v1.json"),
      "utf8",
    );
    const receipt = JSON.parse(raw) as AgentReceiptV1;
    const verified = await verifyAgentReceiptV1(receipt);
    expect(verified.receipt_id).toBe("660e8400-e29b-41d4-a716-446655440001");
    expect(verified.scope).toBe("intent_terminal");
    expect(verified.execution).toBeUndefined();
  });

  it("derives action receipt_id deterministically", () => {
    expect(
      actionReceiptId("550e8400-e29b-41d4-a716-446655440000", "call_test_action_001"),
    ).toBe("0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484");
  });

  it("matches conformance JCS hash vectors", () => {
    const vectors = JSON.parse(readFileSync(join(CONFORMANCE_DIR, "jcs-hash-vectors.json"), "utf8")) as {
      vectors: Array<{ name: string; value?: unknown; jcs_sha256_hex?: string }>;
    };
    const mpp = vectors.vectors.find((vector) => vector.name === "mpp_sorted_object");
    expect(mpp?.jcs_sha256_hex).toBeTruthy();
    expect(valueDigestSha256Hex(mpp?.value)).toBe(mpp?.jcs_sha256_hex);

    const config = vectors.vectors.find((vector) => vector.name === "config_hash_input");
    const configValue = config?.value as {
      system_prompt: string;
      tools_manifest: unknown;
      policy_snapshot_id: string;
    };
    expect(
      configHashSha256Hex({
        system_prompt: configValue.system_prompt,
        tools_manifest: configValue.tools_manifest,
        policy_snapshot_id: configValue.policy_snapshot_id,
      }),
    ).toBe(config?.jcs_sha256_hex);
  });

  it("rejects tampered receipts", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const receipt = JSON.parse(raw) as AgentReceiptV1;
    receipt.outcome.harbor_state = "released";
    await expect(verifyAgentReceiptV1(receipt)).rejects.toThrow(/message digest mismatch/);
  });

  it("rejects unknown top-level keys via raw JSON verify", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const receipt = JSON.parse(raw) as Record<string, unknown>;
    receipt.extra_field = "leak";
    await expect(verifyAgentReceiptV1FromJSON(receipt)).rejects.toThrow(/schema validation failed/);
  });

  it("rejects forbidden fields anywhere in raw JSON verify", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const receipt = JSON.parse(raw) as Record<string, unknown>;
    const authorization = receipt.authorization as Record<string, unknown>;
    authorization.user_prompt = "secret prompt";
    await expect(verifyAgentReceiptV1FromJSON(receipt)).rejects.toThrow(/forbidden field/);
  });

  it("verifies signed conformance vector from raw JSON", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const verified = await verifyAgentReceiptV1FromJSON(raw);
    expect(verified.receipt_id).toBe(
      "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484",
    );
  });

  it("rejects receipts signed by keys outside expectedSigningPublicKeys", async () => {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    const receipt = JSON.parse(raw) as AgentReceiptV1;
    await expect(
      verifyAgentReceiptV1(receipt, {
        expectedSigningPublicKeys: ["00".repeat(32)],
      }),
    ).rejects.toThrow(/trusted key set/);
  });

  const OPERATOR_SEED_HEX = "11".repeat(32);

  function loadConformanceReceipt(): AgentReceiptV1 {
    const raw = readFileSync(join(CONFORMANCE_DIR, "signed-action-receipt-v1.json"), "utf8");
    return JSON.parse(raw) as AgentReceiptV1;
  }

  it("attaches and verifies an operator attestation bound to agent.operator_did", async () => {
    const receipt = loadConformanceReceipt();
    const attested = await attachOperatorAttestationV1(
      receipt,
      OPERATOR_SEED_HEX,
      receipt.authorization.agent.operator_did,
    );
    expect(attested.operator_attestation).toBeTruthy();
    const verified = await verifyAgentReceiptV1(attested);
    expect(verified.operator_attestation?.operator_did).toBe(
      receipt.authorization.agent.operator_did,
    );
  });

  it("attach rejects an operator_did that does not match agent.operator_did", async () => {
    const receipt = loadConformanceReceipt();
    await expect(
      attachOperatorAttestationV1(receipt, OPERATOR_SEED_HEX, "did:web:operator.other"),
    ).rejects.toThrow(/operator_did must match authorization.agent.operator_did/);
  });

  it("verify rejects an operator attestation whose operator_did was swapped", async () => {
    const receipt = loadConformanceReceipt();
    const attested = await attachOperatorAttestationV1(
      receipt,
      OPERATOR_SEED_HEX,
      receipt.authorization.agent.operator_did,
    );
    attested.operator_attestation!.operator_did = "did:web:operator.other";
    await expect(verifyAgentReceiptV1(attested)).rejects.toThrow(
      /operator_attestation.operator_did must match authorization.agent.operator_did/,
    );
  });

  it("enforces operator registry when verifyOperatorAgainstRegistry is set", async () => {
    const receipt = loadConformanceReceipt();
    const attested = await attachOperatorAttestationV1(
      receipt,
      OPERATOR_SEED_HEX,
      receipt.authorization.agent.operator_did,
    );
    const operatorPubHex = attested.operator_attestation!.signing_public_key_ed25519_hex;

    await expect(
      verifyAgentReceiptV1(attested, {
        verifyOperatorAgainstRegistry: true,
        trustedOperatorPublicKeys: [operatorPubHex],
      }),
    ).resolves.toBeTruthy();

    await expect(
      verifyAgentReceiptV1(attested, {
        verifyOperatorAgainstRegistry: true,
        trustedOperatorPublicKeys: ["00".repeat(32)],
      }),
    ).rejects.toThrow(/operator registry/);
  });
});
