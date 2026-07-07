import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  actionReceiptId,
  configHashSha256Hex,
  valueDigestSha256Hex,
  verifyAgentReceiptV1,
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
});
