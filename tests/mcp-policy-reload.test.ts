import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  McpPolicyReloadGate,
  parseMcpPolicyReloadConfig,
  parseMcpPolicyReloadMode,
} from "../src/mcp-policy-reload.js";
import { policyDocumentToDict } from "../src/policy/digest.js";
import { parsePaybondPolicyDocumentV1 } from "../src/policy/schema.js";

function travelDocument(maxSpendCents = 20_000) {
  return parsePaybondPolicyDocumentV1({
    version: 1,
    name: "travel-agent-v1",
    default_deny: true,
    tools: {
      "travel.book_hotel": {
        side_effecting: true,
        max_spend_cents: maxSpendCents,
        evidence_preset: "cost_and_completion",
      },
    },
    intent: { allowed_tools: ["travel.book_hotel"] },
  });
}

describe("mcp policy reload", () => {
  it("parses reload env config", () => {
    expect(parseMcpPolicyReloadMode("watch")).toBe("watch");
    expect(parseMcpPolicyReloadMode(undefined)).toBe("off");
    const config = parseMcpPolicyReloadConfig({
      PAYBOND_POLICY_FILE: "./paybond.policy.yaml",
      PAYBOND_POLICY_RELOAD: "poll",
    });
    expect(config?.reloadMode).toBe("poll");
    expect(config?.policyFile).toContain("paybond.policy.yaml");
  });

  it("assertSpendGate resolves spend from policy registry", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-policy-"));
    const path = join(dir, "paybond.policy.json");
    const document = travelDocument(12_500);
    await writeFile(path, JSON.stringify(policyDocumentToDict(document)), "utf8");

    const gate = await McpPolicyReloadGate.open({
      policyFile: path,
      reloadMode: "off",
    });

    const gated = gate.assertSpendGate({
      operation: "travel.book_hotel",
      allowedTools: ["travel.book_hotel"],
    });
    expect(gated.requestedSpendCents).toBe(12_500);
    expect(gated.policyDigest).toMatch(/^sha256:/);
  });

  it("reload applies stricter cap between tool invocations", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-policy-"));
    const path = join(dir, "paybond.policy.json");
    await writeFile(path, JSON.stringify(policyDocumentToDict(travelDocument(20_000))), "utf8");

    const gate = await McpPolicyReloadGate.open({
      policyFile: path,
      reloadMode: "off",
    });
    gate.beginToolCall();
    gate.endToolCall();

    await writeFile(path, JSON.stringify(policyDocumentToDict(travelDocument(5_000))), "utf8");
    const result = await gate.reloadPolicy({ file: path });
    expect(result.applied).toBe(true);

    const gated = gate.assertSpendGate({
      operation: "travel.book_hotel",
      allowedTools: ["travel.book_hotel"],
    });
    expect(gated.requestedSpendCents).toBe(5_000);
  });

  it("waits for in-flight MCP tool calls before reload swap", async () => {
    const dir = await mkdtemp(join(tmpdir(), "mcp-policy-"));
    const path = join(dir, "paybond.policy.json");
    await writeFile(path, JSON.stringify(policyDocumentToDict(travelDocument(20_000))), "utf8");

    const gate = await McpPolicyReloadGate.open({
      policyFile: path,
      reloadMode: "off",
    });

    gate.beginToolCall();
    await writeFile(path, JSON.stringify(policyDocumentToDict(travelDocument(5_000))), "utf8");
    let reloadDone = false;
    const reloadPromise = gate.reloadPolicy({ file: path }).then((result) => {
      reloadDone = true;
      return result;
    });

    await new Promise((resolve) => setTimeout(resolve, 40));
    expect(reloadDone).toBe(false);

    gate.endToolCall();
    const result = await reloadPromise;
    expect(result.applied).toBe(true);
    expect(
      gate.assertSpendGate({
        operation: "travel.book_hotel",
        allowedTools: ["travel.book_hotel"],
      }).requestedSpendCents,
    ).toBe(5_000);
  });
});
