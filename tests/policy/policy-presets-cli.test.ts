import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { runCli } from "../../src/cli/router.js";
import { parseGuardrailSpecs } from "../../src/policy/guardrail-spec.js";
import { renderPolicyDocumentYaml } from "../../src/policy/render-yaml.js";
import { resolveComposedPresetDocument } from "../../src/policy/presets.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import { scaffoldComposedPolicy, scaffoldPolicyFromPreset } from "../../src/policy/init.js";
import { listPolicyPresetsCatalog } from "../../src/policy/catalog.js";

describe("policy guardrail specs", () => {
  it("parses read-only and max-spend guardrails", () => {
    const layers = parseGuardrailSpecs("read-only,max-spend:500");
    expect(layers).toHaveLength(2);
    expect(layers[1]?.caps?.budgetMaxSpendUsd).toBe(500);
    expect(layers[1]?.caps?.sideEffectingMaxSpendCents).toBe(50_000);
  });
});

describe("policy presets catalog", () => {
  it("lists domains, guardrails, solutions, and presets", () => {
    const catalog = listPolicyPresetsCatalog();
    expect(catalog.domains.map((entry) => entry.id)).toEqual(["travel", "shopping", "saas", "aws"]);
    expect(catalog.solutions.map((entry) => entry.id)).toEqual([
      "travel",
      "shopping",
      "saas",
      "aws",
      "stripe-commerce",
    ]);
    expect(catalog.presets.some((entry) => entry.id === "read-only")).toBe(true);
    expect(catalog.guardrails.some((entry) => entry.id === "max-spend:<usd>")).toBe(true);
  });
});

describe("policy init compose flags", () => {
  it("scaffolds travel preset with max spend override", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-max-spend-"));
    const out = join(cwd, "paybond.policy.yaml");
    const result = await scaffoldPolicyFromPreset({
      out,
      presetId: "travel",
      maxSpendUsd: 500,
      force: false,
    });
    expect(result.max_spend_usd).toBe(500);
    const text = await readFile(out, "utf8");
    expect(text).toContain("max_spend_usd: 500");
    expect(text).toContain("max_spend_cents: 50000");
    const policy = await PaybondPolicy.load(out);
    expect(policy.document.intent?.budget?.max_spend_usd).toBe(500);
  });

  it("scaffolds composed domain + guardrails policy", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-compose-"));
    const out = join(cwd, "paybond.policy.yaml");
    const result = await scaffoldComposedPolicy({
      out,
      domainId: "travel",
      guardrails: "read-only,max-spend:500",
      force: false,
    });
    expect(result.domain).toBe("travel");
    const policy = await PaybondPolicy.load(out);
    expect(Object.keys(policy.document.tools)).toEqual(["search.web"]);
    expect(policy.document.intent?.budget?.max_spend_usd).toBe(500);
  });
});

describe("policy presets CLI", () => {
  it("policy presets list returns catalog", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--format", "json", "policy", "presets", "list"], { cwd: process.cwd(), stdout });
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.domains).toHaveLength(4);
    expect(payload.data.solutions).toHaveLength(5);
  });

  it("policy presets show travel prints composed yaml", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["policy", "presets", "show", "travel"], { cwd: process.cwd(), stdout });
    expect(code).toBe(0);
    const text = stdout.chunks.join("");
    expect(text).toContain("travel.book_hotel");
    expect(text).toContain("max_spend_usd: 200");
  });

  it("policy init --domain travel --guardrails writes owned file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-cli-compose-"));
    const out = join(cwd, "paybond.policy.yaml");
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "policy",
        "init",
        "--domain",
        "travel",
        "--guardrails",
        "default-deny,max-spend:100",
        "--out",
        out,
      ],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    await access(out, constants.F_OK);
    const policy = await PaybondPolicy.load(out);
    expect(policy.document.default_deny).toBe(true);
    expect(policy.document.intent?.budget?.max_spend_usd).toBe(100);
  });
});

describe("renderPolicyDocumentYaml", () => {
  it("round-trips composed travel preset structure", () => {
    const yaml = renderPolicyDocumentYaml(resolveComposedPresetDocument("travel"));
    expect(yaml).toContain("name: travel-agent-v1");
    expect(yaml).toContain("travel.book_hotel:");
    expect(yaml).toContain("search.web:");
  });
});
