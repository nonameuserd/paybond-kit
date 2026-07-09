import { readFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { runCli } from "../../src/cli/router.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import { scaffoldPolicyFromPreset } from "../../src/policy/init.js";
import {
  isKnownPolicyPresetId,
  listPolicyPresetIds,
  readPolicyPresetYaml,
  resolveComposedPresetDocument,
  resolvePolicyPresetPath,
} from "../../src/policy/presets.js";
import {
  getSolutionSmokeDefaults,
  isKnownSolutionId,
  listSolutionIds,
  loadSolutionManifest,
} from "../../src/solutions/catalog.js";

describe("stripe-commerce policy preset", () => {
  it("is registered in known preset and solution catalogs", () => {
    expect(isKnownPolicyPresetId("stripe-commerce")).toBe(true);
    expect(isKnownSolutionId("stripe-commerce")).toBe(true);
    expect(listPolicyPresetIds()).toContain("stripe-commerce");
    expect(listSolutionIds()).toContain("stripe-commerce");
  });

  it("loads flat preset yaml with stripe_charge evidence", async () => {
    const path = resolvePolicyPresetPath("stripe-commerce");
    expect(path).toContain("stripe-commerce.yaml");

    const yaml = readPolicyPresetYaml("stripe-commerce");
    expect(yaml).toContain("payments.charge_customer:");
    expect(yaml).toContain("evidence_preset: stripe_charge");
    expect(yaml).toContain("max_spend_usd: 500");

    const document = resolveComposedPresetDocument("stripe-commerce");
    expect(document.name).toBe("stripe-commerce-agent-v1");
    expect(document.tools["payments.charge_customer"]?.evidence_preset).toBe("stripe_charge");
    expect(document.intent?.budget?.max_spend_usd).toBe(500);

    const policy = await PaybondPolicy.fromDocument(document);
    const report = await policy.validate();
    expect(report.valid).toBe(true);
  });

  it("loads solution manifest with smoke defaults", () => {
    const manifest = loadSolutionManifest("stripe-commerce");
    expect(manifest.id).toBe("stripe-commerce");
    expect(manifest.primary_operation).toBe("payments.charge_customer");
    expect(manifest.completion_preset).toBe("stripe_charge");
    expect(manifest.smoke.evidence_preset).toBe("stripe_charge");

    const smoke = getSolutionSmokeDefaults("stripe-commerce");
    expect(smoke.operation).toBe("payments.charge_customer");
    expect(smoke.requestedSpendCents).toBe(2500);
    expect(smoke.evidencePreset).toBe("stripe_charge");
    expect(smoke.resultBody).toEqual({
      payment_intent_id: "pi_smoke",
      charge_id: "ch_smoke",
      cost_cents: 2500,
      status: "succeeded",
    });
  });

  it("CLI policy init --preset stripe-commerce writes owned policy file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-stripe-commerce-"));
    const out = join(cwd, "paybond.policy.yaml");
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(
      ["--format", "json", "policy", "init", "--preset", "stripe-commerce", "--out", out],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.preset).toBe("stripe-commerce");

    const text = await readFile(out, "utf8");
    expect(text).toContain("payments.charge_customer");
    expect(text).toContain("evidence_preset: stripe_charge");

    const result = await scaffoldPolicyFromPreset({
      out: join(cwd, "regen.policy.yaml"),
      presetId: "stripe-commerce",
      force: false,
    });
    expect(result.preset).toBe("stripe-commerce");
    expect(result.name).toBe("stripe-commerce-agent-v1");
  });
});
