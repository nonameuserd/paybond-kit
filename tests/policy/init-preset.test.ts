import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { runCli } from "../../src/cli/router.js";
import { PaybondPolicy } from "../../src/policy/load.js";
import { scaffoldPolicyFromPreset } from "../../src/policy/init.js";

describe("policy init --preset", () => {
  it("scaffolds travel preset with header comment", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-preset-"));
    const out = join(cwd, "paybond.policy.yaml");
    const result = await scaffoldPolicyFromPreset({ out, presetId: "travel", force: false });
    expect(result.preset).toBe("travel");
    expect(result.name).toBe("travel-agent-v1");

    const text = await readFile(out, "utf8");
    expect(text).toContain("# Reference implementation — edit freely. Regenerate with:");
    expect(text).toContain("# paybond policy init --preset travel --force");
    expect(text).toContain("travel.book_hotel");

    const policy = await PaybondPolicy.load(out);
    const report = await policy.validate();
    expect(report.valid).toBe(true);
  });

  it("CLI policy init --preset travel writes owned policy file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-policy-init-cli-preset-"));
    const out = join(cwd, "paybond.policy.yaml");
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      ["--format", "json", "policy", "init", "--preset", "travel", "--out", out],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.preset).toBe("travel");
    await access(out, constants.F_OK);
  });
});
