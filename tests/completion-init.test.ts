import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { getCompletionPreset, loadCompletionCatalog } from "../src/completion-catalog.js";
import { runCompletionInit } from "../src/completion-init.js";

describe("completion preset catalog", () => {
  it("loads the shared catalog with api_response_ok archetype", () => {
    const catalog = loadCompletionCatalog();
    expect(catalog.version).toBe(1);
    const preset = getCompletionPreset("api_response_ok");
    expect(preset.harbor_template_id).toBe("api_response_v1");
    expect(preset.evidence_schema.required).toEqual(["http_status", "vendor_ref_id", "response_digest"]);
  });
});

describe("paybond init completion", () => {
  const originalExitCode = process.exitCode;

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = originalExitCode;
  });

  it("scaffolds api_response_ok with aligned schema and sample evidence", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-completion-init-"));
    const out = join(cwd, "paybond-completion-api-response-ok.ts");
    const preset = getCompletionPreset("api_response_ok");
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(runCompletionInit(["--preset", "api_response_ok", "--out", out])).resolves.toBe(0);

    expect(stdout).toHaveBeenCalledWith(`Created Paybond completion integration: ${out}\n`);
    const body = await readFile(out, "utf8");
    for (const fragment of [
      'export const COMPLETION_PRESET_ID = "api_response_ok"',
      'export const HARBOR_TEMPLATE_ID = "api_response_v1"',
      "export function buildCompletionEvidence",
      "http_status: number",
      "vendor_ref_id: string",
      "response_digest: string",
      JSON.stringify(preset.sample_evidence.http_status),
      "export const policyBindingStub",
      "completionPreset:",
      "paybond policy preview",
    ]) {
      expect(body).toContain(fragment);
    }
  });

  it("refuses to overwrite without --force", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-completion-init-"));
    const out = join(cwd, "paybond-completion.ts");
    await writeFile(out, "existing", "utf8");

    await expect(runCompletionInit(["--preset", "api_response_ok", "--out", out])).resolves.toBe(1);
    expect(await readFile(out, "utf8")).toBe("existing");
  });
});
