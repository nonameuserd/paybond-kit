import { access, readFile } from "node:fs/promises";
import { constants } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli/router.js";
import {
  copyTemplateToDirectory,
  listTemplateEntries,
  normalizeTemplateId,
} from "../src/template-init.js";

describe("paybond init --template", () => {
  it("lists bundled starter templates", async () => {
    const entries = await listTemplateEntries();
    expect(entries.length).toBeGreaterThanOrEqual(9);
    expect(entries.some((entry) => entry.id === "travel-agent")).toBe(true);
    expect(entries.some((entry) => entry.id === "mastra-travel-agent")).toBe(true);
  });

  it("normalizes repo slugs to template ids", () => {
    expect(normalizeTemplateId("paybond-travel-agent")).toBe("travel-agent");
    expect(normalizeTemplateId("paybond-mastra-travel-agent")).toBe("mastra-travel-agent");
    expect(normalizeTemplateId("openai-shopping-agent")).toBe("openai-shopping-agent");
  });

  it("copies travel-agent template into an empty directory", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-init-"));
    const lines: string[] = [];

    const result = await copyTemplateToDirectory({
      cwd,
      templateId: "travel-agent",
      writeStdout(line) {
        lines.push(line);
      },
    });

    expect(result.template_id).toBe("travel-agent");
    expect(result.repo).toBe("paybond-travel-agent");
    expect(result.preset).toBe("travel");
    expect(result.smoke_command).toContain("--policy-file paybond.policy.yaml");

    await access(join(cwd, "package.json"), constants.F_OK);
    await access(join(cwd, "paybond.policy.yaml"), constants.F_OK);
    await access(join(cwd, "src/index.ts"), constants.F_OK);

    const packageJson = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
      scripts: { smoke: string };
    };
    expect(packageJson.dependencies["@paybond/kit"]).toMatch(/^\^/);
    expect(packageJson.scripts.smoke).toContain("--policy-file paybond.policy.yaml");
    expect(packageJson.scripts.smoke).toContain("travel.book_hotel");
    expect(lines.join("\n")).toContain("npm run smoke");
  });

  it("validates --framework against template", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-framework-"));
    await expect(
      copyTemplateToDirectory({
        cwd,
        templateId: "travel-agent",
        framework: "openai-agents",
      }),
    ).rejects.toThrow("does not match");
  });

  it("accepts matching --framework", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-framework-ok-"));
    const result = await copyTemplateToDirectory({
      cwd,
      templateId: "travel-agent",
      framework: "langgraph",
    });
    expect(result.template_id).toBe("travel-agent");
  });

  it("copies mastra-travel-agent template into an empty directory", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-mastra-"));
    const result = await copyTemplateToDirectory({
      cwd,
      templateId: "mastra-travel-agent",
      framework: "mastra",
    });

    expect(result.template_id).toBe("mastra-travel-agent");
    expect(result.repo).toBe("paybond-mastra-travel-agent");
    expect(result.framework).toBe("mastra");

    const indexSource = await readFile(join(cwd, "src/index.ts"), "utf8");
    expect(indexSource).toContain("runMastraSandboxDemo");
    expect(indexSource).toContain("@paybond/kit/mastra");

    const packageJson = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      dependencies: Record<string, string>;
    };
    expect(packageJson.dependencies["@mastra/core"]).toMatch(/^\^/);
  });

  it("copies stripe-agent-demo template into an empty directory", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-stripe-"));
    const result = await copyTemplateToDirectory({
      cwd,
      templateId: "stripe-agent-demo",
    });

    expect(result.template_id).toBe("stripe-agent-demo");
    expect(result.repo).toBe("paybond-stripe-agent-demo");
    expect(result.preset).toBe("stripe-commerce");
    expect(result.smoke_command).toContain("payments.charge_customer");
    expect(result.smoke_command).toContain("stripe_charge");

    await access(join(cwd, "paybond.policy.yaml"), constants.F_OK);
    await access(join(cwd, "src/charge-customer.ts"), constants.F_OK);

    const indexSource = await readFile(join(cwd, "src/index.ts"), "utf8");
    expect(indexSource).toContain("mapChargeEvidence");

    const packageJson = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      scripts: { smoke: string };
    };
    expect(packageJson.scripts.smoke).toContain("payments.charge_customer");
  });

  it("CLI init --template writes scaffold files", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-template-cli-"));
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = await runCli(
      ["--format", "json", "init", "--template", "vercel-shopping-agent", "--force"],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.template_id).toBe("vercel-shopping-agent");
    expect(payload.data.preset).toBe("shopping");
    await access(join(cwd, "paybond.policy.yaml"), constants.F_OK);
    await access(join(cwd, "src/index.ts"), constants.F_OK);
  });
});
