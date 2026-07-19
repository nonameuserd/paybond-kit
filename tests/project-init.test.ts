import { access, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli/router.js";
import { PaybondPolicy } from "../src/policy/load.js";
import { parseProjectInitArgv, runProjectInit } from "../src/project-init.js";

describe("paybond init wizard", () => {
  it("parses non-interactive flags", () => {
    const parsed = parseProjectInitArgv([
      "--solution",
      "travel",
      "--max-spend-usd",
      "500",
      "--framework",
      "langgraph",
      "--non-interactive",
      "--force",
    ]);
    expect(parsed).not.toBe("help");
    if (parsed === "help") {
      throw new Error("expected parsed options");
    }
    expect(parsed.solution).toBe("travel");
    expect(parsed.maxSpendUsd).toBe(500);
    expect(parsed.framework).toBe("langgraph");
    expect(parsed.nonInteractive).toBe(true);
    expect(parsed.force).toBe(true);
  });

  it("scaffolds travel + langgraph files non-interactively", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-"));
    const lines: string[] = [];

    const result = await runProjectInit({
      cwd,
      solution: "travel",
      maxSpendUsd: 500,
      framework: "langgraph",
      language: "typescript",
      nonInteractive: true,
      force: true,
      writeStdout(line) {
        lines.push(line);
      },
    });

    expect(result.solution).toBe("travel");
    expect(result.preset_id).toBe("travel");
    expect(result.max_spend_usd).toBe(500);
    expect(result.framework).toBe("langgraph");
    expect(result.files).toContain("paybond.policy.yaml");
    expect(result.files).toContain("paybond.config.ts");
    expect(result.files).toContain("paybond.instrument.ts");
    expect(result.files).toContain(".env.example");
    expect(result.files).toContain("package.json");
    expect(lines.some((line) => line.startsWith("Created "))).toBe(true);
    expect(lines.join("\n")).toContain("npm run smoke");

    const policyText = await readFile(join(cwd, "paybond.policy.yaml"), "utf8");
    expect(policyText).toContain("max_spend_usd: 500");
    const policy = await PaybondPolicy.load(join(cwd, "paybond.policy.yaml"));
    const report = await policy.validate();
    expect(report.valid).toBe(true);

    const instrument = await readFile(join(cwd, "paybond.instrument.ts"), "utf8");
    expect(instrument).toContain("instrumentLangGraph");
    expect(instrument).toContain("travel.book_hotel");

    const packageJson = JSON.parse(await readFile(join(cwd, "package.json"), "utf8")) as {
      scripts: { smoke: string };
    };
    expect(packageJson.scripts.smoke).toContain("--policy-file paybond.policy.yaml");
  });

  it("defaults mcp-server solution to mcp framework", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-mcp-"));
    const result = await runProjectInit({
      cwd,
      solution: "mcp-server",
      nonInteractive: true,
      force: true,
    });
    expect(result.framework).toBe("mcp");
    const instrument = await readFile(join(cwd, "paybond.instrument.ts"), "utf8");
    expect(instrument).toContain("instrumentMCP");
  });

  it("CLI init --non-interactive writes scaffold files", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-cli-"));
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(
      [
        "--format",
        "json",
        "init",
        "--solution",
        "shopping",
        "--max-spend-usd",
        "150",
        "--framework",
        "openai",
        "--non-interactive",
        "--force",
      ],
      { cwd, stdout },
    );
    expect(code).toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.solution).toBe("shopping");
    expect(payload.data.preset_id).toBe("shopping");
    await access(join(cwd, "paybond.policy.yaml"), constants.F_OK);
    await access(join(cwd, "paybond.instrument.ts"), constants.F_OK);
  });

  it("refuses to overwrite without --force", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-force-"));
    await runProjectInit({
      cwd,
      solution: "travel",
      nonInteractive: true,
      force: false,
    });
    await expect(
      runProjectInit({
        cwd,
        solution: "travel",
        nonInteractive: true,
        force: false,
      }),
    ).rejects.toThrow("already exists");
  });

  it("overwrites an existing scaffold with --force", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-overwrite-"));
    await runProjectInit({
      cwd,
      solution: "travel",
      nonInteractive: true,
      force: false,
    });

    await runProjectInit({
      cwd,
      solution: "saas",
      maxSpendUsd: 100,
      nonInteractive: true,
      force: true,
    });

    const policyText = await readFile(join(cwd, "paybond.policy.yaml"), "utf8");
    expect(policyText).toContain("name: saas");
    expect(policyText).toContain("max_spend_usd: 100");
  });

  it("confirms policy overwrite in the interactive wizard", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-project-init-confirm-"));
    const policyFile = join(cwd, "paybond.policy.yaml");
    await writeFile(policyFile, "name: existing\n", "utf8");
    const prompts: string[] = [];

    await runProjectInit({
      cwd,
      solution: "saas",
      maxSpendUsd: 100,
      framework: "generic",
      language: "typescript",
      prompt: async (question: string): Promise<string> => {
        prompts.push(question);
        return "yes";
      },
    });

    expect(prompts).toEqual([`${policyFile} already exists. Overwrite it? [y/N] `]);
    await expect(readFile(policyFile, "utf8")).resolves.toContain("name: saas");
  });
});
