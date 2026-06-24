import { describe, expect, it } from "vitest";

import { runCli } from "../src/cli/router.js";
import { shouldUseColor } from "../src/cli/color.js";
import { defaultGlobalOptions } from "../src/cli/globals.js";

describe("paybond cli ux", () => {
  it("suggests a command for typos", async () => {
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["logn"], { stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/did you mean "login"/);
  });

  it("suggests a global flag for typos before the subcommand", async () => {
    const stderr = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["--formt", "json", "whoami"], { stderr });
    expect(code).toBe(1);
    expect(stderr.chunks.join("")).toMatch(/did you mean --format/);
  });

  it("prints command help via paybond help", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["help", "login"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("Usage: paybond login");
    expect(stdout.chunks.join("")).toContain("Examples:");
  });

  it("prints examples via paybond examples", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["examples", "doctor"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("paybond doctor");
  });

  it("prints bash completion script", async () => {
    const stdout = { chunks: [] as string[], write(chunk: string): boolean { this.chunks.push(chunk); return true; } };
    const code = await runCli(["completion", "bash"], { stdout });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("complete -F _paybond_completion paybond");
  });

  it("disables color for JSON output", () => {
    const globals = defaultGlobalOptions();
    globals.format = "json";
    globals.color = "always";
    expect(shouldUseColor(globals)).toBe(false);
  });

  it("honors NO_COLOR for auto mode", () => {
    const globals = defaultGlobalOptions();
    globals.color = "auto";
    expect(shouldUseColor(globals, false)).toBe(false);
  });
});
