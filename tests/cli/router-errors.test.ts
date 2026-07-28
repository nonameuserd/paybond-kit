import { describe, expect, it, vi } from "vitest";

import { runCli } from "../../src/cli/router.js";

function streamCollector() {
  return {
    chunks: [] as string[],
    write(chunk: string): boolean {
      this.chunks.push(chunk);
      return true;
    },
    text(): string {
      return this.chunks.join("");
    },
  };
}

describe("paybond CLI --debug / PAYBOND_CLI_DEBUG diagnostics", () => {
  it("does not print a stack trace by default", async () => {
    const stdout = streamCollector();
    const stderr = streamCollector();
    const code = await runCli(["--format", "json", "definitely-not-a-command"], {
      stdout,
      stderr,
    });
    expect(code).not.toBe(0);
    const payload = JSON.parse(stdout.text());
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.usage.unknown_command");
    expect(stderr.text()).not.toContain("at ");
    expect(stderr.text()).not.toContain("CliError");
  });

  it("prints a stack trace to stderr with --debug while keeping the JSON envelope on stdout", async () => {
    const stdout = streamCollector();
    const stderr = streamCollector();
    const code = await runCli(
      ["--debug", "--format", "json", "definitely-not-a-command"],
      { stdout, stderr },
    );
    expect(code).not.toBe(0);
    const payload = JSON.parse(stdout.text());
    expect(payload.ok).toBe(false);
    const err = stderr.text();
    expect(err).toContain("CliError");
    expect(err).toContain("at ");
  });

  it("honors PAYBOND_CLI_DEBUG=1 for stack-trace diagnostics", async () => {
    vi.stubEnv("PAYBOND_CLI_DEBUG", "1");
    try {
      const stdout = streamCollector();
      const stderr = streamCollector();
      const code = await runCli(["--format", "json", "definitely-not-a-command"], {
        stdout,
        stderr,
      });
      expect(code).not.toBe(0);
      expect(stderr.text()).toContain("CliError");
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it("prints a stack trace for argv parse errors when --debug is set", async () => {
    const stdout = streamCollector();
    const stderr = streamCollector();
    const code = await runCli(["--debug", "--not-a-real-flag", "help"], {
      stdout,
      stderr,
    });
    expect(code).not.toBe(0);
    // Argv parse errors are emitted before globals exist; --debug is honored via argv.
    expect(stderr.text()).toContain("at ");
  });
});
