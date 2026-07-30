import { describe, expect, it } from "vitest";

import {
  handleMcpServe,
  mcpServeArgvMatches,
  runMcpServeCommandSync,
} from "../../src/cli/commands/setup.js";
import { createContext } from "../../src/cli/context.js";
import { defaultGlobalOptions } from "../../src/cli/globals.js";
import { CliError } from "../../src/cli/types.js";

describe("mcp serve sync entrypoint", () => {
  it("matches mcp serve after global flags", () => {
    expect(mcpServeArgvMatches(["mcp", "serve"])).toBe(true);
    expect(mcpServeArgvMatches(["--env-file", ".env.local", "mcp", "serve"])).toBe(true);
    expect(mcpServeArgvMatches(["doctor", "--agent"])).toBe(false);
  });

  it("prints help without launching the server", () => {
    const stdout = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = runMcpServeCommandSync(["mcp", "serve", "--help"], {
      stdout,
      stderr: { write: () => true },
    });
    expect(code).toBe(0);
    expect(stdout.chunks.join("")).toContain("paybond mcp serve");
    expect(stdout.chunks.join("")).toContain("--transport");
  });

  // These deliberately stop before actually launching a transport: stdio
  // blocks reading stdin forever and --transport http binds a real OS
  // socket, so only the argument-validation branches that return early are
  // exercised here.

  it("rejects an invalid --transport value", () => {
    const stderr = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = runMcpServeCommandSync(["mcp", "serve", "--transport", "carrier-pigeon"], {
      stdout: { write: () => true },
      stderr,
    });
    expect(code).toBe(2);
    expect(stderr.chunks.join("")).toContain("invalid --transport");
  });

  it("rejects unexpected arguments after --transport", () => {
    const stderr = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = runMcpServeCommandSync(["mcp", "serve", "--transport", "http", "extra"], {
      stdout: { write: () => true },
      stderr,
    });
    expect(code).toBe(2);
    expect(stderr.chunks.join("")).toContain("unexpected arguments");
  });

  it("rejects legacy unexpected arguments", () => {
    const stderr = {
      chunks: [] as string[],
      write(chunk: string): boolean {
        this.chunks.push(chunk);
        return true;
      },
    };
    const code = runMcpServeCommandSync(["mcp", "serve", "extra"], {
      stdout: { write: () => true },
      stderr,
    });
    expect(code).toBe(2);
    expect(stderr.chunks.join("")).toContain("unexpected arguments");
  });

  it("forbids async dispatcher handling", async () => {
    const ctx = createContext(defaultGlobalOptions(), {
      stdout: { write: () => true },
      stderr: { write: () => true },
    });
    await expect(handleMcpServe(ctx, [])).rejects.toBeInstanceOf(CliError);
    await expect(handleMcpServe(ctx, [])).rejects.toMatchObject({
      code: "cli.mcp.serve_async_forbidden",
    });
  });
});
