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
