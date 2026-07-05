import { createRequire } from "node:module";

type MastraToolsModule = typeof import("@mastra/core/tools");

let cachedMastraTools: MastraToolsModule | undefined;

/**
 * Lazily resolve the optional `@mastra/core` peer dependency.
 *
 * Importing `@paybond/kit/mastra` must not require Mastra installed — the peer
 * is only needed when adapter functions or the sandbox demo actually run.
 */
export function loadMastraTools(): MastraToolsModule {
  if (cachedMastraTools === undefined) {
    try {
      const require = createRequire(import.meta.url);
      cachedMastraTools = require("@mastra/core/tools") as MastraToolsModule;
    } catch (err) {
      throw new Error(
        'The Mastra integration requires the optional peer dependency "@mastra/core"; install it with: npm install @mastra/core',
        { cause: err },
      );
    }
  }
  return cachedMastraTools;
}

/** Re-export {@link loadMastraTools} as `createTool` for sandbox demos. */
export function loadMastraCreateTool(): MastraToolsModule["createTool"] {
  return loadMastraTools().createTool;
}
