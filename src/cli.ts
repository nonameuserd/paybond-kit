#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { runCli } from "./cli/router.js";

declare const process: {
  argv: string[];
  exitCode?: number;
  stderr: { write(chunk: string): boolean };
};

async function invokedFromCLI(): Promise<boolean> {
  const scriptPath = process.argv[1];
  if (!scriptPath) {
    return false;
  }

  async function realFileURL(filePath: string): Promise<string> {
    let resolved = path.resolve(filePath);
    try {
      resolved = await fs.realpath(resolved);
    } catch {
      // keep absolute path
    }
    const href = pathToFileURL(resolved).href;
    return href.startsWith("file:///var/") ? href.replace("file:///var/", "file:///private/var/") : href;
  }

  return (await realFileURL(scriptPath)) === (await realFileURL(fileURLToPath(import.meta.url)));
}

invokedFromCLI().then((invoked) => {
  if (!invoked) {
    return;
  }
  runCli(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  }, (err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}, (err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});

export { runCli } from "./cli/router.js";
