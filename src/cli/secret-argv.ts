import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { consumeFlag } from "./globals.js";
import { CliError } from "./types.js";

/**
 * Reject secret-valued CLI flags that leak via shell history / process listings.
 * Prefer env vars or `--*-file` paths mode 0600.
 */
export function rejectSecretArgvFlag(argv: string[], flag: string, alternatives: string): string[] {
  const consumed = consumeFlag(argv, flag);
  if (consumed.present) {
    throw new CliError(
      `${flag} is rejected (secrets must not appear on argv); use ${alternatives}`,
      {
        category: "usage",
        code: "cli.secret.argv_rejected",
        details: { flag },
      },
    );
  }
  return consumed.rest;
}

/** Read a secret from `--flag-file` (trimmed) when present. */
export async function readSecretFileFlag(
  argv: string[],
  fileFlag: string,
  cwd: string,
): Promise<{ value?: string; rest: string[] }> {
  const consumed = consumeFlag(argv, fileFlag);
  if (!consumed.value?.trim()) {
    return { rest: consumed.rest };
  }
  const path = resolve(cwd, consumed.value.trim());
  try {
    const raw = await readFile(path, "utf8");
    const value = raw.trim();
    if (!value) {
      throw new CliError(`${fileFlag} points to an empty file`, {
        category: "usage",
        code: "cli.secret.empty_file",
        details: { flag: fileFlag, path },
      });
    }
    return { value, rest: consumed.rest };
  } catch (err) {
    if (err instanceof CliError) {
      throw err;
    }
    throw new CliError(
      `unable to read ${fileFlag}: ${err instanceof Error ? err.message : String(err)}`,
      {
        category: "usage",
        code: "cli.secret.file_unreadable",
        details: { flag: fileFlag, path },
      },
    );
  }
}

/** Resolve a secret from file flag, else process env (never argv value flags). */
export async function resolveSecretFromFileOrEnv(input: {
  argv: string[];
  cwd: string;
  rejectedFlag: string;
  fileFlag: string;
  envName: string;
  alternatives: string;
}): Promise<{ value?: string; rest: string[] }> {
  const afterReject = rejectSecretArgvFlag(input.argv, input.rejectedFlag, input.alternatives);
  const fromFile = await readSecretFileFlag(afterReject, input.fileFlag, input.cwd);
  if (fromFile.value) {
    return fromFile;
  }
  const fromEnv = process.env[input.envName]?.trim();
  return { value: fromEnv || undefined, rest: fromFile.rest };
}
