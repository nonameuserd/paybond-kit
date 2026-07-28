import { isAbsolute, relative, resolve, sep } from "node:path";

import { CliError } from "../types.js";

/** Strict run-id slug: no path separators, no `..`, bounded length. */
const AGENT_RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Validate a CLI/API agent run id (UUID or strict slug).
 * Rejects path traversal payloads such as `../../package`.
 */
export function assertValidAgentRunId(runId: string): string {
  const trimmed = runId.trim();
  if (!trimmed || !AGENT_RUN_ID_RE.test(trimmed) || trimmed === "." || trimmed === "..") {
    throw new CliError(
      `invalid run_id ${JSON.stringify(runId)}; expected a UUID or slug matching [A-Za-z0-9][A-Za-z0-9._-]{0,127}`,
      {
        category: "validation",
        code: "cli.agent.invalid_run_id",
        details: { run_id: runId },
      },
    );
  }
  return trimmed;
}

/** Ensure `candidate` resolves strictly beneath `rootDir`. */
export function assertPathInsideDir(rootDir: string, candidate: string): string {
  const root = resolve(rootDir);
  const resolved = resolve(candidate);
  const rel = relative(root, resolved);
  if (rel === "" || rel.startsWith(`..${sep}`) || rel === ".." || isAbsolute(rel)) {
    throw new CliError(`run path escapes runs directory: ${candidate}`, {
      category: "validation",
      code: "cli.agent.run_path_escape",
      details: { root: rootDir, path: candidate },
    });
  }
  return resolved;
}
