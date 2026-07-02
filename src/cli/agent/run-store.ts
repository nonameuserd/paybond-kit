import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { writeAtomicFileAsync } from "../automation.js";
import { CliError } from "../types.js";

import type { PersistedProductionEvidence } from "./production-evidence.js";

export type PersistedAgentRunContext = {
  run_id: string;
  tenant_id: string;
  intent_id: string;
  capability_token: string;
  operation: string;
  allowed_tools: string[];
  sandbox: boolean;
  sandbox_lifecycle_status?: string;
  requested_spend_cents?: number;
  completion_preset?: string;
  registry_file?: string;
  default_deny?: boolean;
  policy_digest?: string;
  policy_version?: string;
  policy_loaded_at?: string;
  reload_watch?: boolean;
  reload_poll?: boolean;
  last_reload_at?: string;
  /** Raw policy file content at last successful bind/reload (for CLI re-attach). */
  policy_bind_content?: string;
  /** Production auto-evidence credentials for non-sandbox attach binds. */
  production_evidence?: PersistedProductionEvidence;
  created_at: string;
};

export function agentRunsDir(cwd: string): string {
  return join(cwd, ".paybond", "runs");
}

export function agentRunFilePath(cwd: string, runId: string): string {
  return join(agentRunsDir(cwd), `${runId.trim()}.json`);
}

export async function persistAgentRunContext(
  cwd: string,
  context: PersistedAgentRunContext,
): Promise<string> {
  const path = agentRunFilePath(cwd, context.run_id);
  await mkdir(agentRunsDir(cwd), { recursive: true });
  await writeAtomicFileAsync(path, `${JSON.stringify(context, null, 2)}\n`, 0o600);
  return path;
}

export async function loadAgentRunContext(cwd: string, runId: string): Promise<PersistedAgentRunContext> {
  const path = agentRunFilePath(cwd, runId.trim());
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      throw new CliError(`unknown run_id "${runId}"; run paybond agent run bind first`, {
        category: "validation",
        code: "cli.agent.unknown_run_id",
        exitCode: 1,
        details: { run_id: runId, path },
      });
    }
    throw err;
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CliError(`invalid run context at ${path}`, {
      category: "validation",
      code: "cli.agent.invalid_run_context",
    });
  }
  return parsed as PersistedAgentRunContext;
}
