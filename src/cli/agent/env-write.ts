import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import { quoteEnvValue } from "./env-quote.js";

export type AgentEnvWriteInput = {
  envFile: string;
  cwd: string;
  intentId: string;
  capabilityToken: string;
  runId: string;
};

export async function appendAgentRunEnvVars(input: AgentEnvWriteInput): Promise<string> {
  const envPath = resolve(input.cwd, input.envFile);
  let existing = "";
  try {
    existing = await readFile(envPath, "utf8");
  } catch (err) {
    if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
      throw err;
    }
  }

  const lines = [
    `PAYBOND_INTENT_ID=${quoteEnvValue(input.intentId)}`,
    `PAYBOND_CAPABILITY_TOKEN=${quoteEnvValue(input.capabilityToken)}`,
    `PAYBOND_RUN_ID=${quoteEnvValue(input.runId)}`,
  ];

  const updates = new Map<string, string>();
  for (const line of lines) {
    const key = line.split("=", 1)[0]!;
    updates.set(key, line);
  }

  const output: string[] = [];
  const seen = new Set<string>();
  for (const rawLine of existing.split(/\r?\n/)) {
    const match = /^(\s*(?:export\s+)?([A-Z0-9_]+)\s*=)/.exec(rawLine);
    if (match && updates.has(match[2]!)) {
      output.push(updates.get(match[2]!)!);
      seen.add(match[2]!);
      continue;
    }
    output.push(rawLine);
  }
  for (const [key, line] of updates) {
    if (!seen.has(key)) {
      output.push(line);
    }
  }

  let body = output.join("\n");
  if (body.length > 0 && !body.endsWith("\n")) {
    body += "\n";
  }
  await writeFile(envPath, body, { encoding: "utf8", mode: 0o600 });
  return envPath;
}
