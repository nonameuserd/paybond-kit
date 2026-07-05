import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import type { PaybondRunProductionEvidenceCredentials } from "../../agent/types.js";
import { readEnvFileValue } from "../credentials.js";
import { CliError } from "../types.js";

export type PersistedProductionEvidence = {
  payee_did: string;
  agent_recognition_key_id: string;
};

declare const process: { env: Record<string, string | undefined> };

function resolveEnvPath(cwd: string, envFile: string): string {
  return resolve(cwd, envFile);
}

async function readConfiguredEnvValue(
  cwd: string,
  envFile: string,
  key: string,
): Promise<string | undefined> {
  const fromProcess = process.env[key]?.trim();
  if (fromProcess) {
    return fromProcess;
  }
  try {
    const body = await readFile(resolveEnvPath(cwd, envFile), "utf8");
    return readEnvFileValue(body, key);
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return undefined;
    }
    throw err;
  }
}

function parseSeed32Hex(raw: string, field: string): Uint8Array {
  const hex = raw.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new CliError(`${field} must be a 32-byte Ed25519 seed (64 hex characters)`, {
      category: "usage",
      code: "cli.agent.invalid_signing_seed",
      details: { field },
    });
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Resolve production auto-evidence credentials from CLI flags and APP_* env fallbacks. */
export async function resolveProductionEvidenceFromCli(input: {
  cwd: string;
  envFile: string;
  payeeDid?: string;
  payeeSigningSeedHex?: string;
  agentRecognitionKeyId?: string;
  agentRecognitionSigningSeedHex?: string;
}): Promise<PaybondRunProductionEvidenceCredentials> {
  const payeeDid =
    input.payeeDid?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_PAYEE_DID"));
  const payeeSigningSeedHex =
    input.payeeSigningSeedHex?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_PAYEE_SEED_HEX"));
  const agentRecognitionKeyId =
    input.agentRecognitionKeyId?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_AGENT_RECOGNITION_KEY_ID"));
  const agentRecognitionSigningSeedHex =
    input.agentRecognitionSigningSeedHex?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_AGENT_RECOGNITION_SEED_HEX"));

  if (!payeeDid) {
    throw new CliError(
      "production attach requires --payee-did or APP_PAYEE_DID",
      { category: "usage", code: "cli.agent.production_evidence_incomplete" },
    );
  }
  if (!payeeSigningSeedHex) {
    throw new CliError(
      "production attach requires --payee-signing-seed-hex or APP_PAYEE_SEED_HEX",
      { category: "usage", code: "cli.agent.production_evidence_incomplete" },
    );
  }
  if (!agentRecognitionKeyId) {
    throw new CliError(
      "production attach requires --agent-recognition-key-id or APP_AGENT_RECOGNITION_KEY_ID",
      { category: "usage", code: "cli.agent.production_evidence_incomplete" },
    );
  }
  if (!agentRecognitionSigningSeedHex) {
    throw new CliError(
      "production attach requires --agent-recognition-signing-seed-hex or APP_AGENT_RECOGNITION_SEED_HEX",
      { category: "usage", code: "cli.agent.production_evidence_incomplete" },
    );
  }

  return {
    payeeDid,
    payeeSigningSeed: parseSeed32Hex(payeeSigningSeedHex, "--payee-signing-seed-hex"),
    agentRecognitionKeyId,
    agentRecognitionSigningSeed: parseSeed32Hex(
      agentRecognitionSigningSeedHex,
      "--agent-recognition-signing-seed-hex",
    ),
  };
}

export type AgentRecognitionCredentials = {
  agentRecognitionKeyId: string;
  agentRecognitionSigningSeed: Uint8Array;
};

/** Resolve agent recognition signing credentials from CLI flags and APP_* env fallbacks. */
export async function resolveAgentRecognitionFromCli(input: {
  cwd: string;
  envFile: string;
  agentRecognitionKeyId?: string;
  agentRecognitionSigningSeedHex?: string;
}): Promise<AgentRecognitionCredentials> {
  const agentRecognitionKeyId =
    input.agentRecognitionKeyId?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_AGENT_RECOGNITION_KEY_ID"));
  const agentRecognitionSigningSeedHex =
    input.agentRecognitionSigningSeedHex?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_AGENT_RECOGNITION_SEED_HEX"));

  if (!agentRecognitionKeyId) {
    throw new CliError(
      "Harbor intent mutation requires --agent-recognition-key-id or APP_AGENT_RECOGNITION_KEY_ID",
      { category: "usage", code: "cli.agent.recognition_incomplete" },
    );
  }
  if (!agentRecognitionSigningSeedHex) {
    throw new CliError(
      "Harbor intent mutation requires --agent-recognition-signing-seed-hex or APP_AGENT_RECOGNITION_SEED_HEX",
      { category: "usage", code: "cli.agent.recognition_incomplete" },
    );
  }

  return {
    agentRecognitionKeyId,
    agentRecognitionSigningSeed: parseSeed32Hex(
      agentRecognitionSigningSeedHex,
      "--agent-recognition-signing-seed-hex",
    ),
  };
}

export function productionEvidenceToPersisted(
  credentials: PaybondRunProductionEvidenceCredentials,
): PersistedProductionEvidence {
  return {
    payee_did: credentials.payeeDid,
    agent_recognition_key_id: credentials.agentRecognitionKeyId,
  };
}

/** Re-supply signing seeds at tool execute (or other re-attach) time; metadata comes from the run store. */
export async function resolveProductionEvidenceForReattach(input: {
  cwd: string;
  envFile: string;
  persisted: PersistedProductionEvidence;
  payeeSigningSeedHex?: string;
  agentRecognitionSigningSeedHex?: string;
  command?: string;
}): Promise<PaybondRunProductionEvidenceCredentials> {
  const command = input.command ?? "agent tool execute";
  const payeeDid = input.persisted.payee_did?.trim() ?? "";
  const keyId = input.persisted.agent_recognition_key_id?.trim() ?? "";
  if (!payeeDid || !keyId) {
    throw new CliError(
      "run is missing production_evidence metadata; re-bind with production attach flags",
      { category: "validation", code: "cli.agent.missing_production_evidence" },
    );
  }

  const payeeSigningSeedHex =
    input.payeeSigningSeedHex?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_PAYEE_SEED_HEX"));
  const agentRecognitionSigningSeedHex =
    input.agentRecognitionSigningSeedHex?.trim() ||
    (await readConfiguredEnvValue(input.cwd, input.envFile, "APP_AGENT_RECOGNITION_SEED_HEX"));

  if (!payeeSigningSeedHex) {
    throw new CliError(
      `${command} requires --payee-signing-seed-hex or APP_PAYEE_SEED_HEX for production runs`,
      { category: "usage", code: "cli.agent.production_signing_seed_required" },
    );
  }
  if (!agentRecognitionSigningSeedHex) {
    throw new CliError(
      `${command} requires --agent-recognition-signing-seed-hex or APP_AGENT_RECOGNITION_SEED_HEX for production runs`,
      { category: "usage", code: "cli.agent.production_signing_seed_required" },
    );
  }

  return {
    payeeDid,
    payeeSigningSeed: parseSeed32Hex(payeeSigningSeedHex, "--payee-signing-seed-hex"),
    agentRecognitionKeyId: keyId,
    agentRecognitionSigningSeed: parseSeed32Hex(
      agentRecognitionSigningSeedHex,
      "--agent-recognition-signing-seed-hex",
    ),
  };
}
