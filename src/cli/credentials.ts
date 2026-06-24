import { readFile } from "node:fs/promises";
import path from "node:path";

import { resolveConfigValue } from "./config.js";
import { CLI_WARN_ENV_FALLBACK, formatWarning } from "./automation.js";
import { DEFAULT_ENV_FILE, DEFAULT_GATEWAY } from "./globals.js";
import { CliError, type GlobalOptions } from "./types.js";

function resolvePath(cwd: string, envFile: string): string {
  return path.isAbsolute(envFile) ? path.resolve(envFile) : path.resolve(cwd, envFile);
}

declare const process: { env: Record<string, string | undefined>; cwd(): string };

function quoteTrim(value: string): string {
  const trimmed = value.trim();
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

export function readEnvFileValue(body: string, key: string): string | undefined {
  const prefix = `${key}=`;
  const exportPrefix = `export ${key}=`;
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.trim();
    let value = "";
    if (line.startsWith(exportPrefix)) {
      value = line.slice(exportPrefix.length).trim();
    } else if (line.startsWith(prefix)) {
      value = line.slice(prefix.length).trim();
    } else {
      continue;
    }
    const unquoted = quoteTrim(value);
    return unquoted || undefined;
  }
  return undefined;
}

export async function loadEnvFile(envFile: string, cwd: string): Promise<string | undefined> {
  const envPath = resolvePath(cwd, envFile);
  try {
    const body = await readFile(envPath, "utf8");
    return readEnvFileValue(body, "PAYBOND_API_KEY");
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return undefined;
    }
    throw new CliError(`unable to read env file ${envPath}`, {
      category: "environment",
      code: "cli.environment.env_file_read_failed",
      details: { env_file: envPath },
    });
  }
}

export type ResolvedApiKey = {
  apiKey: string;
  warnings: string[];
};

export async function resolveApiKeyWithMeta(globals: GlobalOptions, cwd: string): Promise<ResolvedApiKey> {
  const warnings: string[] = [];
  const fromProcess = process.env.PAYBOND_API_KEY?.trim();
  if (fromProcess) {
    warnings.push(formatWarning(CLI_WARN_ENV_FALLBACK, "using PAYBOND_API_KEY from process environment"));
    return { apiKey: fromProcess, warnings };
  }
  let envFile = globals.envFile;
  let gateway = globals.gateway;
  if (globals.profile) {
    const profileEnvFile = await resolveConfigValue("env_file", globals.profile);
    const profileGateway = await resolveConfigValue("gateway", globals.profile);
    if (profileEnvFile) {
      envFile = profileEnvFile;
      warnings.push(formatWarning(CLI_WARN_ENV_FALLBACK, `using profile ${globals.profile} env_file`));
    }
    if (profileGateway) {
      gateway = profileGateway;
      warnings.push(formatWarning(CLI_WARN_ENV_FALLBACK, `using profile ${globals.profile} gateway`));
    }
  }
  globals.envFile = envFile;
  globals.gateway = gateway;
  const fromFile = await loadEnvFile(envFile, cwd);
  if (fromFile) {
    return { apiKey: fromFile, warnings };
  }
  throw new CliError("missing PAYBOND_API_KEY; run paybond login or set PAYBOND_API_KEY", {
    category: "auth",
    code: "cli.auth.missing_api_key",
    exitCode: 2,
    details: { env_file: resolvePath(cwd, envFile) },
  });
}

export async function resolveApiKey(globals: GlobalOptions, cwd: string): Promise<string> {
  const resolved = await resolveApiKeyWithMeta(globals, cwd);
  return resolved.apiKey;
}

export type CredentialSourceDescription = {
  source: "process_env" | "env_file" | "missing";
  env_file?: string;
  profile?: string;
  key_masked?: string;
};

export async function describeCredentialSource(
  globals: GlobalOptions,
  cwd: string,
): Promise<CredentialSourceDescription> {
  const { maskApiKey } = await import("./redact.js");
  const fromProcess = process.env.PAYBOND_API_KEY?.trim();
  if (fromProcess) {
    return { source: "process_env", key_masked: maskApiKey(fromProcess) };
  }
  let envFile = globals.envFile;
  const profile = globals.profile;
  if (globals.profile) {
    const profileEnvFile = await resolveConfigValue("env_file", globals.profile);
    if (profileEnvFile) {
      envFile = profileEnvFile;
    }
  }
  const envPath = resolvePath(cwd, envFile);
  try {
    const fromFile = await loadEnvFile(envFile, cwd);
    if (fromFile) {
      return {
        source: "env_file",
        env_file: envPath,
        profile: profile ?? undefined,
        key_masked: maskApiKey(fromFile),
      };
    }
  } catch {
    // fall through to missing
  }
  return {
    source: "missing",
    env_file: envPath,
    profile: profile ?? undefined,
  };
}

export function assertApiKeyShape(apiKey: string): void {
  if (!apiKey.startsWith("paybond_sk_")) {
    throw new CliError("PAYBOND_API_KEY has an unexpected shape", {
      category: "auth",
      code: "cli.auth.invalid_api_key_shape",
      exitCode: 2,
    });
  }
}

export function resolvedDefaultsForDoctor(globals: GlobalOptions): { gateway: string; envFile: string } {
  return {
    gateway: globals.gateway || DEFAULT_GATEWAY,
    envFile: globals.envFile || DEFAULT_ENV_FILE,
  };
}
