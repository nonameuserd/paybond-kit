import { mkdir, readFile, writeFile } from "node:fs/promises";

import { redactConfigValue } from "./redact.js";
import { validateCliGateway } from "./globals.js";
import { CliError } from "./types.js";

export type CliConfigFile = {
  install_id?: string;
  telemetry?: boolean;
  profiles?: Record<string, { env_file?: string; gateway?: string }>;
  values?: Record<string, string>;
};

export function configFilePath(): string {
  const home = process.env.HOME?.trim() || process.env.USERPROFILE?.trim() || "";
  const base = process.env.XDG_CONFIG_HOME?.trim() || (home ? `${home}/.config` : ".config");
  return `${base.replace(/\/+$/, "")}/paybond/config.json`;
}

export async function loadConfigFile(): Promise<CliConfigFile> {
  try {
    const raw = await readFile(configFilePath(), "utf8");
    const parsed = JSON.parse(raw) as CliConfigFile;
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      return {};
    }
    throw new CliError(`unable to read CLI config: ${err instanceof Error ? err.message : String(err)}`, {
      category: "environment",
      code: "cli.environment.config_read_failed",
    });
  }
}

export async function saveConfigFile(config: CliConfigFile): Promise<void> {
  const configPath = configFilePath();
  const dir = configPath.replace(/\/[^/]+$/, "");
  await mkdir(dir, { recursive: true });
  await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

export async function resolveConfigValue(key: string, profile?: string): Promise<string | undefined> {
  const config = await loadConfigFile();
  if (profile) {
    const profileValues = config.profiles?.[profile];
    if (profileValues && key in profileValues) {
      const value = profileValues[key as keyof typeof profileValues];
      return typeof value === "string" ? value : undefined;
    }
  }
  return config.values?.[key];
}

export async function setConfigValue(key: string, value: string, profile?: string): Promise<void> {
  const storedValue = key.toLowerCase() === "gateway" ? validateCliGateway(value) : value;
  const config = await loadConfigFile();
  if (profile) {
    config.profiles ??= {};
    config.profiles[profile] ??= {};
    (config.profiles[profile] as Record<string, string>)[key] = storedValue;
  } else {
    config.values ??= {};
    config.values[key] = storedValue;
  }
  await saveConfigFile(config);
}

export async function unsetConfigValue(key: string, profile?: string): Promise<boolean> {
  const config = await loadConfigFile();
  if (profile) {
    const profileValues = config.profiles?.[profile];
    if (!profileValues || !(key in profileValues)) {
      return false;
    }
    delete (profileValues as Record<string, string>)[key];
    await saveConfigFile(config);
    return true;
  }
  if (!config.values || !(key in config.values)) {
    return false;
  }
  delete config.values[key];
  await saveConfigFile(config);
  return true;
}

export async function listConfigEntries(profile?: string): Promise<Record<string, string>> {
  const config = await loadConfigFile();
  const entries: Record<string, string> = {};
  if (profile) {
    const profileValues = config.profiles?.[profile] ?? {};
    for (const [key, value] of Object.entries(profileValues)) {
      if (typeof value === "string") {
        entries[key] = redactConfigValue(key, value);
      }
    }
    return entries;
  }
  for (const [key, value] of Object.entries(config.values ?? {})) {
    entries[key] = redactConfigValue(key, value);
  }
  for (const [profileName, profileValues] of Object.entries(config.profiles ?? {})) {
    for (const [key, value] of Object.entries(profileValues ?? {})) {
      if (typeof value === "string") {
        entries[`profiles.${profileName}.${key}`] = redactConfigValue(key, value);
      }
    }
  }
  return entries;
}

declare const process: { env: Record<string, string | undefined> };
