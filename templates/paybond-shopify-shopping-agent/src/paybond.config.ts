import { Paybond } from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

function readEnvValue(body: string, key: string): string | undefined {
  const pattern = new RegExp("^\\s*(?:export\\s+)?" + key + "\\s*=\\s*(.*)$", "m");
  const match = body.match(pattern);
  if (!match) return undefined;
  let value = (match[1] ?? "").trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      value = JSON.parse(value);
    } catch {
      value = value.slice(1, -1);
    }
  } else if (value.startsWith("'") && value.endsWith("'")) {
    value = value.slice(1, -1);
  }
  return value.trim() || undefined;
}

export async function loadPaybondEnvFile(envFile = ".env.local"): Promise<void> {
  if (process.env.PAYBOND_API_KEY?.trim()) return;
  let body: string;
  try {
    const { readFile } = await import("node:fs/promises");
    body = await readFile(envFile, "utf8");
  } catch (err) {
    if ((err as { code?: string }).code === "ENOENT") return;
    throw err;
  }
  const apiKey = readEnvValue(body, "PAYBOND_API_KEY");
  if (apiKey) {
    process.env.PAYBOND_API_KEY = apiKey;
  }
}

export async function createPaybondClient(): Promise<Paybond> {
  await loadPaybondEnvFile(".env.local");
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login");
  }
  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}
