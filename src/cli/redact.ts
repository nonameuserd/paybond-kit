export function maskApiKey(rawKey: string): string {
  const trimmed = rawKey.trim();
  const parts = trimmed.split("_");
  if (parts.length >= 5 && parts[0] === "paybond" && parts[1] === "sk") {
    const environment = parts[2]!;
    const keyId = parts[3]!;
    const redactedKeyId = keyId.length > 12 ? `${keyId.slice(0, 8)}...${keyId.slice(-4)}` : "redacted";
    return `paybond_sk_${environment}_${redactedKeyId}`;
  }
  return "paybond_sk_...";
}

export function redactSensitiveFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveFields(item));
  }
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (child && typeof child === "object") {
        out[key] = redactSensitiveFields(child);
        continue;
      }
      const lowered = key.toLowerCase();
      if (
        lowered === "capability_token" ||
        lowered === "access_token" ||
        lowered === "refresh_token" ||
        (lowered.endsWith("_token") && lowered !== "token_type")
      ) {
        out[key] = typeof child === "string" && child.trim() ? "[redacted]" : child;
      } else if (lowered === "api_key" || lowered.endsWith("_api_key")) {
        out[key] = typeof child === "string" ? maskApiKey(child) : child;
      } else {
        out[key] = child;
      }
    }
    return out;
  }
  return value;
}

const SENSITIVE_CONFIG_KEY_EXACT = new Set([
  "api_key",
  "paybond_api_key",
  "secret",
  "client_secret",
  "password",
]);

const SENSITIVE_CONFIG_KEY_TOKEN_ALLOWLIST = new Set(["token_type", "token_endpoint"]);

export function isSensitiveConfigKey(key: string): boolean {
  const lowered = key.toLowerCase();
  if (SENSITIVE_CONFIG_KEY_EXACT.has(lowered)) {
    return true;
  }
  if (lowered.endsWith("_token") && !SENSITIVE_CONFIG_KEY_TOKEN_ALLOWLIST.has(lowered)) {
    return true;
  }
  if (lowered.endsWith("_api_key") || lowered.endsWith("_secret") || lowered.endsWith("_password")) {
    return true;
  }
  return false;
}

export function redactConfigValue(key: string, value: string): string {
  if (!isSensitiveConfigKey(key)) {
    return value;
  }
  return value.trim() ? maskApiKey(value) : "";
}
