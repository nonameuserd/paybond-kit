import { redactPaybondAttachBundle } from "../agent/attach-bundle.js";

const SENSITIVE_SEED_EXACT_FIELDS = new Set(["payee_signing_seed", "agent_recognition_signing_seed"]);
const ATTACH_BUNDLE_FIELDS = new Set(["attach_bundle", "paybond_attach_bundle"]);

function isSensitiveSeedKey(key: string): boolean {
  const lowered = key.toLowerCase();
  if (SENSITIVE_SEED_EXACT_FIELDS.has(lowered)) {
    return true;
  }
  return lowered.endsWith("_seed") || lowered.endsWith("_seed_hex");
}

function isAttachBundleKey(key: string): boolean {
  return ATTACH_BUNDLE_FIELDS.has(key.toLowerCase());
}

function redactAttachBundleValue(value: unknown): unknown {
  if (typeof value === "string") {
    return value.trim() ? redactPaybondAttachBundle(value) : value;
  }
  return hasRedactableScalarContent(value) ? "[redacted]" : value;
}

function hasRedactableScalarContent(value: unknown): boolean {
  if (typeof value === "string") {
    return value.trim().length > 0;
  }
  if (value instanceof Uint8Array) {
    return value.length > 0;
  }
  return false;
}

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
      const lowered = key.toLowerCase();
      if (
        lowered === "capability_token" ||
        lowered === "capabilitytoken" ||
        lowered === "access_token" ||
        lowered === "accesstoken" ||
        lowered === "refresh_token" ||
        lowered === "refreshtoken" ||
        (lowered.endsWith("_token") && lowered !== "token_type")
      ) {
        out[key] = hasRedactableScalarContent(child) ? "[redacted]" : child;
        continue;
      }
      if (lowered === "api_key" || lowered.endsWith("_api_key")) {
        out[key] = typeof child === "string" ? maskApiKey(child) : child;
        continue;
      }
      if (isAttachBundleKey(key)) {
        out[key] = redactAttachBundleValue(child);
        continue;
      }
      if (typeof child === "string" && child.trim().startsWith("ab1.")) {
        out[key] = redactPaybondAttachBundle(child);
        continue;
      }
      if (isSensitiveSeedKey(key)) {
        out[key] = hasRedactableScalarContent(child) ? "[redacted]" : child;
        continue;
      }
      if (child && typeof child === "object") {
        out[key] = redactSensitiveFields(child);
        continue;
      }
      out[key] = child;
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
  "attach_bundle",
  "paybond_attach_bundle",
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
  if (isAttachBundleKey(key) || value.trim().startsWith("ab1.")) {
    return value.trim() ? redactPaybondAttachBundle(value) : "";
  }
  return value.trim() ? maskApiKey(value) : "";
}
