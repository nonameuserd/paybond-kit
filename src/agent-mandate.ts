/**
 * Local verification for protocol-v2 signed AgentMandateV1 envelopes.
 *
 * Canonical JSON matches Go gateway `marshalCanonicalAgentMandate` (fixed struct field
 * order and HTML-safe `\u` escapes), not Kit's generic JCS-style `normalizeJson`.
 */

import { createHash } from "node:crypto";

import { getPublicKey, sign, verify as ed25519Verify } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";

export const AGENT_MANDATE_SCHEMA_VERSION = 1;
export const AGENT_MANDATE_KIND_V1 = "paybond.agent_mandate_v1";
export const AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256 = "ed25519-sha256-json-v1";

export const AGENT_AUTHORIZATION_KIND_PRINCIPAL = "principal";
export const AGENT_AUTHORIZATION_KIND_TENANT = "tenant";

export const HUMAN_PRESENCE_MODE_HUMAN_PRESENT = "human_present";
export const HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT = "human_not_present";

export const CONSTRAINT_REFERENCE_KIND_PREDICATE = "predicate";
export const CONSTRAINT_REFERENCE_KIND_POLICY = "policy";

export const SCOPE_TOKEN_RE = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
export const CURRENCY_RE = /^[a-z0-9_]{3,16}$/;
export const HEX64_RE = /^[a-f0-9]{64}$/;
export const TENANT_ID_RE = /^[a-z0-9][a-z0-9._-]*$/;
export const MAX_TENANT_ID_LEN = 256;

const SETTLEMENT_RAILS = new Set([
  "stripe_connect",
  "stripe_ach_debit",
  "stripe_mpp",
  "x402_usdc_base",
]);

export type AgentMandateAuthorization = {
  kind: string;
  tenant_id: string;
  principal_subject: string;
  principal_type: string;
};

export type AgentMandateAgentIdentity = {
  subject: string;
  issuer: string;
  key_id: string;
  display_name: string;
};

export type AgentMandateSpendCeiling = {
  amount_minor: number;
  currency: string;
};

export type AgentMandateSettlementRailPolicy = {
  default_rail: string;
  allowed_rails: string[];
};

export type AgentMandateConstraintReference = {
  kind: string;
  id: string;
  version: string;
  digest_sha256_hex: string;
  uri: string;
};

/** Normalized mandate core used for canonical JSON hashing and signing. */
export type AgentMandateV1 = {
  schema_version: number;
  kind: string;
  authorization: AgentMandateAuthorization;
  agent: AgentMandateAgentIdentity;
  allowed_actions: string[];
  allowed_tools: string[];
  spend_ceiling: AgentMandateSpendCeiling;
  settlement: AgentMandateSettlementRailPolicy;
  constraint: AgentMandateConstraintReference;
  expires_at: string;
  nonce: string;
  human_presence_mode: string;
};

export type SignedAgentMandateV1 = AgentMandateV1 & {
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

type AgentMandateWireInput = AgentMandateV1 | Record<string, unknown>;

export function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

export function readString(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback;
}

export function readNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string");
}

export function hexToBytes(hex: string): Uint8Array {
  const trimmed = hex.trim().toLowerCase();
  if (trimmed.length % 2 !== 0) {
    throw new Error("invalid hex length");
  }
  const out = new Uint8Array(trimmed.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function sha256Hex(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Matches Go `encoding/json` HTML-safe escaping on top of standard JSON encoding. */
export function goJsonEscape(json: string): string {
  return json
    .replaceAll("&", "\\u0026")
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function parseTenantId(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("agent mandate: authorization.tenant_id: tenant: id is missing");
  }
  if (trimmed.length > MAX_TENANT_ID_LEN) {
    throw new Error(
      `agent mandate: authorization.tenant_id: tenant: id exceeds max length (${MAX_TENANT_ID_LEN})`,
    );
  }
  if (!TENANT_ID_RE.test(trimmed)) {
    throw new Error(
      "agent mandate: authorization.tenant_id: tenant: id must match [a-z0-9][a-z0-9._-]* (lowercase alphanumeric, dots, underscores, hyphens)",
    );
  }
  return trimmed;
}

function normalizeScopeSet(raw: string[], field: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    const value = item.trim().toLowerCase();
    if (value === "") {
      throw new Error(`agent mandate: ${field} contains an empty value`);
    }
    if (!SCOPE_TOKEN_RE.test(value)) {
      throw new Error(`agent mandate: ${field} value ${JSON.stringify(value)} is not canonical`);
    }
    if (seen.has(value)) {
      continue;
    }
    seen.add(value);
    out.push(value);
  }
  out.sort();
  return out;
}

function normalizeAllowedRails(raw: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const item of raw) {
    const rail = item.trim().toLowerCase();
    if (!SETTLEMENT_RAILS.has(rail)) {
      throw new Error(`agent mandate: settlement.allowed_rails: unknown settlement rail ${JSON.stringify(item)}`);
    }
    if (seen.has(rail)) {
      continue;
    }
    seen.add(rail);
    out.push(rail);
  }
  out.sort();
  return out;
}

function parseExpiresAt(value: unknown): Date {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error("agent mandate: expires_at is required");
    }
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      throw new Error("agent mandate: expires_at is required");
    }
    const parsed = new Date(trimmed);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error("agent mandate: expires_at is required");
    }
    return parsed;
  }
  throw new Error("agent mandate: expires_at is required");
}

export function roundUtcToSeconds(date: Date): Date {
  const rounded = new Date(date.getTime());
  rounded.setUTCMilliseconds(0);
  return rounded;
}

/** Formats UTC timestamps like Go `time.RFC3339Nano` with zero sub-second precision omitted. */
export function formatRfc3339NanoUtc(date: Date): string {
  const iso = date.toISOString();
  return iso.endsWith(".000Z") ? `${iso.slice(0, -5)}Z` : iso;
}

function coerceAgentMandateWire(input: AgentMandateWireInput): Record<string, unknown> {
  return readObject(input) ?? {};
}

function readAgentMandateFields(raw: Record<string, unknown>): {
  schema_version: number;
  kind: string;
  authorization: Record<string, unknown>;
  agent: Record<string, unknown>;
  allowed_actions: string[];
  allowed_tools: string[];
  spend_ceiling: Record<string, unknown>;
  settlement: Record<string, unknown>;
  constraint: Record<string, unknown>;
  expires_at: unknown;
  nonce: string;
  human_presence_mode: string;
} {
  return {
    schema_version: readNumber(raw.schema_version),
    kind: readString(raw.kind),
    authorization: readObject(raw.authorization) ?? {},
    agent: readObject(raw.agent) ?? {},
    allowed_actions: readStringArray(raw.allowed_actions),
    allowed_tools: readStringArray(raw.allowed_tools),
    spend_ceiling: readObject(raw.spend_ceiling) ?? {},
    settlement: readObject(raw.settlement) ?? {},
    constraint: readObject(raw.constraint) ?? {},
    expires_at: raw.expires_at,
    nonce: readString(raw.nonce),
    human_presence_mode: readString(raw.human_presence_mode),
  };
}

/**
 * Validates and canonicalizes mandate fields for hashing and signing.
 *
 * @throws When structure or field values are invalid.
 */
export function normalizeAgentMandateV1(input: AgentMandateWireInput): AgentMandateV1 {
  const raw = readAgentMandateFields(coerceAgentMandateWire(input));

  let schemaVersion = raw.schema_version;
  if (schemaVersion === 0 || schemaVersion === AGENT_MANDATE_SCHEMA_VERSION) {
    schemaVersion = AGENT_MANDATE_SCHEMA_VERSION;
  } else {
    throw new Error(`agent mandate: unsupported schema_version ${schemaVersion}`);
  }

  let kind = raw.kind.trim();
  if (kind === "" || kind === AGENT_MANDATE_KIND_V1) {
    kind = AGENT_MANDATE_KIND_V1;
  } else {
    throw new Error(`agent mandate: unsupported kind ${JSON.stringify(kind)}`);
  }

  const authorizationKind = readString(raw.authorization.kind).trim().toLowerCase();
  if (
    authorizationKind !== AGENT_AUTHORIZATION_KIND_PRINCIPAL &&
    authorizationKind !== AGENT_AUTHORIZATION_KIND_TENANT
  ) {
    throw new Error(
      `agent mandate: authorization.kind must be ${JSON.stringify(AGENT_AUTHORIZATION_KIND_PRINCIPAL)} or ${JSON.stringify(AGENT_AUTHORIZATION_KIND_TENANT)}`,
    );
  }

  const tenantId = parseTenantId(readString(raw.authorization.tenant_id));
  const principalSubject = readString(raw.authorization.principal_subject).trim();
  const principalType = readString(raw.authorization.principal_type).trim().toLowerCase();

  if (authorizationKind === AGENT_AUTHORIZATION_KIND_PRINCIPAL) {
    if (!principalSubject) {
      throw new Error(
        "agent mandate: authorization.principal_subject is required for principal-scoped mandates",
      );
    }
    if (principalType && !SCOPE_TOKEN_RE.test(principalType)) {
      throw new Error(
        `agent mandate: authorization.principal_type ${JSON.stringify(principalType)} is not canonical`,
      );
    }
  } else if (principalSubject || principalType) {
    throw new Error(
      "agent mandate: tenant-scoped mandates must not set principal_subject or principal_type",
    );
  }

  const agentSubject = readString(raw.agent.subject).trim();
  const agentIssuer = readString(raw.agent.issuer).trim();
  const agentKeyId = readString(raw.agent.key_id).trim();
  const agentDisplayName = readString(raw.agent.display_name).trim();
  if (!agentSubject) {
    throw new Error("agent mandate: agent.subject is required");
  }

  const allowedActions = normalizeScopeSet(raw.allowed_actions, "allowed_actions");
  const allowedTools = normalizeScopeSet(raw.allowed_tools, "allowed_tools");
  if (allowedActions.length === 0 && allowedTools.length === 0) {
    throw new Error("agent mandate: at least one allowed action or allowed tool is required");
  }

  const amountMinor = readNumber(raw.spend_ceiling.amount_minor);
  if (amountMinor <= 0) {
    throw new Error("agent mandate: spend_ceiling.amount_minor must be greater than zero");
  }
  const currency = readString(raw.spend_ceiling.currency).trim().toLowerCase();
  if (!CURRENCY_RE.test(currency)) {
    throw new Error(`agent mandate: spend_ceiling.currency ${JSON.stringify(currency)} is not canonical`);
  }

  const defaultRail = readString(raw.settlement.default_rail).trim().toLowerCase();
  const allowedRails = normalizeAllowedRails(readStringArray(raw.settlement.allowed_rails));
  if (!defaultRail) {
    throw new Error("agent mandate: settlement.default_rail is required");
  }
  if (allowedRails.length === 0) {
    throw new Error("agent mandate: settlement.allowed_rails must contain at least one rail");
  }
  if (!allowedRails.includes(defaultRail)) {
    throw new Error("agent mandate: settlement.default_rail must be present in settlement.allowed_rails");
  }

  const constraintKind = readString(raw.constraint.kind).trim().toLowerCase();
  if (
    constraintKind !== CONSTRAINT_REFERENCE_KIND_PREDICATE &&
    constraintKind !== CONSTRAINT_REFERENCE_KIND_POLICY
  ) {
    throw new Error(
      `agent mandate: constraint.kind must be ${JSON.stringify(CONSTRAINT_REFERENCE_KIND_PREDICATE)} or ${JSON.stringify(CONSTRAINT_REFERENCE_KIND_POLICY)}`,
    );
  }
  const constraintId = readString(raw.constraint.id).trim();
  const constraintVersion = readString(raw.constraint.version).trim();
  const constraintDigest = readString(raw.constraint.digest_sha256_hex).trim().toLowerCase();
  const constraintUri = readString(raw.constraint.uri).trim();
  if (constraintDigest && !HEX64_RE.test(constraintDigest)) {
    throw new Error(
      "agent mandate: constraint.digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest",
    );
  }
  if (!constraintId && !constraintUri && !constraintDigest) {
    throw new Error("agent mandate: constraint must set id, uri, or digest_sha256_hex");
  }

  const nonce = raw.nonce.trim();
  if (!nonce) {
    throw new Error("agent mandate: nonce is required");
  }
  if (nonce.length > 256) {
    throw new Error("agent mandate: nonce must be 256 bytes or fewer");
  }

  const humanPresenceMode = raw.human_presence_mode.trim().toLowerCase();
  if (
    humanPresenceMode !== HUMAN_PRESENCE_MODE_HUMAN_PRESENT &&
    humanPresenceMode !== HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT
  ) {
    throw new Error(
      `agent mandate: human_presence_mode must be ${JSON.stringify(HUMAN_PRESENCE_MODE_HUMAN_PRESENT)} or ${JSON.stringify(HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT)}`,
    );
  }

  const expiresAt = formatRfc3339NanoUtc(roundUtcToSeconds(parseExpiresAt(raw.expires_at)));

  return {
    schema_version: schemaVersion,
    kind,
    authorization: {
      kind: authorizationKind,
      tenant_id: tenantId,
      principal_subject: principalSubject,
      principal_type: principalType,
    },
    agent: {
      subject: agentSubject,
      issuer: agentIssuer,
      key_id: agentKeyId,
      display_name: agentDisplayName,
    },
    allowed_actions: allowedActions,
    allowed_tools: allowedTools,
    spend_ceiling: {
      amount_minor: amountMinor,
      currency,
    },
    settlement: {
      default_rail: defaultRail,
      allowed_rails: allowedRails,
    },
    constraint: {
      kind: constraintKind,
      id: constraintId,
      version: constraintVersion,
      digest_sha256_hex: constraintDigest,
      uri: constraintUri,
    },
    expires_at: expiresAt,
    nonce,
    human_presence_mode: humanPresenceMode,
  };
}

function marshalCanonicalAgentMandate(mandate: AgentMandateV1): Uint8Array {
  const payload = {
    schema_version: mandate.schema_version,
    kind: mandate.kind,
    authorization: {
      kind: mandate.authorization.kind,
      tenant_id: mandate.authorization.tenant_id,
      principal_subject: mandate.authorization.principal_subject,
      principal_type: mandate.authorization.principal_type,
    },
    agent: {
      subject: mandate.agent.subject,
      issuer: mandate.agent.issuer,
      key_id: mandate.agent.key_id,
      display_name: mandate.agent.display_name,
    },
    allowed_actions: [...mandate.allowed_actions],
    allowed_tools: [...mandate.allowed_tools],
    spend_ceiling: {
      amount_minor: mandate.spend_ceiling.amount_minor,
      currency: mandate.spend_ceiling.currency,
    },
    settlement: {
      default_rail: mandate.settlement.default_rail,
      allowed_rails: [...mandate.settlement.allowed_rails],
    },
    constraint: {
      kind: mandate.constraint.kind,
      id: mandate.constraint.id,
      version: mandate.constraint.version,
      digest_sha256_hex: mandate.constraint.digest_sha256_hex,
      uri: mandate.constraint.uri,
    },
    expires_at: mandate.expires_at,
    nonce: mandate.nonce,
    human_presence_mode: mandate.human_presence_mode,
  };

  return new TextEncoder().encode(goJsonEscape(JSON.stringify(payload)));
}

/** Returns canonical mandate bytes used for digesting and Ed25519 signing. */
export function canonicalAgentMandateJsonBytes(input: AgentMandateWireInput): Uint8Array {
  return marshalCanonicalAgentMandate(normalizeAgentMandateV1(input));
}

/** Returns the portable SHA-256 digest over canonical mandate JSON as lowercase hex. */
export function agentMandateDigestSha256Hex(input: AgentMandateWireInput): string {
  return sha256Hex(canonicalAgentMandateJsonBytes(input));
}

/**
 * Validates, canonicalizes, and signs a mandate with Ed25519-over-SHA-256(canonical JSON).
 *
 * @param signingSeed - 32-byte Ed25519 seed (noble private key).
 */
export function signAgentMandateV1(
  signingSeed: Uint8Array,
  input: AgentMandateWireInput,
): SignedAgentMandateV1 {
  ensureEd25519Sha512Sync();
  if (signingSeed.length !== 32) {
    throw new Error("agent mandate: signing key must be an ed25519 private key");
  }

  const normalized = normalizeAgentMandateV1(input);
  const body = marshalCanonicalAgentMandate(normalized);
  const digest = sha256Hex(body);
  const digestBytes = hexToBytes(digest);
  const signature = sign(digestBytes, signingSeed);
  const publicKey = getPublicKey(signingSeed);

  return {
    ...normalized,
    signing_algorithm: AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256,
    message_digest_sha256_hex: digest,
    signing_public_key_ed25519_hex: Buffer.from(publicKey).toString("hex"),
    ed25519_signature_hex: Buffer.from(signature).toString("hex"),
  };
}

/**
 * Checks structure, expiry, digest recompute, and detached Ed25519 signature.
 *
 * @param now - Verification instant (defaults to current UTC time).
 */
export function verifySignedAgentMandateV1(
  signed: SignedAgentMandateV1 | Record<string, unknown>,
  now: Date = new Date(),
): void {
  ensureEd25519Sha512Sync();

  const raw = coerceAgentMandateWire(signed);
  const mandateFields = readAgentMandateFields(raw);
  const normalized = normalizeAgentMandateV1(mandateFields);

  const nowUtc = new Date(now.getTime());
  const expiresAt = parseExpiresAt(normalized.expires_at);
  if (expiresAt.getTime() <= nowUtc.getTime()) {
    throw new Error(`agent mandate: expired at ${normalized.expires_at}`);
  }

  const signingAlgorithm = readString(raw.signing_algorithm).trim();
  if (signingAlgorithm !== AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256) {
    throw new Error(
      `agent mandate: signing_algorithm must be ${JSON.stringify(AGENT_MANDATE_SIGNING_ALGORITHM_ED25519_SHA256)}`,
    );
  }

  const body = marshalCanonicalAgentMandate(normalized);
  const digest = sha256Hex(body);
  const messageDigest = readString(raw.message_digest_sha256_hex).trim().toLowerCase();
  if (!HEX64_RE.test(messageDigest)) {
    throw new Error(
      "agent mandate: message_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest",
    );
  }
  if (messageDigest !== digest) {
    throw new Error("agent mandate: message digest mismatch");
  }

  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = hexToBytes(readString(raw.signing_public_key_ed25519_hex));
    signature = hexToBytes(readString(raw.ed25519_signature_hex));
  } catch {
    throw new Error("agent mandate: invalid signing_public_key_ed25519_hex");
  }
  if (publicKey.length !== 32) {
    throw new Error("agent mandate: invalid signing_public_key_ed25519_hex");
  }
  if (signature.length !== 64) {
    throw new Error("agent mandate: invalid ed25519_signature_hex");
  }

  if (!ed25519Verify(signature, hexToBytes(digest), publicKey)) {
    throw new Error("agent mandate: ed25519 signature verification failed");
  }
}
