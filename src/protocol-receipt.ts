/**
 * Local verification for protocol-v2 authorization and settlement receipts.
 *
 * Canonical JSON matches the Go gateway `protocolAuthorizationReceiptCanonicalV1` /
 * `protocolSettlementReceiptCanonicalV1` marshalers (fixed struct field order, signing
 * fields stripped, RFC3339Nano UTC timestamps, HTML-safe `\u` escapes), not Kit's generic
 * JCS-style `normalizeJson`. Ported from `go/gateway/internal/protocolv2/receipt.go`.
 */

import { getPublicKey, sign, verify as ed25519Verify } from "@noble/ed25519";

import {
  AGENT_AUTHORIZATION_KIND_PRINCIPAL,
  AGENT_AUTHORIZATION_KIND_TENANT,
  CURRENCY_RE,
  HEX64_RE,
  HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT,
  HUMAN_PRESENCE_MODE_HUMAN_PRESENT,
  MAX_TENANT_ID_LEN,
  SCOPE_TOKEN_RE,
  TENANT_ID_RE,
  formatRfc3339NanoUtc,
  goJsonEscape,
  hexToBytes,
  readNumber,
  readObject,
  readString,
  readStringArray,
  roundUtcToSeconds,
  sha256Hex,
  type AgentMandateAgentIdentity,
  type AgentMandateAuthorization,
  type AgentMandateConstraintReference,
  type AgentMandateSettlementRailPolicy,
  type AgentMandateSpendCeiling,
} from "./agent-mandate.js";
import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";

export const PROTOCOL_RECEIPT_SCHEMA_VERSION = 1;
export const PROTOCOL_RECEIPT_VERSION_V1 = "1";
export const PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256 = "ed25519-sha256-json-v1";

export const PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1 = "paybond.protocol_authorization_receipt_v1";
export const PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1 = "paybond.protocol_settlement_receipt_v1";

export const PROTOCOL_RECEIPT_STATUS_AUTHORIZED = "authorized";

/** Default protocol source (AP2-aligned) for imported mandates and exported receipts. */
export const PROTOCOL_SOURCE_AP2 = "ap2";

/** Stripe Agentic Commerce Protocol (ACP) source identifier for partner receipts. */
export const PROTOCOL_SOURCE_ACP = "acp";

/** Stripe Unified Commerce Protocol (UCP) source identifier for partner receipts. */
export const PROTOCOL_SOURCE_UCP = "ucp";

const PROTOCOL_SETTLEMENT_TERMINAL_STATES = new Set([
  "released",
  "refunded",
  "resolved_split",
  "escalated_external",
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Partner transport metadata for imported mandates and exported receipts. */
export type ProtocolTransportBindingV1 = {
  source_protocol: string;
  partner_platform?: string;
  external_authorization_id?: string;
  request_id?: string;
};

/** Signed acknowledgement emitted after accepting a partner mandate binding. */
export type ProtocolAuthorizationReceiptV1 = {
  schema_version: number;
  kind: string;
  receipt_version: string;
  receipt_id: string;
  issued_at: string;
  status: string;
  intent_id: string;
  tenant_id: string;
  verifier_id: string;
  transport_binding: ProtocolTransportBindingV1;
  mandate_digest_sha256_hex: string;
  imported_mandate_signing_public_key_ed25519_hex: string;
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
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

/** Signed terminal outcome artifact for a Harbor intent bound to a partner mandate. */
export type ProtocolSettlementReceiptV1 = {
  schema_version: number;
  kind: string;
  receipt_version: string;
  receipt_id: string;
  issued_at: string;
  intent_id: string;
  tenant_id: string;
  verifier_id: string;
  transport_binding: ProtocolTransportBindingV1;
  authorization_receipt_id: string;
  mandate_digest_sha256_hex: string;
  harbor_state: string;
  predicate_passed?: boolean;
  settlement_rail: string;
  settlement_mode: string;
  principal_did: string;
  payee_did: string;
  currency: string;
  amount_cents: number;
  terminal_observed_at: string;
  signing_algorithm: string;
  message_digest_sha256_hex: string;
  signing_public_key_ed25519_hex: string;
  ed25519_signature_hex: string;
};

type ProtocolAuthorizationReceiptInput = ProtocolAuthorizationReceiptV1 | Record<string, unknown>;
type ProtocolSettlementReceiptInput = ProtocolSettlementReceiptV1 | Record<string, unknown>;

function readOptionalBool(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function coerceWire(input: ProtocolAuthorizationReceiptInput | ProtocolSettlementReceiptInput): Record<string, unknown> {
  return readObject(input) ?? {};
}

function normalizeTenantId(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`${label}: tenant: id is missing`);
  }
  if (trimmed.length > MAX_TENANT_ID_LEN) {
    throw new Error(`${label}: tenant: id exceeds max length (${MAX_TENANT_ID_LEN})`);
  }
  if (!TENANT_ID_RE.test(trimmed)) {
    throw new Error(
      `${label}: tenant: id must match [a-z0-9][a-z0-9._-]* (lowercase alphanumeric, dots, underscores, hyphens)`,
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
      throw new Error(`${field} contains an empty value`);
    }
    if (!SCOPE_TOKEN_RE.test(value)) {
      throw new Error(`${field} value ${JSON.stringify(value)} is not canonical`);
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

function parseTimestamp(value: unknown, errMsg: string): Date {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) {
      throw new Error(errMsg);
    }
    return value;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) {
      throw new Error(errMsg);
    }
    const parsed = new Date(trimmed);
    if (Number.isNaN(parsed.getTime())) {
      throw new Error(errMsg);
    }
    return parsed;
  }
  throw new Error(errMsg);
}

function normalizeTimestamp(value: unknown, errMsg: string): string {
  return formatRfc3339NanoUtc(roundUtcToSeconds(parseTimestamp(value, errMsg)));
}

function normalizeTransportBinding(raw: Record<string, unknown>, label: string): ProtocolTransportBindingV1 {
  let sourceProtocol = readString(raw.source_protocol).trim().toLowerCase();
  if (sourceProtocol === "") {
    sourceProtocol = PROTOCOL_SOURCE_AP2;
  }
  if (!SCOPE_TOKEN_RE.test(sourceProtocol)) {
    throw new Error(`${label}: source_protocol ${JSON.stringify(sourceProtocol)} is not canonical`);
  }
  const partnerPlatform = readString(raw.partner_platform).trim();
  const externalAuthorizationId = readString(raw.external_authorization_id).trim();
  const requestId = readString(raw.request_id).trim();
  for (const [field, value] of [
    ["partner_platform", partnerPlatform],
    ["external_authorization_id", externalAuthorizationId],
    ["request_id", requestId],
  ] as const) {
    if (value.length > 256) {
      throw new Error(`${label}: ${field} must be 256 bytes or fewer`);
    }
  }
  return {
    source_protocol: sourceProtocol,
    partner_platform: partnerPlatform,
    external_authorization_id: externalAuthorizationId,
    request_id: requestId,
  };
}

function canonicalTransportBinding(binding: ProtocolTransportBindingV1): Record<string, unknown> {
  const out: Record<string, unknown> = { source_protocol: binding.source_protocol };
  if (binding.partner_platform) {
    out.partner_platform = binding.partner_platform;
  }
  if (binding.external_authorization_id) {
    out.external_authorization_id = binding.external_authorization_id;
  }
  if (binding.request_id) {
    out.request_id = binding.request_id;
  }
  return out;
}

/**
 * Validates and canonicalizes an authorization receipt for hashing and signing.
 *
 * Signing fields are lower/trim-normalized but not recomputed here.
 *
 * @throws When structure or field values are invalid.
 */
export function normalizeProtocolAuthorizationReceiptV1(
  input: ProtocolAuthorizationReceiptInput,
): ProtocolAuthorizationReceiptV1 {
  const raw = coerceWire(input);
  const label = "protocol authorization receipt";

  let schemaVersion = readNumber(raw.schema_version);
  if (schemaVersion === 0 || schemaVersion === PROTOCOL_RECEIPT_SCHEMA_VERSION) {
    schemaVersion = PROTOCOL_RECEIPT_SCHEMA_VERSION;
  } else {
    throw new Error(`${label}: unsupported schema_version ${schemaVersion}`);
  }

  let kind = readString(raw.kind).trim();
  if (kind === "" || kind === PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1) {
    kind = PROTOCOL_AUTHORIZATION_RECEIPT_KIND_V1;
  } else {
    throw new Error(`${label}: unsupported kind ${JSON.stringify(kind)}`);
  }

  let receiptVersion = readString(raw.receipt_version).trim();
  if (receiptVersion === "" || receiptVersion === PROTOCOL_RECEIPT_VERSION_V1) {
    receiptVersion = PROTOCOL_RECEIPT_VERSION_V1;
  } else {
    throw new Error(`${label}: unsupported receipt_version ${JSON.stringify(receiptVersion)}`);
  }

  const receiptId = readString(raw.receipt_id).trim().toLowerCase();
  if (receiptId === "") {
    throw new Error(`${label}: receipt_id is required`);
  }
  if (!SCOPE_TOKEN_RE.test(receiptId)) {
    throw new Error(`${label}: receipt_id ${JSON.stringify(receiptId)} is not canonical`);
  }

  const intentIdTrimmed = readString(raw.intent_id).trim();
  if (!UUID_RE.test(intentIdTrimmed)) {
    throw new Error(`${label}: intent_id must be a canonical UUID`);
  }
  const intentId = intentIdTrimmed.toLowerCase();

  const issuedAt = normalizeTimestamp(raw.issued_at, `${label}: issued_at is required`);

  let status = readString(raw.status).trim().toLowerCase();
  if (status === "" || status === PROTOCOL_RECEIPT_STATUS_AUTHORIZED) {
    status = PROTOCOL_RECEIPT_STATUS_AUTHORIZED;
  } else {
    throw new Error(`${label}: unsupported status ${JSON.stringify(status)}`);
  }

  const tenantId = normalizeTenantId(readString(raw.tenant_id), `${label}: tenant_id`);

  const verifierId = readString(raw.verifier_id).trim().toLowerCase();
  if (verifierId === "") {
    throw new Error(`${label}: verifier_id is required`);
  }
  if (!SCOPE_TOKEN_RE.test(verifierId)) {
    throw new Error(`${label}: verifier_id ${JSON.stringify(verifierId)} is not canonical`);
  }

  const transportBinding = normalizeTransportBinding(
    readObject(raw.transport_binding) ?? {},
    `${label}: transport_binding`,
  );

  const mandateDigest = readString(raw.mandate_digest_sha256_hex).trim().toLowerCase();
  if (!HEX64_RE.test(mandateDigest)) {
    throw new Error(
      `${label}: mandate_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest`,
    );
  }

  const importedMandatePubKey = readString(raw.imported_mandate_signing_public_key_ed25519_hex)
    .trim()
    .toLowerCase();
  let importedPubKeyBytes: Uint8Array;
  try {
    importedPubKeyBytes = hexToBytes(importedMandatePubKey);
  } catch {
    throw new Error(`${label}: imported_mandate_signing_public_key_ed25519_hex is invalid`);
  }
  if (importedPubKeyBytes.length !== 32) {
    throw new Error(`${label}: imported_mandate_signing_public_key_ed25519_hex is invalid`);
  }

  const authorizationRaw = readObject(raw.authorization) ?? {};
  const authorizationKind = readString(authorizationRaw.kind).trim().toLowerCase();
  if (
    authorizationKind !== AGENT_AUTHORIZATION_KIND_PRINCIPAL &&
    authorizationKind !== AGENT_AUTHORIZATION_KIND_TENANT
  ) {
    throw new Error(
      `${label}: authorization.kind must be ${JSON.stringify(AGENT_AUTHORIZATION_KIND_PRINCIPAL)} or ${JSON.stringify(AGENT_AUTHORIZATION_KIND_TENANT)}`,
    );
  }
  const authorizationTenantId = normalizeTenantId(
    readString(authorizationRaw.tenant_id),
    `${label}: authorization.tenant_id`,
  );
  if (authorizationTenantId !== tenantId) {
    throw new Error(`${label}: authorization.tenant_id must match tenant_id`);
  }
  const authorization: AgentMandateAuthorization = {
    kind: authorizationKind,
    tenant_id: authorizationTenantId,
    principal_subject: readString(authorizationRaw.principal_subject).trim(),
    principal_type: readString(authorizationRaw.principal_type).trim().toLowerCase(),
  };

  const agentRaw = readObject(raw.agent) ?? {};
  const agent: AgentMandateAgentIdentity = {
    subject: readString(agentRaw.subject).trim(),
    issuer: readString(agentRaw.issuer).trim(),
    key_id: readString(agentRaw.key_id).trim(),
    display_name: readString(agentRaw.display_name).trim(),
  };
  if (agent.subject === "") {
    throw new Error(`${label}: agent.subject is required`);
  }

  const allowedActions = normalizeScopeSet(readStringArray(raw.allowed_actions), `${label}: allowed_actions`);
  const allowedTools = normalizeScopeSet(readStringArray(raw.allowed_tools), `${label}: allowed_tools`);
  if (allowedActions.length === 0 && allowedTools.length === 0) {
    throw new Error(`${label}: at least one allowed action or allowed tool is required`);
  }

  const spendCeilingRaw = readObject(raw.spend_ceiling) ?? {};
  const amountMinor = readNumber(spendCeilingRaw.amount_minor);
  if (amountMinor <= 0) {
    throw new Error(`${label}: spend_ceiling.amount_minor must be greater than zero`);
  }
  const currency = readString(spendCeilingRaw.currency).trim().toLowerCase();
  if (!CURRENCY_RE.test(currency)) {
    throw new Error(`${label}: spend_ceiling.currency ${JSON.stringify(currency)} is not canonical`);
  }
  const spendCeiling: AgentMandateSpendCeiling = { amount_minor: amountMinor, currency };

  const settlementRaw = readObject(raw.settlement) ?? {};
  const defaultRail = readString(settlementRaw.default_rail).trim().toLowerCase();
  if (defaultRail === "") {
    throw new Error(`${label}: settlement.default_rail is required`);
  }
  const allowedRails = normalizeScopeSet(
    readStringArray(settlementRaw.allowed_rails),
    `${label}: settlement.allowed_rails`,
  );
  const settlement: AgentMandateSettlementRailPolicy = {
    default_rail: defaultRail,
    allowed_rails: allowedRails,
  };

  const constraintRaw = readObject(raw.constraint) ?? {};
  const constraintKind = readString(constraintRaw.kind).trim().toLowerCase();
  if (constraintKind === "") {
    throw new Error(`${label}: constraint.kind is required`);
  }
  const constraint: AgentMandateConstraintReference = {
    kind: constraintKind,
    id: readString(constraintRaw.id).trim(),
    version: readString(constraintRaw.version).trim(),
    digest_sha256_hex: readString(constraintRaw.digest_sha256_hex).trim().toLowerCase(),
    uri: readString(constraintRaw.uri).trim(),
  };

  const expiresAt = normalizeTimestamp(raw.expires_at, `${label}: expires_at is required`);

  const nonce = readString(raw.nonce).trim();
  if (nonce === "") {
    throw new Error(`${label}: nonce is required`);
  }

  const humanPresenceMode = readString(raw.human_presence_mode).trim().toLowerCase();
  if (
    humanPresenceMode !== HUMAN_PRESENCE_MODE_HUMAN_PRESENT &&
    humanPresenceMode !== HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT
  ) {
    throw new Error(
      `${label}: human_presence_mode must be ${JSON.stringify(HUMAN_PRESENCE_MODE_HUMAN_PRESENT)} or ${JSON.stringify(HUMAN_PRESENCE_MODE_HUMAN_NOT_PRESENT)}`,
    );
  }

  let signingAlgorithm = readString(raw.signing_algorithm).trim().toLowerCase();
  if (signingAlgorithm === "") {
    signingAlgorithm = PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256;
  }

  return {
    schema_version: schemaVersion,
    kind,
    receipt_version: receiptVersion,
    receipt_id: receiptId,
    issued_at: issuedAt,
    status,
    intent_id: intentId,
    tenant_id: tenantId,
    verifier_id: verifierId,
    transport_binding: transportBinding,
    mandate_digest_sha256_hex: mandateDigest,
    imported_mandate_signing_public_key_ed25519_hex: importedMandatePubKey,
    authorization,
    agent,
    allowed_actions: allowedActions,
    allowed_tools: allowedTools,
    spend_ceiling: spendCeiling,
    settlement,
    constraint,
    expires_at: expiresAt,
    nonce,
    human_presence_mode: humanPresenceMode,
    signing_algorithm: signingAlgorithm,
    message_digest_sha256_hex: readString(raw.message_digest_sha256_hex).trim().toLowerCase(),
    signing_public_key_ed25519_hex: readString(raw.signing_public_key_ed25519_hex).trim().toLowerCase(),
    ed25519_signature_hex: readString(raw.ed25519_signature_hex).trim().toLowerCase(),
  };
}

/**
 * Validates and canonicalizes a settlement receipt for hashing and signing.
 *
 * @throws When structure or field values are invalid.
 */
export function normalizeProtocolSettlementReceiptV1(
  input: ProtocolSettlementReceiptInput,
): ProtocolSettlementReceiptV1 {
  const raw = coerceWire(input);
  const label = "protocol settlement receipt";

  let schemaVersion = readNumber(raw.schema_version);
  if (schemaVersion === 0 || schemaVersion === PROTOCOL_RECEIPT_SCHEMA_VERSION) {
    schemaVersion = PROTOCOL_RECEIPT_SCHEMA_VERSION;
  } else {
    throw new Error(`${label}: unsupported schema_version ${schemaVersion}`);
  }

  let kind = readString(raw.kind).trim();
  if (kind === "" || kind === PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1) {
    kind = PROTOCOL_SETTLEMENT_RECEIPT_KIND_V1;
  } else {
    throw new Error(`${label}: unsupported kind ${JSON.stringify(kind)}`);
  }

  let receiptVersion = readString(raw.receipt_version).trim();
  if (receiptVersion === "" || receiptVersion === PROTOCOL_RECEIPT_VERSION_V1) {
    receiptVersion = PROTOCOL_RECEIPT_VERSION_V1;
  } else {
    throw new Error(`${label}: unsupported receipt_version ${JSON.stringify(receiptVersion)}`);
  }

  const receiptId = readString(raw.receipt_id).trim().toLowerCase();
  if (receiptId === "") {
    throw new Error(`${label}: receipt_id is required`);
  }
  if (!SCOPE_TOKEN_RE.test(receiptId)) {
    throw new Error(`${label}: receipt_id ${JSON.stringify(receiptId)} is not canonical`);
  }

  const intentIdTrimmed = readString(raw.intent_id).trim();
  if (!UUID_RE.test(intentIdTrimmed)) {
    throw new Error(`${label}: intent_id must be a canonical UUID`);
  }
  const intentId = intentIdTrimmed.toLowerCase();
  if (receiptId !== intentId) {
    throw new Error(`${label}: receipt_id must equal intent_id for Harbor-backed receipts`);
  }

  const issuedAt = normalizeTimestamp(raw.issued_at, `${label}: issued_at is required`);

  const tenantId = normalizeTenantId(readString(raw.tenant_id), `${label}: tenant_id`);

  const verifierId = readString(raw.verifier_id).trim().toLowerCase();
  if (verifierId === "") {
    throw new Error(`${label}: verifier_id is required`);
  }
  if (!SCOPE_TOKEN_RE.test(verifierId)) {
    throw new Error(`${label}: verifier_id ${JSON.stringify(verifierId)} is not canonical`);
  }

  const transportBinding = normalizeTransportBinding(
    readObject(raw.transport_binding) ?? {},
    `${label}: transport_binding`,
  );

  const authorizationReceiptId = readString(raw.authorization_receipt_id).trim().toLowerCase();
  if (authorizationReceiptId === "") {
    throw new Error(`${label}: authorization_receipt_id is required`);
  }
  if (!SCOPE_TOKEN_RE.test(authorizationReceiptId)) {
    throw new Error(
      `${label}: authorization_receipt_id ${JSON.stringify(authorizationReceiptId)} is not canonical`,
    );
  }

  const mandateDigest = readString(raw.mandate_digest_sha256_hex).trim().toLowerCase();
  if (!HEX64_RE.test(mandateDigest)) {
    throw new Error(
      `${label}: mandate_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest`,
    );
  }

  const harborState = readString(raw.harbor_state).trim().toLowerCase();
  if (!PROTOCOL_SETTLEMENT_TERMINAL_STATES.has(harborState)) {
    throw new Error(
      `${label}: harbor_state must be released, refunded, resolved_split, or escalated_external`,
    );
  }

  const predicatePassed = readOptionalBool(raw.predicate_passed);

  const settlementRail = readString(raw.settlement_rail).trim().toLowerCase();
  if (settlementRail === "") {
    throw new Error(`${label}: settlement_rail is required`);
  }
  const settlementMode = readString(raw.settlement_mode).trim();
  if (settlementMode === "") {
    throw new Error(`${label}: settlement_mode is required`);
  }
  const principalDid = readString(raw.principal_did).trim();
  const payeeDid = readString(raw.payee_did).trim();
  const currency = readString(raw.currency).trim().toLowerCase();
  if (currency === "") {
    throw new Error(`${label}: currency is required`);
  }
  const amountCents = readNumber(raw.amount_cents);
  if (amountCents <= 0) {
    throw new Error(`${label}: amount_cents must be greater than zero`);
  }

  const terminalObservedAt = normalizeTimestamp(
    raw.terminal_observed_at,
    `${label}: terminal_observed_at is required`,
  );

  let signingAlgorithm = readString(raw.signing_algorithm).trim().toLowerCase();
  if (signingAlgorithm === "") {
    signingAlgorithm = PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256;
  }

  const normalized: ProtocolSettlementReceiptV1 = {
    schema_version: schemaVersion,
    kind,
    receipt_version: receiptVersion,
    receipt_id: receiptId,
    issued_at: issuedAt,
    intent_id: intentId,
    tenant_id: tenantId,
    verifier_id: verifierId,
    transport_binding: transportBinding,
    authorization_receipt_id: authorizationReceiptId,
    mandate_digest_sha256_hex: mandateDigest,
    harbor_state: harborState,
    settlement_rail: settlementRail,
    settlement_mode: settlementMode,
    principal_did: principalDid,
    payee_did: payeeDid,
    currency,
    amount_cents: amountCents,
    terminal_observed_at: terminalObservedAt,
    signing_algorithm: signingAlgorithm,
    message_digest_sha256_hex: readString(raw.message_digest_sha256_hex).trim().toLowerCase(),
    signing_public_key_ed25519_hex: readString(raw.signing_public_key_ed25519_hex).trim().toLowerCase(),
    ed25519_signature_hex: readString(raw.ed25519_signature_hex).trim().toLowerCase(),
  };
  if (predicatePassed !== undefined) {
    normalized.predicate_passed = predicatePassed;
  }
  return normalized;
}

function marshalCanonicalAuthorizationReceipt(receipt: ProtocolAuthorizationReceiptV1): Uint8Array {
  const payload = {
    schema_version: receipt.schema_version,
    kind: receipt.kind,
    receipt_version: receipt.receipt_version,
    receipt_id: receipt.receipt_id,
    issued_at: receipt.issued_at,
    status: receipt.status,
    intent_id: receipt.intent_id,
    tenant_id: receipt.tenant_id,
    verifier_id: receipt.verifier_id,
    transport_binding: canonicalTransportBinding(receipt.transport_binding),
    mandate_digest_sha256_hex: receipt.mandate_digest_sha256_hex,
    imported_mandate_signing_public_key_ed25519_hex:
      receipt.imported_mandate_signing_public_key_ed25519_hex,
    authorization: {
      kind: receipt.authorization.kind,
      tenant_id: receipt.authorization.tenant_id,
      principal_subject: receipt.authorization.principal_subject ?? "",
      principal_type: receipt.authorization.principal_type ?? "",
    },
    agent: {
      subject: receipt.agent.subject,
      issuer: receipt.agent.issuer ?? "",
      key_id: receipt.agent.key_id ?? "",
      display_name: receipt.agent.display_name ?? "",
    },
    allowed_actions: receipt.allowed_actions.length > 0 ? [...receipt.allowed_actions] : null,
    allowed_tools: receipt.allowed_tools.length > 0 ? [...receipt.allowed_tools] : null,
    spend_ceiling: {
      amount_minor: receipt.spend_ceiling.amount_minor,
      currency: receipt.spend_ceiling.currency,
    },
    settlement: {
      default_rail: receipt.settlement.default_rail,
      allowed_rails: [...receipt.settlement.allowed_rails],
    },
    constraint: {
      kind: receipt.constraint.kind,
      id: receipt.constraint.id ?? "",
      version: receipt.constraint.version ?? "",
      digest_sha256_hex: receipt.constraint.digest_sha256_hex ?? "",
      uri: receipt.constraint.uri ?? "",
    },
    expires_at: receipt.expires_at,
    nonce: receipt.nonce,
    human_presence_mode: receipt.human_presence_mode,
  };
  return new TextEncoder().encode(goJsonEscape(JSON.stringify(payload)));
}

function marshalCanonicalSettlementReceipt(receipt: ProtocolSettlementReceiptV1): Uint8Array {
  const payload: Record<string, unknown> = {
    schema_version: receipt.schema_version,
    kind: receipt.kind,
    receipt_version: receipt.receipt_version,
    receipt_id: receipt.receipt_id,
    issued_at: receipt.issued_at,
    intent_id: receipt.intent_id,
    tenant_id: receipt.tenant_id,
    verifier_id: receipt.verifier_id,
    transport_binding: canonicalTransportBinding(receipt.transport_binding),
    authorization_receipt_id: receipt.authorization_receipt_id,
    mandate_digest_sha256_hex: receipt.mandate_digest_sha256_hex,
    harbor_state: receipt.harbor_state,
  };
  if (receipt.predicate_passed !== undefined) {
    payload.predicate_passed = receipt.predicate_passed;
  }
  payload.settlement_rail = receipt.settlement_rail;
  payload.settlement_mode = receipt.settlement_mode;
  payload.principal_did = receipt.principal_did;
  payload.payee_did = receipt.payee_did;
  payload.currency = receipt.currency;
  payload.amount_cents = receipt.amount_cents;
  payload.terminal_observed_at = receipt.terminal_observed_at;
  return new TextEncoder().encode(goJsonEscape(JSON.stringify(payload)));
}

function verifySignedDigest(
  kind: string,
  signingAlgorithm: string,
  messageDigestHex: string,
  publicKeyHex: string,
  signatureHex: string,
  expectedDigestHex: string,
): void {
  if (signingAlgorithm !== PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256) {
    throw new Error(
      `${kind}: signing_algorithm must be ${JSON.stringify(PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256)}`,
    );
  }
  if (!HEX64_RE.test(messageDigestHex)) {
    throw new Error(
      `${kind}: message_digest_sha256_hex must be a lowercase 64-byte hex SHA-256 digest`,
    );
  }
  if (messageDigestHex !== expectedDigestHex) {
    throw new Error(`${kind}: message digest mismatch`);
  }
  let publicKey: Uint8Array;
  let signature: Uint8Array;
  try {
    publicKey = hexToBytes(publicKeyHex);
  } catch {
    throw new Error(`${kind}: invalid signing_public_key_ed25519_hex`);
  }
  if (publicKey.length !== 32) {
    throw new Error(`${kind}: invalid signing_public_key_ed25519_hex`);
  }
  try {
    signature = hexToBytes(signatureHex);
  } catch {
    throw new Error(`${kind}: invalid ed25519_signature_hex`);
  }
  if (signature.length !== 64) {
    throw new Error(`${kind}: invalid ed25519_signature_hex`);
  }
  if (!ed25519Verify(signature, hexToBytes(expectedDigestHex), publicKey)) {
    throw new Error(`${kind}: ed25519 signature verification failed`);
  }
}

/**
 * Validates, canonicalizes, and signs an authorization receipt with
 * Ed25519-over-SHA-256(canonical JSON).
 *
 * @param signingSeed - 32-byte Ed25519 seed (noble private key).
 */
export function signProtocolAuthorizationReceiptV1(
  signingSeed: Uint8Array,
  input: ProtocolAuthorizationReceiptInput,
): ProtocolAuthorizationReceiptV1 {
  ensureEd25519Sha512Sync();
  if (signingSeed.length !== 32) {
    throw new Error("protocol authorization receipt: signing key must be an ed25519 private key");
  }
  const normalized = normalizeProtocolAuthorizationReceiptV1(input);
  const digest = sha256Hex(marshalCanonicalAuthorizationReceipt(normalized));
  const signature = sign(hexToBytes(digest), signingSeed);
  const publicKey = getPublicKey(signingSeed);
  return {
    ...normalized,
    signing_algorithm: PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256,
    message_digest_sha256_hex: digest,
    signing_public_key_ed25519_hex: Buffer.from(publicKey).toString("hex"),
    ed25519_signature_hex: Buffer.from(signature).toString("hex"),
  };
}

/**
 * Validates, canonicalizes, and signs a settlement receipt with
 * Ed25519-over-SHA-256(canonical JSON).
 *
 * @param signingSeed - 32-byte Ed25519 seed (noble private key).
 */
export function signProtocolSettlementReceiptV1(
  signingSeed: Uint8Array,
  input: ProtocolSettlementReceiptInput,
): ProtocolSettlementReceiptV1 {
  ensureEd25519Sha512Sync();
  if (signingSeed.length !== 32) {
    throw new Error("protocol settlement receipt: signing key must be an ed25519 private key");
  }
  const normalized = normalizeProtocolSettlementReceiptV1(input);
  const digest = sha256Hex(marshalCanonicalSettlementReceipt(normalized));
  const signature = sign(hexToBytes(digest), signingSeed);
  const publicKey = getPublicKey(signingSeed);
  return {
    ...normalized,
    signing_algorithm: PROTOCOL_RECEIPT_SIGNING_ALGORITHM_ED25519_SHA256,
    message_digest_sha256_hex: digest,
    signing_public_key_ed25519_hex: Buffer.from(publicKey).toString("hex"),
    ed25519_signature_hex: Buffer.from(signature).toString("hex"),
  };
}

/**
 * Checks structure, canonical digest recompute, and detached Ed25519 signature.
 *
 * @returns The normalized authorization receipt on success.
 * @throws When structure, digest, or signature verification fails.
 */
export function verifyProtocolAuthorizationReceiptV1(
  input: ProtocolAuthorizationReceiptInput,
): ProtocolAuthorizationReceiptV1 {
  ensureEd25519Sha512Sync();
  const normalized = normalizeProtocolAuthorizationReceiptV1(input);
  const digest = sha256Hex(marshalCanonicalAuthorizationReceipt(normalized));
  verifySignedDigest(
    "protocol authorization receipt",
    normalized.signing_algorithm,
    normalized.message_digest_sha256_hex,
    normalized.signing_public_key_ed25519_hex,
    normalized.ed25519_signature_hex,
    digest,
  );
  return normalized;
}

/**
 * Checks structure, canonical digest recompute, and detached Ed25519 signature.
 *
 * @returns The normalized settlement receipt on success.
 * @throws When structure, digest, or signature verification fails.
 */
export function verifyProtocolSettlementReceiptV1(
  input: ProtocolSettlementReceiptInput,
): ProtocolSettlementReceiptV1 {
  ensureEd25519Sha512Sync();
  const normalized = normalizeProtocolSettlementReceiptV1(input);
  const digest = sha256Hex(marshalCanonicalSettlementReceipt(normalized));
  verifySignedDigest(
    "protocol settlement receipt",
    normalized.signing_algorithm,
    normalized.message_digest_sha256_hex,
    normalized.signing_public_key_ed25519_hex,
    normalized.ed25519_signature_hex,
    digest,
  );
  return normalized;
}
