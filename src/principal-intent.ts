/**
 * Principal intent creation signing for raw `predicate_dsl` (no managed-policy binding).
 * Matches `crates/harbor-intent-escrow/src/signing.rs` (`intent_creation_sign_bytes_raw`).
 */

import { sign, getPublicKey } from "@noble/ed25519";
import { ensureEd25519Sha512Sync } from "./ed25519-sync.js";
import { jsonValueDigest } from "./json-digest.js";
import {
  COMPLETION_CONTRACT_SIGN_VERSION,
  concatBytes,
  encodeBincodeString,
  encodeBincodeUuid,
  encodeFixed32,
  encodeU8,
  encodeVarintI64,
  encodeVarintU32,
} from "./bincode-wire.js";
import { validateUsdDenominatedSettlement } from "./mpp-commercial.js";

/** Tenant-configured settlement rail names. Clients may request a rail, not a destination. */
export type SettlementRail = "stripe_connect" | "stripe_ach_debit" | "stripe_mpp" | "x402_usdc_base";

const SETTLEMENT_RAIL_VALUES = new Set<SettlementRail>(["stripe_connect", "stripe_ach_debit", "stripe_mpp", "x402_usdc_base"]);

function validateSettlementRail(value: string): SettlementRail {
  if (!SETTLEMENT_RAIL_VALUES.has(value as SettlementRail)) {
    throw new Error(`settlementRail must be one of ${[...SETTLEMENT_RAIL_VALUES].join(", ")}`);
  }
  return value as SettlementRail;
}

function dslDigest(predicate: Record<string, unknown>): Uint8Array {
  return jsonValueDigest(predicate);
}

function allowedToolsDigest(tools: string[]): Uint8Array {
  const sorted = [...tools]
    .map((s) => s.trim().toLowerCase())
    .sort()
    .filter((v, i, a) => a.indexOf(v) === i);
  return jsonValueDigest(sorted);
}

function encodeU32(n: number): Uint8Array {
  return encodeVarintU32(n);
}

function encodeBincodeFixed32(bytes: Uint8Array): Uint8Array {
  return encodeFixed32(bytes);
}

/** Bincode payload for optional completion contract tail (wire format revision byte `2`). */
function encodeCompletionContractSignV1(input: {
  completionPresetId: string;
  vendorContractProvider: string;
  vendorApiVersion: string;
  vendorSchemaDigest: Uint8Array;
  canonicalSchemaDigest: Uint8Array;
}): Uint8Array {
  return concatBytes(
    encodeU8(COMPLETION_CONTRACT_SIGN_VERSION),
    encodeBincodeString(input.completionPresetId),
    encodeBincodeString(input.vendorContractProvider),
    encodeBincodeString(input.vendorApiVersion),
    encodeBincodeFixed32(input.vendorSchemaDigest),
    encodeBincodeFixed32(input.canonicalSchemaDigest),
  );
}

function digestHexToBytes(hexValue: string | undefined): Uint8Array {
  if (!hexValue || hexValue.trim() === "") {
    return new Uint8Array(32);
  }
  const trimmed = hexValue.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error("digest hex must be a 64-character hex string");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number.parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function appendCompletionContractSignExtension(
  base: Uint8Array,
  snapshot: CompletionContractSnapshot,
): Uint8Array {
  const extension = encodeCompletionContractSignV1({
    completionPresetId: snapshot.completionPresetId,
    vendorContractProvider: snapshot.vendorContractProvider ?? "",
    vendorApiVersion: snapshot.vendorApiVersion ?? "",
    vendorSchemaDigest: digestHexToBytes(snapshot.vendorSchemaDigestHex),
    canonicalSchemaDigest: digestHexToBytes(snapshot.canonicalSchemaDigestHex),
  });
  return concatBytes(base, extension);
}

export type CompletionContractSnapshot = {
  completionPresetId: string;
  vendorContractProvider?: string;
  vendorApiVersion?: string;
  vendorSchemaDigestHex?: string;
  canonicalSchemaDigestHex: string;
};

function encodeIntentCreationSign(input: {
  version: 4 | 5 | 6 | 7;
  tenantId: string;
  intentId: string;
  principalDid: string;
  payeeDid: string;
  amountCents: number;
  currency: string;
  deadlineRfc3339: string;
  budgetDigest: Uint8Array;
  evidenceSchemaDigest: Uint8Array;
  predicateDslDigest: Uint8Array;
  predicateRef: string;
  allowedToolsDigest: Uint8Array;
  settlementRail: SettlementRail;
  policyTemplateId?: string;
  policyVersionSeq?: number;
  policyContentDigest?: Uint8Array;
  payeePubkey?: Uint8Array;
}): Uint8Array {
  const base = concatBytes(
    encodeU8(input.version),
    encodeBincodeString(input.tenantId),
    encodeBincodeUuid(input.intentId),
    encodeBincodeString(input.principalDid),
    encodeBincodeString(input.payeeDid),
    encodeVarintI64(input.amountCents),
    encodeBincodeString(input.currency),
    encodeBincodeString(input.deadlineRfc3339),
    input.budgetDigest,
    input.evidenceSchemaDigest,
    input.predicateDslDigest,
    encodeBincodeString(input.predicateRef),
    input.allowedToolsDigest,
    encodeBincodeString(input.settlementRail),
  );
  if (input.version === 4) {
    return base;
  }
  if (input.version === 6) {
    if (input.payeePubkey === undefined) {
      throw new Error("payeePubkey is required for signing version 6");
    }
    return concatBytes(base, encodeBincodeFixed32(input.payeePubkey));
  }
  if (
    input.policyTemplateId === undefined ||
    input.policyVersionSeq === undefined ||
    input.policyContentDigest === undefined
  ) {
    throw new Error("policy binding fields are required for signing version 5 or 7");
  }
  const withPolicy = concatBytes(
    base,
    encodeBincodeString(input.policyTemplateId),
    encodeU32(input.policyVersionSeq),
    encodeBincodeFixed32(input.policyContentDigest),
  );
  if (input.version === 5) {
    return withPolicy;
  }
  if (input.payeePubkey === undefined) {
    throw new Error("payeePubkey is required for signing version 7");
  }
  return concatBytes(withPolicy, encodeBincodeFixed32(input.payeePubkey));
}

export function intentCreationSignBytesRaw(input: {
  tenantId: string;
  intentId: string;
  principalDid: string;
  payeeDid: string;
  payeePubkeyBytes: Uint8Array;
  amountCents: number;
  currency: string;
  deadlineRfc3339: string;
  budget: Record<string, unknown>;
  evidenceSchema: Record<string, unknown>;
  predicate: Record<string, unknown>;
  predicateRef: string;
  allowedTools: string[];
  settlementRail: SettlementRail;
  completionContract?: CompletionContractSnapshot;
}): Uint8Array {
  if (input.payeePubkeyBytes.length !== 32) {
    throw new Error("payeePubkeyBytes must be 32 bytes");
  }
  const budgetDigest = jsonValueDigest(input.budget);
  const evidenceSchemaDigest = jsonValueDigest(input.evidenceSchema);
  const predicateDslDigest = dslDigest(input.predicate);
  const allowedDigest = allowedToolsDigest(input.allowedTools);
  const base = encodeIntentCreationSign({
    version: 6,
    tenantId: input.tenantId,
    intentId: input.intentId,
    principalDid: input.principalDid,
    payeeDid: input.payeeDid,
    amountCents: input.amountCents,
    currency: input.currency,
    deadlineRfc3339: input.deadlineRfc3339,
    budgetDigest,
    evidenceSchemaDigest,
    predicateDslDigest,
    predicateRef: input.predicateRef,
    allowedToolsDigest: allowedDigest,
    settlementRail: input.settlementRail,
    payeePubkey: input.payeePubkeyBytes,
  });
  if (!input.completionContract) {
    return base;
  }
  return appendCompletionContractSignExtension(base, input.completionContract);
}

export type PolicyBindingRef = {
  templateId: string;
  versionSeq: number;
};

export type PublishedPolicyHead = {
  templateId: string;
  versionSeq: number;
  materializedPredicate: Record<string, unknown>;
  policyContentDigestHex: string;
};

function parseDigestHex(hexValue: string): Uint8Array {
  const trimmed = hexValue.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{64}$/.test(trimmed)) {
    throw new Error("policyContentDigestHex must be a 64-character hex string");
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number.parseInt(trimmed.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Bincode payload for managed-policy intent creation (wire format revision byte `5`). */
export function intentCreationSignBytesWithPolicyBinding(input: {
  tenantId: string;
  intentId: string;
  principalDid: string;
  payeeDid: string;
  payeePubkeyBytes: Uint8Array;
  amountCents: number;
  currency: string;
  deadlineRfc3339: string;
  budget: Record<string, unknown>;
  evidenceSchema: Record<string, unknown>;
  materializedPredicate: Record<string, unknown>;
  predicateRef: string;
  allowedTools: string[];
  settlementRail: SettlementRail;
  policyBinding: PolicyBindingRef;
  policyContentDigestHex: string;
  completionContract?: CompletionContractSnapshot;
}): Uint8Array {
  if (input.payeePubkeyBytes.length !== 32) {
    throw new Error("payeePubkeyBytes must be 32 bytes");
  }
  const budgetDigest = jsonValueDigest(input.budget);
  const evidenceSchemaDigest = jsonValueDigest(input.evidenceSchema);
  const predicateDslDigest = dslDigest(input.materializedPredicate);
  const allowedDigest = allowedToolsDigest(input.allowedTools);
  const base = encodeIntentCreationSign({
    version: 7,
    tenantId: input.tenantId,
    intentId: input.intentId,
    principalDid: input.principalDid,
    payeeDid: input.payeeDid,
    amountCents: input.amountCents,
    currency: input.currency,
    deadlineRfc3339: input.deadlineRfc3339,
    budgetDigest,
    evidenceSchemaDigest,
    predicateDslDigest,
    predicateRef: input.predicateRef,
    allowedToolsDigest: allowedDigest,
    settlementRail: input.settlementRail,
    policyTemplateId: input.policyBinding.templateId,
    policyVersionSeq: input.policyBinding.versionSeq,
    policyContentDigest: parseDigestHex(input.policyContentDigestHex),
    payeePubkey: input.payeePubkeyBytes,
  });
  if (!input.completionContract) {
    return base;
  }
  return appendCompletionContractSignExtension(base, input.completionContract);
}

export type BuildSignedCreateIntentWithPolicyBindingParams = Omit<
  BuildSignedCreateIntentParams,
  "predicate"
> & {
  policyBinding: PolicyBindingRef;
  publishedPolicyHead: PublishedPolicyHead;
  completionPresetId?: string;
  completionContract?: CompletionContractSnapshot;
};

/**
 * Build a Harbor `POST /intents` JSON body with signing v5 and a published managed-policy head.
 */
export function buildSignedCreateIntentBodyWithPolicyBinding(
  params: BuildSignedCreateIntentWithPolicyBindingParams,
): Record<string, unknown> {
  if (params.principalSigningSeed.length !== 32) {
    throw new Error("principalSigningSeed must be 32 bytes");
  }
  if (params.payeeSigningSeed.length !== 32) {
    throw new Error("payeeSigningSeed must be 32 bytes");
  }
  if (params.allowedTools.length === 0) {
    throw new Error("allowedTools must be non-empty");
  }
  const settlementRail = validateSettlementRail(params.settlementRail);
  validateUsdDenominatedSettlement(settlementRail, params.currency);
  const predicateRef = params.predicateRef ?? "";
  const head = params.publishedPolicyHead;
  if (head.templateId !== params.policyBinding.templateId || head.versionSeq !== params.policyBinding.versionSeq) {
    throw new Error("publishedPolicyHead must match policyBinding template_id and version_seq");
  }
  ensureEd25519Sha512Sync();
  const payeePub = getPublicKey(params.payeeSigningSeed);
  const msg = intentCreationSignBytesWithPolicyBinding({
    tenantId: params.tenantId,
    intentId: params.intentId,
    principalDid: params.principalDid,
    payeeDid: params.payeeDid,
    payeePubkeyBytes: payeePub,
    amountCents: params.amountCents,
    currency: params.currency,
    deadlineRfc3339: params.deadlineRfc3339,
    budget: params.budget,
    evidenceSchema: params.evidenceSchema,
    materializedPredicate: head.materializedPredicate,
    predicateRef,
    allowedTools: params.allowedTools,
    settlementRail,
    policyBinding: params.policyBinding,
    policyContentDigestHex: head.policyContentDigestHex,
    completionContract: params.completionContract,
  });
  const sig = sign(msg, params.principalSigningSeed);
  const pub = getPublicKey(params.principalSigningSeed);
  const body: Record<string, unknown> = {
    intent_id: params.intentId,
    principal_did: params.principalDid,
    principal_pubkey: bytesToBase64(pub),
    principal_signature: bytesToBase64(sig),
    payee_did: params.payeeDid,
    payee_pubkey: bytesToBase64(payeePub),
    budget: params.budget,
    currency: params.currency,
    amount_cents: params.amountCents,
    evidence_schema: params.evidenceSchema,
    deadline: params.deadlineRfc3339,
    settlement_rail: settlementRail,
    signing_version: 7,
    policy_binding: {
      template_id: params.policyBinding.templateId,
      version_seq: params.policyBinding.versionSeq,
    },
    allowed_tools: params.allowedTools,
  };
  if (predicateRef.trim() !== "") {
    body.predicate_ref = predicateRef;
  }
  if (params.completionPresetId?.trim()) {
    body.completion_preset_id = params.completionPresetId.trim();
  }
  return body;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

export type BuildSignedCreateIntentParams = {
  tenantId: string;
  intentId: string;
  principalDid: string;
  principalSigningSeed: Uint8Array;
  payeeDid: string;
  payeeSigningSeed: Uint8Array;
  budget: Record<string, unknown>;
  predicate: Record<string, unknown>;
  currency: string;
  amountCents: number;
  evidenceSchema: Record<string, unknown>;
  deadlineRfc3339: string;
  allowedTools: string[];
  predicateRef?: string;
  /** Rail request for the new intent. Harbor resolves the destination server-side. */
  settlementRail: SettlementRail;
  completionPresetId?: string;
  completionContract?: CompletionContractSnapshot;
};

/**
 * Build a Harbor `POST /intents` JSON body with principal Ed25519 detached signature.
 * `settlementRail` is included in the signature; destinations remain tenant-owned server-side.
 */
export function buildSignedCreateIntentBody(params: BuildSignedCreateIntentParams): Record<string, unknown> {
  if (params.principalSigningSeed.length !== 32) {
    throw new Error("principalSigningSeed must be 32 bytes");
  }
  if (params.payeeSigningSeed.length !== 32) {
    throw new Error("payeeSigningSeed must be 32 bytes");
  }
  if (params.allowedTools.length === 0) {
    throw new Error("allowedTools must be non-empty");
  }
  const settlementRail = validateSettlementRail(params.settlementRail);
  validateUsdDenominatedSettlement(settlementRail, params.currency);
  const predicateRef = params.predicateRef ?? "";
  ensureEd25519Sha512Sync();
  const payeePub = getPublicKey(params.payeeSigningSeed);
  const msg = intentCreationSignBytesRaw({
    tenantId: params.tenantId,
    intentId: params.intentId,
    principalDid: params.principalDid,
    payeeDid: params.payeeDid,
    payeePubkeyBytes: payeePub,
    amountCents: params.amountCents,
    currency: params.currency,
    deadlineRfc3339: params.deadlineRfc3339,
    budget: params.budget,
    evidenceSchema: params.evidenceSchema,
    predicate: params.predicate,
    predicateRef,
    allowedTools: params.allowedTools,
    settlementRail,
    completionContract: params.completionContract,
  });
  const sig = sign(msg, params.principalSigningSeed);
  const pub = getPublicKey(params.principalSigningSeed);
  const body: Record<string, unknown> = {
    intent_id: params.intentId,
    principal_did: params.principalDid,
    principal_pubkey: bytesToBase64(pub),
    principal_signature: bytesToBase64(sig),
    payee_did: params.payeeDid,
    payee_pubkey: bytesToBase64(payeePub),
    budget: params.budget,
    currency: params.currency,
    amount_cents: params.amountCents,
    evidence_schema: params.evidenceSchema,
    deadline: params.deadlineRfc3339,
    predicate_dsl: params.predicate,
    settlement_rail: settlementRail,
    signing_version: 6,
    policy_binding: null,
    allowed_tools: params.allowedTools,
  };
  if (predicateRef.trim() !== "") {
    body.predicate_ref = predicateRef;
  }
  if (params.completionPresetId?.trim()) {
    body.completion_preset_id = params.completionPresetId.trim();
  }
  return body;
}
