import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

import type { PaybondToolRegistry } from "../agent/registry.js";
import {
  policyToIntentCreateInput,
  type PaybondPolicyIntentCreateInput,
  type PaybondPolicyIntentCreateOverrides,
} from "./intent-spec.js";
import {
  mergePaybondPolicies,
  toEffectivePolicyDocument,
  type PolicyMergeOptions,
  type PolicyMergeResult,
} from "./merge.js";
import { parsePolicyDocumentText } from "./parse-text.js";
import { policyToToolRegistry } from "./registry.js";
import {
  isPaybondPolicyDocumentV2,
  isPaybondPolicyOverlay,
  parsePaybondPolicyDocument,
  type PaybondPolicyDocument,
  type PaybondPolicyDocumentV1,
  type PaybondPolicyDocumentV2,
  parsePaybondPolicyDocumentV1,
} from "./schema.js";
import {
  policySandboxBootstrap,
  type PaybondPolicySandboxBootstrapOptions,
} from "./sandbox-bootstrap.js";
import { PolicyValidator, type PolicyValidatorOptions, type PolicyValidatorResult } from "./validate.js";
import {
  validatePolicyRemote,
  validatePolicyPayloadRemote,
  type PolicyRemoteValidateClient,
  type PolicyRemoteValidateOptions,
  type PolicyRemoteValidateResult,
} from "./validate-remote.js";
import {
  resolvePolicyEffectiveRemote,
  type PolicyEffectiveResolveClient,
  type PolicyEffectiveResolveResult,
} from "./load-effective.js";
import type { PaybondRunBindingSandboxBootstrapInput } from "../agent/types.js";

export type PaybondPolicyLoadEffectiveResult = {
  policy: PaybondPolicy;
  report: PolicyMergeResult["report"];
  effectivePolicyDigest: string;
  effectivePolicyVersion: string;
  orgBaseVersionSeq: number;
  orgBaseContentDigest: string;
  unchanged?: boolean;
};

export type PaybondPolicyLoadSource = string | PaybondPolicyDocumentV1 | PaybondPolicyDocument | Record<string, unknown>;

/**
 * Portable policy-as-code document loaded from `paybond.policy.yaml` or an in-memory object.
 * Drives tool registry construction and production intent create alignment.
 */
export class PaybondPolicy {
  readonly document: PaybondPolicyDocumentV1;
  readonly source?: string;

  private constructor(document: PaybondPolicyDocumentV1, source?: string) {
    this.document = document;
    this.source = source;
  }

  /** Policy name from the document (`name` field). */
  get name(): string {
    return this.document.name;
  }

  /** Whether unregistered side-effecting tools should fail closed at intercept time. */
  get defaultDeny(): boolean {
    return this.document.default_deny;
  }

  /** Optional intent section from the policy file. */
  get intent(): PaybondPolicyDocumentV1["intent"] {
    return this.document.intent;
  }

  /**
   * Load and validate a policy from a file path or pre-parsed document object.
   * File paths accept JSON (`.json`) or YAML (`.yaml` / `.yml`).
   */
  static async load(source: PaybondPolicyLoadSource): Promise<PaybondPolicy> {
    if (typeof source === "string") {
      const document = await PaybondPolicy.loadDocument(source);
      const effective = await PaybondPolicy.resolveEffectiveDocument(document, source);
      return new PaybondPolicy(effective, source);
    }
    const document = parsePaybondPolicyDocument(source);
    const effective = await PaybondPolicy.resolveEffectiveDocument(document);
    return new PaybondPolicy(effective);
  }

  private static async resolveEffectiveDocument(
    document: PaybondPolicyDocument,
    sourcePath?: string,
  ): Promise<PaybondPolicyDocumentV1> {
    if (isPaybondPolicyDocumentV2(document) && isPaybondPolicyOverlay(document)) {
      const basePath = document.extends?.base_policy;
      if (!basePath) {
        return toEffectivePolicyDocument(document);
      }
      const resolvedBase = sourcePath
        ? resolve(dirname(sourcePath), basePath)
        : basePath;
      const baseDoc = await PaybondPolicy.loadDocument(resolvedBase);
      return mergePaybondPolicies(baseDoc, document).effective;
    }
    return toEffectivePolicyDocument(document);
  }

  /**
   * Resolve merged effective policy via Gateway org-policy inheritance.
   * Production tenants should prefer this over {@link mergeLocal}.
   */
  static async loadEffective(options: {
    overlay: PaybondPolicyLoadSource;
    gateway: PolicyEffectiveResolveClient;
  }): Promise<PaybondPolicyLoadEffectiveResult> {
    const overlayDoc = await PaybondPolicy.loadDocument(options.overlay);
    if (!isPaybondPolicyDocumentV2(overlayDoc) || !isPaybondPolicyOverlay(overlayDoc)) {
      throw new Error("overlay must be a v2 tenant policy with extends");
    }
    const resolved = await resolvePolicyEffectiveRemote(overlayDoc, options.gateway);
    const effective = parsePaybondPolicyDocumentV1(resolved.effective_policy);
    return {
      policy: PaybondPolicy.fromDocument(effective),
      report: resolved.merge_report,
      effectivePolicyDigest: resolved.effective_policy_digest,
      effectivePolicyVersion: resolved.effective_policy_version,
      orgBaseVersionSeq: resolved.org_base_version_seq,
      orgBaseContentDigest: resolved.org_base_content_digest,
      ...(resolved.unchanged ? { unchanged: true } : {}),
    };
  }

  /** Synchronous variant for pre-parsed effective (v1) document objects only. */
  static fromDocument(document: PaybondPolicyDocumentV1): PaybondPolicy {
    return new PaybondPolicy(document);
  }

  /**
   * Offline merge of org base + tenant overlay into an effective v1 policy.
   * Best-effort for CI; production should use Gateway effective resolution.
   */
  static async mergeLocal(options: {
    base: PaybondPolicyLoadSource;
    overlay: PaybondPolicyLoadSource;
    merge?: PolicyMergeOptions;
  }): Promise<PolicyMergeResult & { policy: PaybondPolicy }> {
    const baseDoc = await PaybondPolicy.loadDocument(options.base);
    const overlayDoc = await PaybondPolicy.loadDocument(options.overlay);
    if (!isPaybondPolicyDocumentV2(overlayDoc) || !isPaybondPolicyOverlay(overlayDoc)) {
      throw new Error("overlay must be a v2 tenant policy with extends");
    }
    const merged = mergePaybondPolicies(baseDoc, overlayDoc, options.merge);
    return {
      ...merged,
      policy: PaybondPolicy.fromDocument(merged.effective),
    };
  }

  private static async loadDocument(source: PaybondPolicyLoadSource): Promise<PaybondPolicyDocument> {
    if (typeof source === "string") {
      const text = await readFile(source, "utf8");
      const raw = parsePolicyDocumentText(text, source);
      return parsePaybondPolicyDocument(raw);
    }
    return parsePaybondPolicyDocument(source);
  }

  /** Load a raw overlay document payload for server-side inheritance validation. */
  static async loadOverlayPayload(source: PaybondPolicyLoadSource): Promise<Record<string, unknown>> {
    if (typeof source === "string") {
      const text = await readFile(source, "utf8");
      const raw = parsePolicyDocumentText(text, source);
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
        throw new Error("overlay must be a JSON or YAML object");
      }
      return raw as Record<string, unknown>;
    }
    if (typeof source === "object" && source !== null && !Array.isArray(source)) {
      return source as Record<string, unknown>;
    }
    throw new Error("overlay must be a file path or raw overlay object");
  }

  /**
   * Validate a tenant overlay with server-side org-base merge
   * (`POST /v1/policy/validate?resolve_inheritance=1`).
   */
  static async validateOverlayRemote(
    overlay: PaybondPolicyLoadSource,
    gateway: PolicyRemoteValidateClient,
    options?: PolicyRemoteValidateOptions,
  ): Promise<PolicyRemoteValidateResult> {
    const payload = await PaybondPolicy.loadOverlayPayload(overlay);
    return validatePolicyPayloadRemote(payload, gateway, {
      ...options,
      resolveInheritance: true,
    });
  }

  /** Build the tool registry consumed by agent middleware. */
  toToolRegistry(): PaybondToolRegistry {
    return policyToToolRegistry(this.document);
  }

  /**
   * Build params for {@link PaybondIntents.createWithPolicyBinding} from policy intent alignment
   * plus caller signing context and a published managed-policy head.
   */
  toIntentCreateInput(
    overrides: PaybondPolicyIntentCreateOverrides,
  ): PaybondPolicyIntentCreateInput {
    return policyToIntentCreateInput(this.document, overrides);
  }

  /** Run client-side alignment checks (registry, presets, optional gateway template lookup). */
  validate(options?: PolicyValidatorOptions): Promise<PolicyValidatorResult> {
    return PolicyValidator.validateDocument(this.document, options);
  }

  /**
   * Validate this policy against the tenant-scoped Gateway registry (`POST /v1/policy/validate`).
   * Requires a logged-in Gateway Harbor client from `paybond.open()`.
   */
  validateRemote(
    gateway: PolicyRemoteValidateClient,
    options?: PolicyRemoteValidateOptions,
  ): Promise<PolicyRemoteValidateResult> {
    return validatePolicyRemote(this.document, gateway, options);
  }

  /** Build sandbox bootstrap input for {@link PaybondAgentRun.bind} from this policy. */
  sandboxBootstrap(
    options: PaybondPolicySandboxBootstrapOptions = {},
  ): PaybondRunBindingSandboxBootstrapInput {
    return policySandboxBootstrap(this.document, options);
  }
}
