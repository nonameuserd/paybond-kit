import { z } from "zod";

/** Supported `paybond.policy.yaml` schema revisions. */
export const PAYBOND_POLICY_SCHEMA_VERSION = 1 as const;
export const PAYBOND_POLICY_SCHEMA_VERSION_V2 = 2 as const;

const IDENTIFIER_PATTERN = /^[a-z0-9_]{1,64}$/;
const POLICY_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/;
const TOOL_NAME_PATTERN = /^[a-z][a-z0-9_.-]{0,127}$/;
const JSON_PATH_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_.]*$/;
const HEAD_DIGEST_PATTERN = /^sha256:[0-9a-fA-F]{64}$/;
const CURRENCY_PATTERN = /^[a-z]{3}$/;
const ORG_ID_PATTERN = /^org_[a-z][a-z0-9_]{0,57}$/;

const identifierSchema = z
  .string()
  .regex(IDENTIFIER_PATTERN, "must be snake_case identifier (1-64 chars)");

const toolNameSchema = z
  .string()
  .regex(TOOL_NAME_PATTERN, "must be a lowercase tool name (dots allowed)");

const jsonPathSchema = z
  .string()
  .regex(JSON_PATH_PATTERN, "must be a dot-separated JSON path");

const headDigestSchema = z
  .string()
  .regex(HEAD_DIGEST_PATTERN, "must be sha256:<64-hex>");

const orgIdSchema = z
  .string()
  .regex(ORG_ID_PATTERN, "must be an org identifier (org_<snake_case>)");

function refineSpendExclusivity(
  entry: { max_spend_cents?: number; spend_from_args?: string },
  ctx: z.RefinementCtx,
  pathPrefix: (string | number)[],
): void {
  if (
    entry.max_spend_cents !== undefined &&
    entry.spend_from_args !== undefined
  ) {
    ctx.addIssue({
      code: "custom",
      path: [...pathPrefix, "spend_from_args"],
      message: "max_spend_cents and spend_from_args are mutually exclusive",
    });
  }
}

function refineSideEffectingEvidence(
  entry: { side_effecting?: boolean; evidence_preset?: string },
  ctx: z.RefinementCtx,
  pathPrefix: (string | number)[],
): void {
  if (entry.side_effecting && !entry.evidence_preset) {
    ctx.addIssue({
      code: "custom",
      path: [...pathPrefix, "evidence_preset"],
      message: "side-effecting tools must declare evidence_preset",
    });
  }
}

const policyToolEntrySchema = z
  .object({
    side_effecting: z.boolean(),
    max_spend_cents: z.number().int().nonnegative().optional(),
    spend_from_args: jsonPathSchema.optional(),
    evidence_preset: identifierSchema.optional(),
    vendor_pack: identifierSchema.optional(),
    operation: z.string().min(1).max(128).optional(),
  })
  .strict()
  .superRefine((entry, ctx) => {
    refineSideEffectingEvidence(entry, ctx, []);
    refineSpendExclusivity(entry, ctx, []);
  });

const policyToolOverrideEntrySchema = z
  .object({
    side_effecting: z.boolean().optional(),
    max_spend_cents: z.number().int().nonnegative().optional(),
    spend_from_args: jsonPathSchema.optional(),
    evidence_preset: identifierSchema.optional(),
    vendor_pack: identifierSchema.optional(),
    operation: z.string().min(1).max(128).optional(),
  })
  .strict()
  .superRefine((entry, ctx) => {
    if (Object.keys(entry).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "tool override must set at least one field",
      });
    }
    refineSideEffectingEvidence(entry, ctx, []);
    refineSpendExclusivity(entry, ctx, []);
  });

const policyBindingSchema = z
  .object({
    template_id: identifierSchema,
    version_seq: z.number().int().positive().optional(),
    head_digest: headDigestSchema.optional(),
  })
  .strict();

const policyBindingOverrideSchema = z
  .object({
    template_id: identifierSchema.optional(),
    version_seq: z.number().int().positive().optional(),
    head_digest: headDigestSchema.optional(),
  })
  .strict()
  .superRefine((binding, ctx) => {
    if (Object.keys(binding).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "policy_binding override must set at least one field",
      });
    }
  });

const policyBudgetSchema = z
  .object({
    currency: z.string().regex(CURRENCY_PATTERN, "must be a lowercase ISO-4217 code"),
    max_spend_usd: z.number().nonnegative().optional(),
  })
  .passthrough();

const policyIntentSchema = z
  .object({
    policy_binding: policyBindingSchema.optional(),
    budget: policyBudgetSchema.optional(),
    allowed_tools: z.array(toolNameSchema).optional(),
  })
  .strict();

const policyAdapterSchema = z
  .object({
    deny_provider_executed_tools: z.boolean().optional(),
  })
  .strict()
  .superRefine((adapter, ctx) => {
    if (Object.keys(adapter).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "adapter must set at least one field",
      });
    }
  });

const policyAdapterOverrideSchema = z
  .object({
    deny_provider_executed_tools: z.boolean().optional(),
  })
  .strict()
  .superRefine((adapter, ctx) => {
    if (Object.keys(adapter).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "adapter override must set at least one field",
      });
    }
  });

const policyIntentOverrideSchema = z
  .object({
    policy_binding: policyBindingOverrideSchema.optional(),
    budget: policyBudgetSchema.optional(),
    allowed_tools: z.array(toolNameSchema).optional(),
  })
  .strict()
  .superRefine((intent, ctx) => {
    if (Object.keys(intent).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "intent override must set at least one field",
      });
    }
  });

const policyExtendsSchema = z
  .object({
    org_policy_id: z
      .string()
      .regex(POLICY_NAME_PATTERN, "must be a lowercase policy name"),
    org_id: orgIdSchema,
    base_digest: headDigestSchema.optional(),
    base_policy: z.string().min(1).max(512).optional(),
  })
  .strict();

const policyOverridesSchema = z
  .object({
    default_deny: z.boolean().optional(),
    tools: z.record(toolNameSchema, policyToolOverrideEntrySchema).optional(),
    intent: policyIntentOverrideSchema.optional(),
    adapter: policyAdapterOverrideSchema.optional(),
  })
  .strict()
  .superRefine((overrides, ctx) => {
    if (
      overrides.default_deny === undefined &&
      !overrides.tools &&
      !overrides.intent &&
      !overrides.adapter
    ) {
      ctx.addIssue({
        code: "custom",
        path: [],
        message: "overrides must set default_deny, tools, intent, and/or adapter",
      });
    }
  });

export const paybondPolicyDocumentV1Schema = z
  .object({
    version: z.literal(PAYBOND_POLICY_SCHEMA_VERSION),
    name: z.string().regex(POLICY_NAME_PATTERN, "must be a lowercase policy name"),
    default_deny: z.boolean(),
    tools: z
      .record(toolNameSchema, policyToolEntrySchema)
      .refine((tools) => Object.keys(tools).length > 0, {
        message: "tools must declare at least one entry",
      }),
    intent: policyIntentSchema.optional(),
    adapter: policyAdapterSchema.optional(),
  })
  .strict();

export const paybondPolicyDocumentV2Schema = z
  .object({
    version: z.literal(PAYBOND_POLICY_SCHEMA_VERSION_V2),
    name: z.string().regex(POLICY_NAME_PATTERN, "must be a lowercase policy name"),
    default_deny: z.boolean(),
    extends: policyExtendsSchema.optional(),
    overrides: policyOverridesSchema.optional(),
    tools: z.record(toolNameSchema, policyToolEntrySchema),
    intent: policyIntentSchema.optional(),
    adapter: policyAdapterSchema.optional(),
  })
  .strict()
  .superRefine((document, ctx) => {
    if (!document.extends && Object.keys(document.tools).length === 0) {
      ctx.addIssue({
        code: "custom",
        path: ["tools"],
        message: "tools must declare at least one entry when extends is omitted",
      });
    }
  });

export type PaybondPolicyToolEntry = z.infer<typeof policyToolEntrySchema>;
export type PaybondPolicyToolOverrideEntry = z.infer<typeof policyToolOverrideEntrySchema>;
export type PaybondPolicyBinding = z.infer<typeof policyBindingSchema>;
export type PaybondPolicyBindingOverride = z.infer<typeof policyBindingOverrideSchema>;
export type PaybondPolicyBudget = z.infer<typeof policyBudgetSchema>;
export type PaybondPolicyIntentSection = z.infer<typeof policyIntentSchema>;
export type PaybondPolicyAdapterSection = z.infer<typeof policyAdapterSchema>;
export type PaybondPolicyAdapterOverrideSection = z.infer<typeof policyAdapterOverrideSchema>;
export type PaybondPolicyIntentOverrideSection = z.infer<typeof policyIntentOverrideSchema>;
export type PaybondPolicyExtends = z.infer<typeof policyExtendsSchema>;
export type PaybondPolicyOverrides = z.infer<typeof policyOverridesSchema>;
export type PaybondPolicyDocumentV1 = z.infer<typeof paybondPolicyDocumentV1Schema>;
export type PaybondPolicyDocumentV2 = z.infer<typeof paybondPolicyDocumentV2Schema>;
export type PaybondPolicyDocument = PaybondPolicyDocumentV1 | PaybondPolicyDocumentV2;

export type PaybondPolicyValidationIssue = {
  path: string;
  code: string;
  message: string;
};

/** Raised when a policy document fails schema validation. */
export class PaybondPolicyValidationError extends Error {
  readonly issues: PaybondPolicyValidationIssue[];

  constructor(message: string, issues: PaybondPolicyValidationIssue[] = []) {
    super(message);
    this.name = "PaybondPolicyValidationError";
    this.issues = issues;
  }
}

function zodIssuesToPolicyIssues(
  issues: z.ZodIssue[],
): PaybondPolicyValidationIssue[] {
  return issues.map((issue) => ({
    path: issue.path.length > 0 ? issue.path.map(String).join(".") : "(root)",
    code: issue.code,
    message: issue.message,
  }));
}

function parseWithSchema<T>(
  schema: z.ZodType<T>,
  raw: unknown,
): T {
  const result = schema.safeParse(raw);
  if (!result.success) {
    const issues = zodIssuesToPolicyIssues(result.error.issues);
    const summary = issues.map((issue) => `${issue.path}: ${issue.message}`).join("; ");
    throw new PaybondPolicyValidationError(
      summary || "invalid paybond.policy.yaml document",
      issues,
    );
  }
  return result.data;
}

/**
 * Parse and validate a raw policy document (already-decoded JSON or YAML object).
 * Accepts v1 flat policies and v2 org-base or tenant-overlay documents.
 */
export function parsePaybondPolicyDocument(raw: unknown): PaybondPolicyDocument {
  if (typeof raw !== "object" || raw === null) {
    throw new PaybondPolicyValidationError("(root) must be an object");
  }
  const version = (raw as { version?: unknown }).version;
  if (version === PAYBOND_POLICY_SCHEMA_VERSION) {
    return parseWithSchema(paybondPolicyDocumentV1Schema, raw);
  }
  if (version === PAYBOND_POLICY_SCHEMA_VERSION_V2) {
    return parseWithSchema(paybondPolicyDocumentV2Schema, raw);
  }
  throw new PaybondPolicyValidationError(
    `version must be ${PAYBOND_POLICY_SCHEMA_VERSION} or ${PAYBOND_POLICY_SCHEMA_VERSION_V2}`,
    [{ path: "version", code: "invalid_literal", message: "unsupported policy schema version" }],
  );
}

/** Parse a v1-only policy document. */
export function parsePaybondPolicyDocumentV1(raw: unknown): PaybondPolicyDocumentV1 {
  return parseWithSchema(paybondPolicyDocumentV1Schema, raw);
}

/** Parse a v2 policy document (org base or tenant overlay). */
export function parsePaybondPolicyDocumentV2(raw: unknown): PaybondPolicyDocumentV2 {
  return parseWithSchema(paybondPolicyDocumentV2Schema, raw);
}

/** Type guard for an already-validated v1 policy document. */
export function isPaybondPolicyDocumentV1(value: unknown): value is PaybondPolicyDocumentV1 {
  return paybondPolicyDocumentV1Schema.safeParse(value).success;
}

/** Type guard for an already-validated v2 policy document. */
export function isPaybondPolicyDocumentV2(value: unknown): value is PaybondPolicyDocumentV2 {
  return paybondPolicyDocumentV2Schema.safeParse(value).success;
}

/** True when a v2 document is a tenant overlay (declares extends). */
export function isPaybondPolicyOverlay(document: PaybondPolicyDocumentV2): boolean {
  return document.extends !== undefined;
}
