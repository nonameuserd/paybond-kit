import fs from "node:fs/promises";
import path from "node:path";

import {
  getCompletionPreset,
  jsonLiteral,
  listCompletionPresetIds,
  type CompletionPreset,
} from "./completion-catalog.js";
import {
  isVendorPack,
  resolveCompletionPreset,
  vendorEvidenceSchema,
} from "./completion-resolve.js";

declare const process: {
  argv: string[];
  cwd(): string;
  exitCode?: number;
  stderr: { write(chunk: string): boolean };
  stdout: { write(chunk: string): boolean };
};

export type CompletionInitOptions = {
  preset: string;
  out: string;
  force: boolean;
};

function usage(): string {
  const presets = listCompletionPresetIds().join("|");
  return [
    `Usage: paybond init completion --preset <${presets}> [--out <path>] [--force]`,
    "",
    "Scaffolds a completion evidence helper aligned with the shared preset catalog.",
  ].join("\n");
}

export function parseCompletionInitArgs(argv: string[]): CompletionInitOptions | "help" {
  let preset = "";
  let out = "";
  let force = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      return "help";
    }
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--preset") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || !listCompletionPresetIds().includes(raw)) {
        throw new Error("invalid --preset");
      }
      preset = raw;
      continue;
    }
    if (arg === "--out") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || raw.startsWith("-")) {
        throw new Error("invalid --out");
      }
      out = raw;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  if (!preset) {
    throw new Error("missing --preset");
  }
  if (!out) {
    out = preset === "cost_and_completion"
      ? "paybond-paid-tool-guard.ts"
      : `paybond-completion-${preset.replaceAll("_", "-")}.ts`;
  }
  return { preset, out, force };
}

function schemaPropertyToTsType(schema: Record<string, unknown>): string {
  const type = schema.type;
  if (type === "integer" || type === "number") {
    return "number";
  }
  if (type === "array") {
    const items = schema.items as Record<string, unknown> | undefined;
    if (items?.type === "string") {
      return "string[]";
    }
    return "unknown[]";
  }
  return "string";
}

function buildTsFieldLines(schema: Record<string, unknown>): string[] {
  const properties = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
  const required = Array.isArray(schema.required)
    ? (schema.required as string[])
    : Object.keys(properties);
  return required.map((field) => {
    const prop = properties[field] ?? { type: "string" };
    return `  ${field}: ${schemaPropertyToTsType(prop)};`;
  });
}

function buildTsFieldLinesFromPreset(preset: CompletionPreset): string[] {
  const vendorSchema = vendorEvidenceSchema(preset);
  if (isVendorPack(preset) && vendorSchema) {
    return buildTsFieldLines(vendorSchema);
  }
  return buildTsFieldLines(preset.evidence_schema);
}


function evidenceFieldComments(preset: CompletionPreset): string[] {
  const vendorSchema = vendorEvidenceSchema(preset);
  const schemaForRequired = vendorSchema ?? preset.evidence_schema;
  const required = Array.isArray(schemaForRequired.required)
    ? (schemaForRequired.required as string[])
    : [];
  const lines = [
    `// Preset: ${preset.preset_id} (${preset.title})`,
    isVendorPack(preset)
      ? `// Vendor pack over archetype: ${preset.archetype_preset_id}`
      : `// Harbor template: ${preset.harbor_template_id}`,
    `// ${preset.human_summary}`,
    "// Map each paid-tool operation to the evidence fields below before submitSandboxEvidence(...).",
  ];
  if (required.length > 0) {
    lines.push(`// Required evidence fields: ${required.join(", ")}`);
  }
  lines.push(
    "// Sandbox: bootstrap with completionPreset to evaluate a strong Harbor predicate on evidence submit.",
    "// Production: publish the managed template head, then create intents with policy_binding (signing v5).",
    `//   paybond policy templates`,
    `//   paybond policy preview --template ${preset.harbor_template_id} --parameters-file parameters.json --evidence-file evidence.json`,
  );
  return lines;
}

function typescriptTemplate(preset: CompletionPreset): string {
  const resolved = resolveCompletionPreset(preset.preset_id);
  const fieldLines = buildTsFieldLinesFromPreset(preset);
  const comments = evidenceFieldComments(preset).join("\n");
  const sampleEvidence = jsonLiteral(
    isVendorPack(preset) && preset.vendor_sample_evidence
      ? preset.vendor_sample_evidence
      : preset.sample_evidence,
    2,
  );
  const evidenceSchema = jsonLiteral(preset.evidence_schema, 2);
  const parameters = jsonLiteral(resolved.parameters, 2);
  const vendorContractExports = isVendorPack(preset) && preset.vendor_contract
    ? `
export const VENDOR_CONTRACT_API_VERSION = "${preset.vendor_contract.api_version}";
export const VENDOR_SCHEMA_DIGEST_HEX = "${preset.vendor_contract.schema_digest_hex}";
export const CANONICAL_SCHEMA_DIGEST_HEX = "${preset.vendor_contract.canonical_schema_digest_hex}";
export const VENDOR_QUALITY_FIELDS = ${jsonLiteral(preset.vendor_contract.quality_fields, 2)} as const;
`
    : "";
  const vendorPackHelpers = isVendorPack(preset)
    ? `
export type VendorEvidence = {
${fieldLines.join("\n")}
};

export function mapVendorEvidenceToCanonical(fields: VendorEvidence): CompletionEvidence {
  return mapVendorEvidenceFields(fields) as CompletionEvidence;
}

function mapVendorEvidenceFields(fields: VendorEvidence): Record<string, unknown> {
  const fieldMap: Record<string, string> = ${jsonLiteral(preset.evidence_field_map ?? {}, 2)};
  const out: Record<string, unknown> = {};
  for (const [vendorKey, value] of Object.entries(fields)) {
    const canonicalKey = fieldMap[vendorKey] ?? vendorKey;
    out[canonicalKey] = value;
  }
  return out;
}
`
    : "";
  const buildFn = isVendorPack(preset)
    ? `export function buildCompletionEvidence(fields: VendorEvidence): Record<string, unknown> {
  return mapVendorEvidenceToCanonical(fields);
}`
    : `export function buildCompletionEvidence(fields: CompletionEvidence): Record<string, unknown> {
  return { ...fields };
}`;

  return `import fs from "node:fs/promises";
import {
  Paybond,
  type SandboxGuardrailBootstrapResult,
  type SandboxGuardrailEvidenceResult,
} from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

${comments}

export const COMPLETION_PRESET_ID = "${preset.preset_id}";
export const HARBOR_TEMPLATE_ID = "${resolved.harborTemplateId}";
${isVendorPack(preset) ? `export const ARCHETYPE_PRESET_ID = "${preset.archetype_preset_id}";` : ""}
${vendorContractExports}

export const completionEvidenceSchema = ${evidenceSchema} as const;

export const completionTemplateParameters = ${parameters} as const;

export const sampleCompletionEvidence = ${sampleEvidence} as const;

export type CompletionEvidence = {
${buildTsFieldLines(preset.evidence_schema).join("\n")}
};
${vendorPackHelpers}
${buildFn}

// Production: use buildSignedCreateIntentBodyWithPolicyBinding from @paybond/kit after publishing ${preset.harbor_template_id}.
export const policyBindingStub = {
  template_id: HARBOR_TEMPLATE_ID,
  parameters: completionTemplateParameters,
  // head_seq and digest_hex are assigned after: paybond policy publish ...
};

const DEFAULT_OPERATION = "paid_tool.operation";
const DEFAULT_REQUESTED_SPEND_CENTS = ${preset.recommended_amount_cents ?? 500};

export type SubmitCompletionEvidenceOptions = {
  operation?: string;
  requestedSpendCents?: number;
  metadata?: Record<string, unknown>;
  artifacts?: string[];
  idempotencyKey?: string;
};

function readEnvValue(body: string, key: string): string | undefined {
  const pattern = new RegExp("^\\\\s*(?:export\\\\s+)?" + key + "\\\\s*=\\\\s*(.*)$", "m");
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

async function readTextFile(envFile: string): Promise<string | undefined> {
  try {
    return await fs.readFile(envFile, "utf8");
  } catch (err) {
    if ((err as { code?: unknown })?.code === "ENOENT") return undefined;
    throw err;
  }
}

export async function loadPaybondEnvFile(envFile = ".env.local"): Promise<void> {
  if (process.env.PAYBOND_API_KEY?.trim()) return;
  const body = await readTextFile(envFile);
  if (body === undefined) return;
  const apiKey = readEnvValue(body, "PAYBOND_API_KEY");
  if (apiKey) {
    process.env.PAYBOND_API_KEY = apiKey;
  }
}

export async function openPaybondFromEnv(envFile = ".env.local"): Promise<Paybond> {
  await loadPaybondEnvFile(envFile);
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login or configure your agent host to pass it");
  }
  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}

export async function bootstrapSandboxGuardrailIntent(
  paybond: Paybond,
  options: {
    operation?: string;
    requestedSpendCents?: number;
    currency?: string;
    metadata?: Record<string, unknown>;
    idempotencyKey?: string;
  } = {},
): Promise<SandboxGuardrailBootstrapResult> {
  return paybond.guardrails.bootstrapSandbox({
    operation: options.operation ?? DEFAULT_OPERATION,
    requestedSpendCents: options.requestedSpendCents ?? DEFAULT_REQUESTED_SPEND_CENTS,
    currency: options.currency ?? "usd",
    evidenceSchema: completionEvidenceSchema,
    completionPreset: "${preset.preset_id}",
    metadata: options.metadata,
    idempotencyKey: options.idempotencyKey,
  });
}

export async function submitCompletionEvidence(
  paybond: Paybond,
  guardrail: Pick<SandboxGuardrailBootstrapResult, "intent_id" | "operation" | "requested_spend_cents">,
  evidence: ${isVendorPack(preset) ? "VendorEvidence" : "CompletionEvidence"},
  options: SubmitCompletionEvidenceOptions = {},
): Promise<SandboxGuardrailEvidenceResult> {
  return paybond.guardrails.submitSandboxEvidence({
    intentId: guardrail.intent_id,
    payload: buildCompletionEvidence(evidence),
    ${isVendorPack(preset) ? "vendorPayload: { ...evidence }," : ""}
    artifacts: options.artifacts,
    operation: options.operation ?? guardrail.operation,
    requestedSpendCents: options.requestedSpendCents ?? guardrail.requested_spend_cents,
    metadata: options.metadata,
    idempotencyKey: options.idempotencyKey,
  });
}
`;
}

function renderTemplate(preset: CompletionPreset): string {
  return typescriptTemplate(preset);
}

async function writeScaffold(out: string, body: string, force: boolean): Promise<void> {
  try {
    await fs.stat(out);
    if (!force) {
      throw new Error(`${out} already exists; pass --force to overwrite`);
    }
  } catch (err) {
    if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
      if (!force) {
        throw err;
      }
    }
  }
  await fs.writeFile(out, body, "utf8");
}

export async function scaffoldCompletionInit(options: CompletionInitOptions): Promise<void> {
  const preset = getCompletionPreset(options.preset);
  await writeScaffold(options.out, renderTemplate(preset), options.force);
}

export async function runCompletionInit(argv: string[]): Promise<number> {
  let parsed: CompletionInitOptions;
  try {
    const result = parseCompletionInitArgs(argv);
    if (result === "help") {
      process.stdout.write(`${usage()}\n`);
      return 0;
    }
    parsed = result;
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n\n${usage()}\n`);
    return 1;
  }
  try {
    await scaffoldCompletionInit(parsed);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  process.stdout.write(`Created Paybond completion integration: ${parsed.out}\n`);
  return 0;
}
