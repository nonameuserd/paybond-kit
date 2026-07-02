import { readJsonBody } from "../automation.js";
import { type CliContext, type GatewayClient, withGateway } from "../context.js";
import { describeCredentialSource } from "../credentials.js";
import {
  getCompletionPreset,
  getCompletionPresetByTemplateId,
  loadCompletionCatalog,
} from "../../completion-catalog.js";
import { resolveCompletionPreset, isVendorPack } from "../../completion-resolve.js";
import { mapSep2828ReceiptsToArtifactAttestedEvidence } from "../../mcp-sep2828-evidence.js";
import { validateCompletionEvidence } from "../../completion-validate-evidence.js";
import { mapX402ReceiptToArtifactAttestedEvidence } from "../../x402-receipt-evidence.js";
import { scaffoldOrgBasePolicy, scaffoldPaybondPolicy, scaffoldComposedPolicy, scaffoldPolicyFromPreset, scaffoldTenantOverlayPolicy, renderPolicyPresetPreviewYaml, renderComposedPolicyPreviewYaml } from "../../policy/init.js";
import { PaybondPolicy } from "../../policy/load.js";
import { listPolicyPresetsCatalog } from "../../policy/catalog.js";
import { isKnownPolicyPresetId } from "../../policy/presets.js";
import { LAYERED_POLICY_PRESET_IDS, type LayeredPolicyPresetId } from "../../policy/compose.js";
import { PolicyValidator, type PolicyValidatorResult } from "../../policy/validate.js";
import {
  parsePolicyRemoteValidateResponse,
  policyRemoteValidateResultToDict,
  policyValidateQueryString,
  validatePolicyRemote,
  type PolicyRemoteValidateOptions,
  type PolicyRemoteValidateResult,
} from "../../policy/validate-remote.js";
import { PaybondPolicyValidationError } from "../../policy/schema.js";
import { consumeBooleanFlag, consumeFlag, parseOptionalNonNegativeInt } from "../globals.js";
import { CliError, type CommandResult } from "../types.js";
import { resolve } from "node:path";

declare const process: { stdin: NodeJS.ReadableStream };

type PolicyValidateToolsMode = "local" | "remote" | "check_gateway";

type PolicyValidateToolsReport = PolicyValidatorResult | PolicyRemoteValidateResult;

async function readJsonFile(path: string): Promise<Record<string, unknown>> {
  return readJsonBody(path, process.stdin);
}

async function resolvePolicyValidateToolsMode(
  ctx: CliContext,
  flags: { remote: boolean; localOnly: boolean; checkGateway: boolean },
): Promise<PolicyValidateToolsMode> {
  if (flags.remote && flags.localOnly) {
    throw new CliError("policy validate-tools: --remote and --local-only are mutually exclusive", {
      category: "usage",
      code: "cli.usage.conflicting_flags",
    });
  }
  if (flags.localOnly) {
    return "local";
  }
  if (flags.remote) {
    return "remote";
  }
  if (flags.checkGateway) {
    return "check_gateway";
  }
  const credentials = await describeCredentialSource(ctx.globals, ctx.cwd);
  return credentials.source === "missing" ? "local" : "remote";
}

function gatewayPolicyRemoteValidateClient(gateway: GatewayClient) {
  return {
    async validatePolicy(
      document: Record<string, unknown>,
      options?: PolicyRemoteValidateOptions,
    ): Promise<PolicyRemoteValidateResult> {
      const qs = policyValidateQueryString(options ?? {});
      const body = await gateway.postJson(`/v1/policy/validate${qs}`, document);
      return parsePolicyRemoteValidateResponse(body);
    },
  };
}

async function runPolicyValidateTools(
  ctx: CliContext,
  path: string,
  mode: PolicyValidateToolsMode,
  strict: boolean,
  resolveInheritance: boolean,
): Promise<PolicyValidateToolsReport> {
  if (mode === "remote") {
    const clientFactory = gatewayPolicyRemoteValidateClient;
    const wrapped = await withGateway(ctx, async (gateway) => {
      const client = clientFactory(gateway);
      if (resolveInheritance) {
        const report = await PaybondPolicy.validateOverlayRemote(path, client, { strict });
        return { data: report };
      }
      const policy = await PaybondPolicy.load(path);
      const report = await policy.validateRemote(client, { strict });
      return { data: report };
    });
    return wrapped.data as PolicyRemoteValidateResult;
  }

  if (mode === "check_gateway") {
    const wrapped = await withGateway(ctx, async (gateway) => {
      const report = await PolicyValidator.validate(path, {
        strict,
        checkGateway: true,
        gateway: {
          async listTemplateIds() {
            const body = await gateway.getJson("/harbor/policy/v1/templates");
            const rows = Array.isArray(body) ? body : Array.isArray(body.templates) ? body.templates : [];
            return rows
              .map((row) =>
                row && typeof row === "object" && !Array.isArray(row)
                  ? String((row as Record<string, unknown>).template_id ?? "")
                  : "",
              )
              .filter((id) => id.length > 0);
          },
        },
      });
      return { data: report };
    });
    return wrapped.data as PolicyValidatorResult;
  }

  return PolicyValidator.validate(path, { strict });
}

function policyValidateToolsPayload(report: PolicyValidateToolsReport): Record<string, unknown> {
  if ("local_valid" in report) {
    return policyRemoteValidateResultToDict(report);
  }
  return {
    valid: report.valid,
    policy_name: report.policy_name,
    tools: report.tools,
    errors: report.errors,
  };
}

export async function handlePolicyPresetsList(_ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv.length > 0 && argv[0] !== "--help" && argv[0] !== "-h") {
    throw new CliError(`unexpected arguments: ${argv.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  return { data: listPolicyPresetsCatalog() };
}

export async function handlePolicyPresetsShow(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const presetFlag = consumeFlag(rest, "--preset");
  rest = presetFlag.rest;
  const maxSpendFlag = consumeFlag(rest, "--max-spend");
  rest = maxSpendFlag.rest;
  const domainFlag = consumeFlag(rest, "--domain");
  rest = domainFlag.rest;
  const guardrailsFlag = consumeFlag(rest, "--guardrails");
  rest = guardrailsFlag.rest;

  let positionalPreset: string | undefined;
  if (!presetFlag.value && rest.length === 1 && !rest[0]!.startsWith("-")) {
    positionalPreset = rest[0]!.trim();
    rest = [];
  }

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }

  let maxSpendUsd: number | undefined;
  if (maxSpendFlag.value !== undefined) {
    const parsed = parseOptionalNonNegativeInt(maxSpendFlag.value, "--max-spend");
    if (parsed === undefined) {
      throw new CliError("invalid --max-spend", {
        category: "usage",
        code: "cli.usage.invalid_amount",
      });
    }
    maxSpendUsd = parsed;
  }

  if (domainFlag.value) {
    const domainId = domainFlag.value.trim();
    if (!(LAYERED_POLICY_PRESET_IDS as readonly string[]).includes(domainId)) {
      throw new CliError(`unknown policy domain: ${domainId}`, {
        category: "validation",
        code: "cli.policy.domain_invalid",
        exitCode: 3,
      });
    }
    if (!guardrailsFlag.value) {
      throw new CliError("policy presets show --domain requires --guardrails", {
        category: "usage",
        code: "cli.usage.missing_args",
      });
    }
    if (presetFlag.value) {
      throw new CliError("policy presets show: --preset cannot be combined with --domain", {
        category: "usage",
        code: "cli.usage.conflicting_flags",
      });
    }
    try {
      const yaml = renderComposedPolicyPreviewYaml({
        domainId: domainId as LayeredPolicyPresetId,
        guardrails: guardrailsFlag.value,
      });
      const yamlLines = yaml.split(/\r?\n/);
      return {
        data: {
          domain: domainId,
          guardrails: guardrailsFlag.value,
          yaml,
          yaml_lines: yamlLines,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CliError(message, {
        category: "validation",
        code: "cli.policy.presets_show_failed",
        exitCode: 3,
      });
    }
  }

  const presetId = (presetFlag.value ?? positionalPreset ?? "").trim();
  if (!presetId) {
    throw new CliError("policy presets show requires a preset id or --preset", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }
  if (guardrailsFlag.value) {
    throw new CliError("policy presets show: --guardrails requires --domain", {
      category: "usage",
      code: "cli.usage.conflicting_flags",
    });
  }
  if (!isKnownPolicyPresetId(presetId)) {
    throw new CliError(`unknown policy preset: ${presetId}`, {
      category: "validation",
      code: "cli.policy.preset_invalid",
      exitCode: 3,
    });
  }

  const yaml = renderPolicyPresetPreviewYaml(presetId, { maxSpendUsd });
  const yamlLines = yaml.split(/\r?\n/);
  return {
    data: {
      preset: presetId,
      ...(maxSpendUsd !== undefined ? { max_spend_usd: maxSpendUsd } : {}),
      yaml,
      yaml_lines: yamlLines,
    },
  };
}

export async function handlePolicyInit(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const outFlag = consumeFlag(rest, "--out");
  rest = outFlag.rest;
  const presetFlag = consumeFlag(rest, "--preset");
  rest = presetFlag.rest;
  const domainFlag = consumeFlag(rest, "--domain");
  rest = domainFlag.rest;
  const guardrailsFlag = consumeFlag(rest, "--guardrails");
  rest = guardrailsFlag.rest;
  const maxSpendFlag = consumeFlag(rest, "--max-spend");
  rest = maxSpendFlag.rest;
  const operationFlag = consumeFlag(rest, "--operation");
  rest = operationFlag.rest;
  const evidencePresetFlag = consumeFlag(rest, "--evidence-preset");
  rest = evidencePresetFlag.rest;
  const forceFlag = consumeBooleanFlag(rest, "--force");
  rest = forceFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }

  const out = resolve(ctx.cwd, outFlag.value ?? "paybond.policy.yaml");

  let maxSpendUsd: number | undefined;
  if (maxSpendFlag.value !== undefined) {
    const parsed = parseOptionalNonNegativeInt(maxSpendFlag.value, "--max-spend");
    if (parsed === undefined) {
      throw new CliError("invalid --max-spend", {
        category: "usage",
        code: "cli.usage.invalid_amount",
      });
    }
    maxSpendUsd = parsed;
  }

  if (domainFlag.value) {
    const domainId = domainFlag.value.trim();
    if (!(LAYERED_POLICY_PRESET_IDS as readonly string[]).includes(domainId)) {
      throw new CliError(`unknown policy domain: ${domainId}`, {
        category: "validation",
        code: "cli.policy.domain_invalid",
        exitCode: 3,
      });
    }
    if (!guardrailsFlag.value) {
      throw new CliError("policy init --domain requires --guardrails", {
        category: "usage",
        code: "cli.usage.missing_args",
      });
    }
    if (presetFlag.value || operationFlag.value || evidencePresetFlag.value || maxSpendUsd !== undefined) {
      throw new CliError(
        "policy init --domain cannot be combined with --preset, --operation, --evidence-preset, or --max-spend",
        { category: "usage", code: "cli.usage.conflicting_flags" },
      );
    }
    try {
      const result = await scaffoldComposedPolicy({
        out,
        domainId: domainId as LayeredPolicyPresetId,
        guardrails: guardrailsFlag.value,
        force: forceFlag.present,
      });
      return { data: result };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CliError(message, {
        category: "validation",
        code: "cli.policy.init_failed",
        exitCode: 3,
      });
    }
  }

  if (guardrailsFlag.value) {
    throw new CliError("policy init --guardrails requires --domain", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  if (presetFlag.value) {
    const presetId = presetFlag.value.trim();
    if (!isKnownPolicyPresetId(presetId)) {
      throw new CliError(`unknown policy preset: ${presetId}`, {
        category: "validation",
        code: "cli.policy.preset_invalid",
        exitCode: 3,
      });
    }
    if (operationFlag.value || evidencePresetFlag.value) {
      throw new CliError(
        "policy init: --preset cannot be combined with --operation or --evidence-preset",
        { category: "usage", code: "cli.usage.conflicting_flags" },
      );
    }
    try {
      const result = await scaffoldPolicyFromPreset({
        out,
        presetId,
        maxSpendUsd,
        force: forceFlag.present,
      });
      return { data: result };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new CliError(message, {
        category: "validation",
        code: "cli.policy.init_failed",
        exitCode: 3,
      });
    }
  }

  if (maxSpendUsd !== undefined) {
    throw new CliError("policy init --max-spend requires --preset", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  const operation = operationFlag.value ?? "travel.book_hotel";
  const evidencePreset = evidencePresetFlag.value ?? "cost_and_completion";

  try {
    const result = await scaffoldPaybondPolicy({
      out,
      operation,
      evidencePreset,
      force: forceFlag.present,
    });
    return { data: result };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new CliError(message, {
      category: err instanceof PaybondPolicyValidationError ? "validation" : "validation",
      code: "cli.policy.init_failed",
      exitCode: 3,
    });
  }
}

export async function handlePolicyInitOrg(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const outFlag = consumeFlag(rest, "--out");
  rest = outFlag.rest;
  const policyIdFlag = consumeFlag(rest, "--policy-id");
  rest = policyIdFlag.rest;
  const operationFlag = consumeFlag(rest, "--operation");
  rest = operationFlag.rest;
  const presetFlag = consumeFlag(rest, "--evidence-preset");
  rest = presetFlag.rest;
  const maxSpendFlag = consumeFlag(rest, "--max-spend-cents");
  rest = maxSpendFlag.rest;
  const forceFlag = consumeBooleanFlag(rest, "--force");
  rest = forceFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!policyIdFlag.value) {
    throw new CliError("policy init-org requires --policy-id", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  const policyId = policyIdFlag.value;
  const out = resolve(ctx.cwd, outFlag.value ?? `${policyId}.yaml`);
  let maxSpendCents: number | undefined;
  if (maxSpendFlag.value !== undefined) {
    const parsed = parseOptionalNonNegativeInt(maxSpendFlag.value, "--max-spend-cents");
    if (parsed === undefined) {
      throw new CliError("invalid --max-spend-cents", {
        category: "usage",
        code: "cli.usage.invalid_amount_cents",
      });
    }
    maxSpendCents = parsed;
  }

  try {
    const result = await scaffoldOrgBasePolicy({
      out,
      policyId,
      operation: operationFlag.value ?? "travel.book_hotel",
      evidencePreset: presetFlag.value ?? "cost_and_completion",
      maxSpendCents,
      force: forceFlag.present,
    });
    return { data: result };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new CliError(message, {
      category: "validation",
      code: "cli.policy.init_org_failed",
      exitCode: 3,
    });
  }
}

export async function handlePolicyExtend(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const extendsFlag = consumeFlag(rest, "--extends");
  rest = extendsFlag.rest;
  const outFlag = consumeFlag(rest, "--out");
  rest = outFlag.rest;
  const nameFlag = consumeFlag(rest, "--name");
  rest = nameFlag.rest;
  const operationFlag = consumeFlag(rest, "--operation");
  rest = operationFlag.rest;
  const presetFlag = consumeFlag(rest, "--evidence-preset");
  rest = presetFlag.rest;
  const basePolicyFlag = consumeFlag(rest, "--base-policy");
  rest = basePolicyFlag.rest;
  const forceFlag = consumeBooleanFlag(rest, "--force");
  rest = forceFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!extendsFlag.value) {
    throw new CliError("policy extend requires --extends org_id/org_policy_id", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  const out = resolve(ctx.cwd, outFlag.value ?? "paybond.policy.yaml");

  try {
    const result = await scaffoldTenantOverlayPolicy({
      out,
      extendsRef: extendsFlag.value,
      name: nameFlag.value,
      operation: operationFlag.value,
      evidencePreset: presetFlag.value,
      basePolicy: basePolicyFlag.value,
      force: forceFlag.present,
    });
    return { data: result };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new CliError(message, {
      category: "validation",
      code: "cli.policy.extend_failed",
      exitCode: 3,
    });
  }
}

export async function handlePolicyValidateTools(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const fileFlag = consumeFlag(rest, "--file");
  rest = fileFlag.rest;
  const remoteFlag = consumeBooleanFlag(rest, "--remote");
  rest = remoteFlag.rest;
  const localOnlyFlag = consumeBooleanFlag(rest, "--local-only");
  rest = localOnlyFlag.rest;
  const checkGatewayFlag = consumeBooleanFlag(rest, "--check-gateway");
  rest = checkGatewayFlag.rest;
  const strictFlag = consumeBooleanFlag(rest, "--strict");
  rest = strictFlag.rest;
  const resolveInheritanceFlag = consumeBooleanFlag(rest, "--resolve-inheritance");
  rest = resolveInheritanceFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!fileFlag.value) {
    throw new CliError("policy validate-tools requires --file", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  const path = resolve(ctx.cwd, fileFlag.value);
  const strict = strictFlag.present || PolicyValidator.isStrictFromEnv();
  const mode = await resolvePolicyValidateToolsMode(ctx, {
    remote: remoteFlag.present,
    localOnly: localOnlyFlag.present,
    checkGateway: checkGatewayFlag.present,
  });
  if (resolveInheritanceFlag.present && mode !== "remote") {
    throw new CliError(
      "policy validate-tools: --resolve-inheritance requires remote validation (use --remote or log in)",
      {
        category: "usage",
        code: "cli.usage.conflicting_flags",
      },
    );
  }
  const report = await runPolicyValidateTools(ctx, path, mode, strict, resolveInheritanceFlag.present);
  const payload = policyValidateToolsPayload(report);

  if (!report.valid) {
    throw new CliError("policy validation failed", {
      category: "validation",
      code: "cli.policy.validation_failed",
      exitCode: 3,
      details: payload,
    });
  }

  return { data: payload };
}

export async function handlePolicyTemplates(_ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv.length > 0 && argv[0] !== "--help" && argv[0] !== "-h") {
    throw new CliError(`unexpected arguments: ${argv.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  const catalog = loadCompletionCatalog();
  const presets = catalog.presets.map((preset) => ({
    preset_id: preset.preset_id,
    title: preset.title,
    harbor_template_id: preset.harbor_template_id,
    human_summary: preset.human_summary,
    recommended_amount_cents: preset.recommended_amount_cents ?? null,
    kind: preset.kind ?? "archetype",
    archetype_preset_id: preset.archetype_preset_id ?? null,
    scope: preset.scope ?? null,
    rail_hints: preset.rail_hints ?? null,
    deprecated: preset.deprecated ?? false,
    superseded_by: preset.superseded_by ?? null,
  }));
  return { data: { catalog_version: catalog.version, presets } };
}

export async function handlePolicyPreview(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const templateFlag = consumeFlag(rest, "--template");
  rest = templateFlag.rest;
  const presetFlag = consumeFlag(rest, "--preset");
  rest = presetFlag.rest;
  const parametersFlag = consumeFlag(rest, "--parameters-file");
  rest = parametersFlag.rest;
  const evidenceFlag = consumeFlag(rest, "--evidence-file");
  rest = evidenceFlag.rest;
  const schemaFlag = consumeFlag(rest, "--schema-file");
  rest = schemaFlag.rest;
  const amountFlag = consumeFlag(rest, "--amount-cents");
  rest = amountFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }

  let templateId = templateFlag.value ?? "";
  let catalogPreset = presetFlag.value ? getCompletionPreset(presetFlag.value) : undefined;
  if (!templateId && catalogPreset) {
    templateId = resolveCompletionPreset(catalogPreset.preset_id).harborTemplateId;
  }
  if (!templateId) {
    throw new CliError("policy preview requires --template or --preset", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }
  if (!catalogPreset) {
    catalogPreset = getCompletionPresetByTemplateId(templateId);
  }

  let parameters: Record<string, unknown>;
  if (parametersFlag.value) {
    parameters = await readJsonFile(parametersFlag.value);
  } else if (catalogPreset) {
    parameters = resolveCompletionPreset(catalogPreset.preset_id).parameters;
  } else {
    throw new CliError("policy preview requires --parameters-file when template is not in the catalog", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  if (!evidenceFlag.value) {
    throw new CliError("policy preview requires --evidence-file", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }
  const evidence = await readJsonFile(evidenceFlag.value);

  let evidenceSchema: Record<string, unknown>;
  if (schemaFlag.value) {
    evidenceSchema = await readJsonFile(schemaFlag.value);
  } else if (catalogPreset) {
    evidenceSchema = resolveCompletionPreset(catalogPreset.preset_id).evidenceSchema;
  } else {
    throw new CliError("policy preview requires --schema-file when template is not in the catalog", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  let amountCents: number;
  if (amountFlag.value !== undefined) {
    const parsed = parseOptionalNonNegativeInt(amountFlag.value, "--amount-cents");
    if (parsed === undefined) {
      throw new CliError("invalid --amount-cents", { category: "usage", code: "cli.usage.invalid_amount_cents" });
    }
    amountCents = parsed;
  } else if (catalogPreset?.recommended_amount_cents) {
    amountCents = catalogPreset.recommended_amount_cents;
  } else {
    amountCents = 100;
  }

  return withGateway(ctx, async (gateway) => {
    const preview = await gateway.postJson("/harbor/policy/v1/preview", {
      template_id: templateId,
      parameters,
    });
    const test = await gateway.postJson("/harbor/policy/v1/test", {
      template_id: templateId,
      parameters,
      evidence,
      evidence_schema: evidenceSchema,
      amount_cents: amountCents,
    });
    const evaluation = (test.predicate_evaluation ?? {}) as Record<string, unknown>;
    const pass = Boolean(evaluation.passed ?? evaluation.pass ?? evaluation.ok);
    return {
      data: {
        template_id: templateId,
        preset_id: catalogPreset?.preset_id ?? null,
        materialized_dsl: preview.materialized_dsl ?? null,
        human_summary: preview.human_summary ?? null,
        predicate_evaluation: evaluation,
        pass,
        amount_cents: amountCents,
      },
    };
  });
}

export async function handlePolicyImportMcpReceipt(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const decisionFlag = consumeFlag(rest, "--decision-file");
  rest = decisionFlag.rest;
  const outcomeFlag = consumeFlag(rest, "--outcome-file");
  rest = outcomeFlag.rest;
  const writeFlag = consumeFlag(rest, "--write-evidence-file");
  rest = writeFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!decisionFlag.value || !outcomeFlag.value) {
    throw new CliError(
      "policy import-mcp-receipt requires --decision-file and --outcome-file",
      { category: "usage", code: "cli.usage.missing_args" },
    );
  }

  const decision = await readJsonFile(decisionFlag.value);
  const outcome = await readJsonFile(outcomeFlag.value);
  const evidence = mapSep2828ReceiptsToArtifactAttestedEvidence(decision, outcome);
  const artifactPreset = getCompletionPreset("artifact_attested");

  if (writeFlag.value) {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(writeFlag.value, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  }

  return {
    data: {
      preset_id: artifactPreset.preset_id,
      harbor_template_id: artifactPreset.harbor_template_id,
      evidence,
      source: "sep2828_mcp_receipt",
    },
  };
}

export async function handlePolicyValidateEvidence(_ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const presetFlag = consumeFlag(rest, "--preset");
  rest = presetFlag.rest;
  const vendorFlag = consumeFlag(rest, "--vendor-file");
  rest = vendorFlag.rest;
  const canonicalFlag = consumeFlag(rest, "--canonical-file");
  rest = canonicalFlag.rest;
  const frozenApiFlag = consumeFlag(rest, "--frozen-api-version");
  rest = frozenApiFlag.rest;
  const frozenVendorDigestFlag = consumeFlag(rest, "--frozen-vendor-schema-digest");
  rest = frozenVendorDigestFlag.rest;
  const frozenCanonicalDigestFlag = consumeFlag(rest, "--frozen-canonical-schema-digest");
  rest = frozenCanonicalDigestFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!presetFlag.value) {
    throw new CliError("policy validate-evidence requires --preset", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }

  const preset = getCompletionPreset(presetFlag.value);
  let vendorPayload: Record<string, unknown> | undefined;
  if (vendorFlag.value) {
    vendorPayload = await readJsonFile(vendorFlag.value);
  }
  let canonicalPayload: Record<string, unknown> | undefined;
  if (canonicalFlag.value) {
    canonicalPayload = await readJsonFile(canonicalFlag.value);
  }

  if (isVendorPack(preset) && !vendorPayload && !canonicalPayload) {
    throw new CliError(
      "policy validate-evidence requires --vendor-file for vendor_pack presets (or --canonical-file)",
      { category: "usage", code: "cli.usage.missing_args" },
    );
  }
  if (!isVendorPack(preset) && !vendorPayload && !canonicalPayload) {
    throw new CliError(
      "policy validate-evidence requires --canonical-file or --vendor-file",
      { category: "usage", code: "cli.usage.missing_args" },
    );
  }

  const report = validateCompletionEvidence({
    presetId: preset.preset_id,
    vendorPayload,
    canonicalPayload,
    frozenVendorApiVersion: frozenApiFlag.value,
    frozenVendorSchemaDigestHex: frozenVendorDigestFlag.value,
    frozenCanonicalSchemaDigestHex: frozenCanonicalDigestFlag.value,
  });

  return {
    data: {
      ...report,
      ok: report.drift_kinds.length === 0,
    },
  };
}

export async function handlePolicyImportX402Receipt(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  let rest = argv;
  const receiptFlag = consumeFlag(rest, "--receipt-file");
  rest = receiptFlag.rest;
  const writeFlag = consumeFlag(rest, "--write-evidence-file");
  rest = writeFlag.rest;

  if (rest.length > 0) {
    throw new CliError(`unexpected arguments: ${rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!receiptFlag.value) {
    throw new CliError(
      "policy import-x402-receipt requires --receipt-file",
      { category: "usage", code: "cli.usage.missing_args" },
    );
  }

  const receipt = await readJsonFile(receiptFlag.value);
  let evidence;
  try {
    evidence = mapX402ReceiptToArtifactAttestedEvidence(receipt);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new CliError(message, { category: "usage", code: "cli.usage.invalid_receipt" });
  }
  const deliveryPreset = getCompletionPreset("x402_delivery_receipt");

  if (writeFlag.value) {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(writeFlag.value, `${JSON.stringify(evidence, null, 2)}\n`, "utf8");
  }

  return {
    data: {
      preset_id: deliveryPreset.preset_id,
      harbor_template_id: deliveryPreset.harbor_template_id,
      evidence,
      source: "x402_receipt_v1",
    },
  };
}