import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

import { loadCompletionCatalog } from "./completion-catalog.js";
import {
  completionPresetDeprecationWarning,
  isVendorPack,
  resolveCompletionPreset,
  vendorEvidenceSchema,
} from "./completion-resolve.js";

/** Stripe payment-rail webhook event types that must not appear as tool-completion predicates. */
export const STRIPE_FUNDING_WEBHOOK_EVENT_TYPES = [
  "payment_intent.succeeded",
  "charge.succeeded",
] as const;

export type CompletionDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

function stableJson(value: unknown): string {
  return JSON.stringify(value);
}

function schemasMatch(expected: Record<string, unknown>, actual: Record<string, unknown>): boolean {
  return stableJson(expected) === stableJson(actual);
}

function parametersMatch(expected: Record<string, unknown>, actual: Record<string, unknown>): boolean {
  return stableJson(expected) === stableJson(actual);
}

const SCAFFOLD_GLOBS = [
  /^paybond-completion-[\w-]+\.(ts|js|py)$/,
  /^paybond-paid-tool-guard\.(ts|js|py)$/,
  /^paybond_completion_[\w]+\.py$/,
];

async function findCompletionScaffolds(cwd: string): Promise<string[]> {
  const matches: string[] = [];
  try {
    const entries = await readdir(cwd);
    for (const entry of entries) {
      if (SCAFFOLD_GLOBS.some((pattern) => pattern.test(entry))) {
        matches.push(path.join(cwd, entry));
      }
    }
  } catch {
    return matches;
  }
  return matches;
}

function extractPresetIdFromScaffold(body: string): string | undefined {
  const tsMatch = body.match(/export const COMPLETION_PRESET_ID = "([^"]+)"/);
  if (tsMatch?.[1]) {
    return tsMatch[1];
  }
  const pyMatch = body.match(/^COMPLETION_PRESET_ID = "([^"]+)"/m);
  return pyMatch?.[1];
}

function schemaPropertyKeys(schema: Record<string, unknown> | undefined): string[] {
  if (!schema) {
    return [];
  }
  const properties = schema.properties;
  if (properties !== null && typeof properties === "object" && !Array.isArray(properties)) {
    return Object.keys(properties as Record<string, unknown>);
  }
  return [];
}

function vendorSchemaForbiddenHits(
  preset: { evidence_field_map?: Record<string, string> },
  vendorSchema: Record<string, unknown> | undefined,
  forbidden: string[] | undefined,
): string[] {
  if (!vendorSchema) {
    return [];
  }
  const fieldMap = preset.evidence_field_map ?? {};
  const unmappedVendorKeys = schemaPropertyKeys(vendorSchema).filter((key) => !(key in fieldMap));
  return forbiddenFieldHits(unmappedVendorKeys, forbidden);
}

function forbiddenFieldHits(propertyKeys: string[], forbidden: string[] | undefined): string[] {
  if (!forbidden?.length) {
    return [];
  }
  const blocked = new Set(forbidden);
  return propertyKeys.filter((key) => blocked.has(key));
}

export function isStripeFundingWebhookEventType(eventType: unknown): boolean {
  return (
    typeof eventType === "string" &&
    (STRIPE_FUNDING_WEBHOOK_EVENT_TYPES as readonly string[]).includes(eventType)
  );
}

function extractTemplateParametersFromScaffold(body: string): Record<string, unknown> | undefined {
  const tsMatch = body.match(/export const completionTemplateParameters = (\{[\s\S]*?\}) as const;/);
  if (tsMatch?.[1]) {
    try {
      return JSON.parse(tsMatch[1]) as Record<string, unknown>;
    } catch {
      return undefined;
    }
  }
  const pyMatch = body.match(/^completion_template_parameters: dict\[str, Any\] = (\{[\s\S]*?\})\n\n/m);
  if (pyMatch?.[1]) {
    try {
      return JSON.parse(pyMatch[1].replace(/'/g, '"')) as Record<string, unknown>;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

type VendorContractPin = {
  apiVersion?: string;
  vendorSchemaDigest?: string;
  canonicalSchemaDigest?: string;
  qualityFields?: string[];
};

function extractVendorContractPinFromScaffold(body: string): VendorContractPin {
  const tsApi = body.match(/export const VENDOR_CONTRACT_API_VERSION = "([^"]+)"/);
  const pyApi = body.match(/^VENDOR_CONTRACT_API_VERSION = "([^"]+)"/m);
  const tsVendorDigest = body.match(/export const VENDOR_SCHEMA_DIGEST_HEX = "([^"]+)"/);
  const pyVendorDigest = body.match(/^VENDOR_SCHEMA_DIGEST_HEX = "([^"]+)"/m);
  const tsCanonicalDigest = body.match(/export const CANONICAL_SCHEMA_DIGEST_HEX = "([^"]+)"/);
  const pyCanonicalDigest = body.match(/^CANONICAL_SCHEMA_DIGEST_HEX = "([^"]+)"/m);
  const tsQuality = body.match(/export const VENDOR_QUALITY_FIELDS = (\[[\s\S]*?\]) as const;/);
  const pyQuality = body.match(/^VENDOR_QUALITY_FIELDS: tuple\[str, \.\.\.\] = tuple\((\[[\s\S]*?\])\)/m);
  let qualityFields: string[] | undefined;
  const qualityRaw = tsQuality?.[1] ?? pyQuality?.[1];
  if (qualityRaw) {
    try {
      const parsed = JSON.parse(qualityRaw) as unknown;
      if (Array.isArray(parsed)) {
        qualityFields = parsed.filter((entry): entry is string => typeof entry === "string");
      }
    } catch {
      qualityFields = undefined;
    }
  }
  return {
    apiVersion: tsApi?.[1] ?? pyApi?.[1],
    vendorSchemaDigest: tsVendorDigest?.[1] ?? pyVendorDigest?.[1],
    canonicalSchemaDigest: tsCanonicalDigest?.[1] ?? pyCanonicalDigest?.[1],
    qualityFields,
  };
}

function extractEvidenceSchemaFromScaffold(body: string): Record<string, unknown> | undefined {
  const tsMatch = body.match(/export const completionEvidenceSchema = (\{[\s\S]*?\}) as const;/);
  if (tsMatch?.[1]) {
    try {
      return JSON.parse(tsMatch[1]) as Record<string, unknown>;
    } catch {
      return undefined;
    }
  }
  const pyMatch = body.match(/^completion_evidence_schema: dict\[str, Any\] = (\{[\s\S]*?\})\n\n/m);
  if (pyMatch?.[1]) {
    try {
      return JSON.parse(pyMatch[1].replace(/'/g, '"')) as Record<string, unknown>;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

type GatewayJsonClient = {
  getJson(path: string): Promise<Record<string, unknown>>;
};

export async function runCompletionCatalogDoctorChecks(options: {
  cwd: string;
  gateway?: GatewayJsonClient;
}): Promise<CompletionDoctorCheck[]> {
  const checks: CompletionDoctorCheck[] = [];
  let catalog;
  try {
    catalog = loadCompletionCatalog();
    checks.push({
      name: "completion_catalog",
      ok: true,
      message: `catalog v${catalog.version} loaded (${catalog.presets.length} presets)`,
    });
  } catch (err) {
    checks.push({
      name: "completion_catalog",
      ok: false,
      message: err instanceof Error ? err.message : String(err),
    });
    return checks;
  }

  const scaffoldPaths = await findCompletionScaffolds(options.cwd);
  const fundingEventWarnings: string[] = [];
  const packStaleWarnings: string[] = [];
  const qualityFieldWarnings: string[] = [];
  if (scaffoldPaths.length === 0) {
    checks.push({
      name: "completion_local_scaffold",
      ok: true,
      message: "no local completion scaffold files in cwd",
    });
  } else {
    const divergences: string[] = [];
    const deprecatedPresets: string[] = [];
    const forbiddenFieldWarnings: string[] = [];
    for (const scaffoldPath of scaffoldPaths) {
      const body = await readFile(scaffoldPath, "utf8");
      const scaffoldName = path.basename(scaffoldPath);
      const presetId = extractPresetIdFromScaffold(body);
      if (!presetId) {
        continue;
      }
      const deprecationWarning = completionPresetDeprecationWarning(presetId);
      if (deprecationWarning) {
        deprecatedPresets.push(`${scaffoldName}: ${deprecationWarning}`);
      }
      let resolved;
      try {
        resolved = resolveCompletionPreset(presetId);
      } catch {
        divergences.push(`${scaffoldName}: unknown preset ${presetId}`);
        continue;
      }
      const embedded = extractEvidenceSchemaFromScaffold(body);
      const expected = isVendorPack(resolved.preset)
        ? resolved.preset.evidence_schema
        : resolved.evidenceSchema;
      if (embedded && !schemasMatch(expected, embedded)) {
        divergences.push(`${scaffoldName}: evidence_schema diverges from catalog for ${presetId}`);
      }

      const forbidden = resolved.preset.forbidden_evidence_fields;
      const hits = [
        ...forbiddenFieldHits(schemaPropertyKeys(embedded), forbidden),
        ...vendorSchemaForbiddenHits(
          resolved.preset,
          vendorEvidenceSchema(resolved.preset),
          forbidden,
        ),
      ];
      const uniqueHits = [...new Set(hits)];
      if (uniqueHits.length > 0) {
        forbiddenFieldWarnings.push(
          `${scaffoldName}: evidence schema includes forbidden field(s) for ${presetId}: ${uniqueHits.join(", ")}`,
        );
      }

      if (resolved.harborTemplateId === "webhook_confirmation_v1") {
        const embeddedParams = extractTemplateParametersFromScaffold(body);
        const expectedEventType =
          embeddedParams?.expected_event_type ?? resolved.parameters.expected_event_type;
        if (isStripeFundingWebhookEventType(expectedEventType)) {
          fundingEventWarnings.push(
            `${scaffoldName}: expected_event_type ${String(expectedEventType)} is a Stripe funding webhook, not tool-completion evidence`,
          );
        }
      }

      if (isVendorPack(resolved.preset)) {
        const contract = resolved.preset.vendor_contract;
        const pin = extractVendorContractPinFromScaffold(body);
        if (contract) {
          if (!pin.apiVersion) {
            packStaleWarnings.push(
              `${scaffoldName}: missing VENDOR_CONTRACT_API_VERSION pin for ${presetId}; re-run paybond init completion`,
            );
          } else if (pin.apiVersion !== contract.api_version) {
            packStaleWarnings.push(
              `${scaffoldName}: pinned api_version ${pin.apiVersion} lags catalog ${contract.api_version} for ${presetId}`,
            );
          }
          if (pin.vendorSchemaDigest && pin.vendorSchemaDigest !== contract.schema_digest_hex) {
            packStaleWarnings.push(
              `${scaffoldName}: pinned vendor schema digest diverges from catalog for ${presetId}`,
            );
          }
          if (pin.canonicalSchemaDigest && pin.canonicalSchemaDigest !== contract.canonical_schema_digest_hex) {
            packStaleWarnings.push(
              `${scaffoldName}: pinned canonical schema digest diverges from catalog for ${presetId}`,
            );
          }
          const expectedQuality = contract.quality_fields ?? [];
          if (expectedQuality.length > 0 && !pin.qualityFields) {
            qualityFieldWarnings.push(
              `${scaffoldName}: missing VENDOR_QUALITY_FIELDS export for ${presetId}`,
            );
          } else if (
            pin.qualityFields &&
            stableJson([...pin.qualityFields].sort()) !== stableJson([...expectedQuality].sort())
          ) {
            qualityFieldWarnings.push(
              `${scaffoldName}: VENDOR_QUALITY_FIELDS diverge from catalog for ${presetId}`,
            );
          }
        }
      }
    }

    if (divergences.length > 0) {
      checks.push({
        name: "completion_local_scaffold",
        ok: true,
        message: `warn: ${divergences.join("; ")}`,
        details: { divergences },
      });
    } else {
      checks.push({
        name: "completion_local_scaffold",
        ok: true,
        message: `checked ${scaffoldPaths.length} scaffold file(s); evidence schemas match catalog`,
      });
    }

    if (deprecatedPresets.length > 0) {
      checks.push({
        name: "completion_deprecated_preset",
        ok: true,
        message: `warn: ${deprecatedPresets.join("; ")}`,
        details: { warnings: deprecatedPresets },
      });
    } else {
      checks.push({
        name: "completion_deprecated_preset",
        ok: true,
        message: "no deprecated completion presets in local scaffolds",
      });
    }

    if (forbiddenFieldWarnings.length > 0) {
      checks.push({
        name: "completion_forbidden_fields",
        ok: true,
        message: `warn: ${forbiddenFieldWarnings.join("; ")}`,
        details: { warnings: forbiddenFieldWarnings },
      });
    } else {
      checks.push({
        name: "completion_forbidden_fields",
        ok: true,
        message: "local scaffold evidence schemas exclude catalog forbidden fields",
      });
    }
  }

  if (scaffoldPaths.length === 0) {
    checks.push({
      name: "completion_deprecated_preset",
      ok: true,
      message: "no local completion scaffold files in cwd",
    });
    checks.push({
      name: "completion_forbidden_fields",
      ok: true,
      message: "no local completion scaffold files in cwd",
    });
  }

  pushPackStaleCheck(checks, packStaleWarnings, scaffoldPaths.length);
  pushQualityFieldsCheck(checks, qualityFieldWarnings, scaffoldPaths.length);

  if (!options.gateway) {
    checks.push({
      name: "completion_policy_heads",
      ok: true,
      message: "skipped policy head check (no gateway credentials)",
    });
    pushFundingEventMisuseCheck(checks, fundingEventWarnings, scaffoldPaths.length);
    return checks;
  }

  const archetypes = catalog.presets.filter((preset) => !isVendorPack(preset));
  const headWarnings: string[] = [];
  for (const preset of archetypes) {
    if (preset.harbor_template_id === "true_v1") {
      continue;
    }
    try {
      const versions = await options.gateway.getJson(
        `/harbor/policy/v1/versions?${new URLSearchParams({ template_id: preset.harbor_template_id }).toString()}`,
      );
      const headSeq = versions.current_head_seq;
      if (headSeq === null || headSeq === undefined) {
        continue;
      }
      const versionRows = Array.isArray(versions.versions) ? versions.versions : [];
      const head = versionRows.find(
        (row) =>
          typeof row === "object" &&
          row !== null &&
          (row as Record<string, unknown>).version_seq === headSeq,
      ) as Record<string, unknown> | undefined;
      if (!head) {
        continue;
      }
      const headParams = readObject(head.parameters) ?? {};
      if (!parametersMatch(preset.parameters, headParams)) {
        headWarnings.push(
          `${preset.harbor_template_id} head seq ${String(headSeq)} parameters diverge from catalog preset ${preset.preset_id}`,
        );
      }
      if (
        preset.harbor_template_id === "webhook_confirmation_v1" &&
        isStripeFundingWebhookEventType(headParams.expected_event_type)
      ) {
        fundingEventWarnings.push(
          `${preset.harbor_template_id} head seq ${String(headSeq)} uses Stripe funding event type ${String(headParams.expected_event_type)}`,
        );
      }
    } catch (err) {
      headWarnings.push(
        `${preset.harbor_template_id}: could not load policy versions (${err instanceof Error ? err.message : String(err)})`,
      );
    }
  }

  if (headWarnings.length > 0) {
    checks.push({
      name: "completion_policy_heads",
      ok: true,
      message: `warn: ${headWarnings.join("; ")}`,
      details: { warnings: headWarnings },
    });
  } else {
    checks.push({
      name: "completion_policy_heads",
      ok: true,
      message: "published policy heads match catalog defaults (or no heads published)",
    });
  }

  pushFundingEventMisuseCheck(checks, fundingEventWarnings, scaffoldPaths.length);
  return checks;
}

function pushPackStaleCheck(
  checks: CompletionDoctorCheck[],
  warnings: string[],
  scaffoldCount: number,
): void {
  if (warnings.length > 0) {
    checks.push({
      name: "completion_pack_stale",
      ok: true,
      message: `warn: ${warnings.join("; ")}`,
      details: { warnings },
    });
    return;
  }
  checks.push({
    name: "completion_pack_stale",
    ok: true,
    message:
      scaffoldCount === 0
        ? "no local completion scaffold files in cwd"
        : "local vendor pack scaffolds match catalog contract pins",
  });
}

function pushQualityFieldsCheck(
  checks: CompletionDoctorCheck[],
  warnings: string[],
  scaffoldCount: number,
): void {
  if (warnings.length > 0) {
    checks.push({
      name: "completion_quality_fields",
      ok: true,
      message: `warn: ${warnings.join("; ")}`,
      details: { warnings },
    });
    return;
  }
  checks.push({
    name: "completion_quality_fields",
    ok: true,
    message:
      scaffoldCount === 0
        ? "no local completion scaffold files in cwd"
        : "vendor pack scaffolds export catalog quality_fields pins",
  });
}

function pushFundingEventMisuseCheck(
  checks: CompletionDoctorCheck[],
  warnings: string[],
  scaffoldCount: number,
): void {
  if (warnings.length > 0) {
    checks.push({
      name: "completion_funding_event_misuse",
      ok: true,
      message: `warn: ${warnings.join("; ")}`,
      details: { warnings },
    });
    return;
  }
  checks.push({
    name: "completion_funding_event_misuse",
    ok: true,
    message:
      scaffoldCount === 0
        ? "no local completion scaffold files in cwd"
        : "no Stripe funding webhook event types in webhook_confirmed scaffolds or policy heads",
  });
}

function readObject(value: unknown): Record<string, unknown> | undefined {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}
