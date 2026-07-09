import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { getCompletionPreset, jsonLiteral } from "../src/completion-catalog.js";
import {
  isStripeFundingWebhookEventType,
  runCompletionCatalogDoctorChecks,
} from "../src/doctor-completion.js";
import { resolveCompletionPreset } from "../src/completion-resolve.js";

function buildScaffoldBody(presetId: string, overrides: { parameters?: Record<string, unknown>; evidenceSchema?: Record<string, unknown> } = {}): string {
  const resolved = resolveCompletionPreset(presetId);
  const preset = resolved.preset;
  const parameters = overrides.parameters ?? resolved.parameters;
  const evidenceSchema = overrides.evidenceSchema ?? preset.evidence_schema;
  return `export const COMPLETION_PRESET_ID = "${presetId}";
export const completionEvidenceSchema = ${jsonLiteral(evidenceSchema)} as const;
export const completionTemplateParameters = ${jsonLiteral(parameters)} as const;
`;
}

describe("doctor-completion", () => {
  it("detects deprecated stripe_webhook_payment preset in scaffolds", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-"));
    await writeFile(
      join(cwd, "paybond-completion-stripe-webhook-payment.ts"),
      buildScaffoldBody("stripe_webhook_payment"),
      "utf8",
    );

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const deprecated = checks.find((check) => check.name === "completion_deprecated_preset");
    expect(deprecated?.message).toContain("warn:");
    expect(deprecated?.message).toContain("vendor_webhook_confirmed");
  });

  it("warns when scaffold evidence schema includes forbidden fields", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-"));
    const preset = getCompletionPreset("ach_paid_api_ok");
    const pollutedSchema = {
      ...preset.evidence_schema,
      properties: {
        ...(preset.evidence_schema.properties as Record<string, unknown>),
        payment_intent_id: { type: "string" },
      },
    };
    await writeFile(
      join(cwd, "paybond-completion-ach-paid-api-ok.ts"),
      buildScaffoldBody("ach_paid_api_ok", { evidenceSchema: pollutedSchema }),
      "utf8",
    );

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const forbidden = checks.find((check) => check.name === "completion_forbidden_fields");
    expect(forbidden?.message).toContain("payment_intent_id");
  });

  it("warns when webhook_confirmed scaffold uses Stripe funding event types", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-"));
    await writeFile(
      join(cwd, "paybond-completion-webhook-confirmed.ts"),
      buildScaffoldBody("webhook_confirmed", {
        parameters: {
          event_type_path: ["event_type"],
          expected_event_type: "payment_intent.succeeded",
        },
      }),
      "utf8",
    );

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const funding = checks.find((check) => check.name === "completion_funding_event_misuse");
    expect(funding?.message).toContain("payment_intent.succeeded");
  });

  it("flags Stripe funding webhook event types", () => {
    expect(isStripeFundingWebhookEventType("payment_intent.succeeded")).toBe(true);
    expect(isStripeFundingWebhookEventType("charge.succeeded")).toBe(true);
    expect(isStripeFundingWebhookEventType("job.completed")).toBe(false);
  });

  it("warns when vendor pack scaffold contract pin lags catalog", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-pack-"));
    const preset = getCompletionPreset("stripe_charge");
    const body = `export const COMPLETION_PRESET_ID = "stripe_charge";
export const VENDOR_CONTRACT_API_VERSION = "legacy_epoch";
export const VENDOR_SCHEMA_DIGEST_HEX = "${preset.vendor_contract?.schema_digest_hex}";
export const CANONICAL_SCHEMA_DIGEST_HEX = "${preset.vendor_contract?.canonical_schema_digest_hex}";
export const completionEvidenceSchema = ${jsonLiteral(preset.evidence_schema)} as const;
export const completionTemplateParameters = ${jsonLiteral(resolveCompletionPreset("stripe_charge").parameters)} as const;
`;
    await writeFile(join(cwd, "paybond-completion-stripe-charge.ts"), body, "utf8");

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const packStale = checks.find((check) => check.name === "completion_pack_stale");
    expect(packStale?.message).toContain("warn:");
    expect(packStale?.message).toContain("legacy_epoch");
  });

  it("includes Stripe tool metadata binding checklist item", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-meta-"));
    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const binding = checks.find((check) => check.name === "stripe_tool_metadata_binding");
    expect(binding?.ok).toBe(true);
    expect(binding?.message).toMatch(/Stripe tool metadata binding/i);
  });

  it("warns when Stripe-wrapping sources omit metadata helpers", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-meta-missing-"));
    await mkdir(join(cwd, "src"), { recursive: true });
    await writeFile(
      join(cwd, "src", "charge.ts"),
      `
export async function charge(stripe: { paymentIntents: { create: Function } }) {
  return stripe.paymentIntents.create({ amount: 100, currency: "usd" });
}
`,
      "utf8",
    );

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const binding = checks.find((check) => check.name === "stripe_tool_metadata_binding");
    expect(binding?.ok).toBe(true);
    expect(binding?.message).toContain("warn:");
    expect(binding?.message).toContain("buildPaybondStripeMetadata");
    expect(binding?.details?.missing_helper_files).toContain("src/charge.ts");
  });

  it("passes Stripe metadata binding when helpers are used", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-doctor-meta-ok-"));
    await mkdir(join(cwd, "src"), { recursive: true });
    await writeFile(
      join(cwd, "src", "charge.ts"),
      `
import { buildPaybondStripeMetadata } from "@paybond/kit";
export async function charge(stripe: { paymentIntents: { create: Function } }, tenantId: string, intentId: string) {
  const metadata = buildPaybondStripeMetadata({ tenantId, intentId });
  return stripe.paymentIntents.create({ amount: 100, currency: "usd", metadata });
}
`,
      "utf8",
    );

    const checks = await runCompletionCatalogDoctorChecks({ cwd });
    const binding = checks.find((check) => check.name === "stripe_tool_metadata_binding");
    expect(binding?.ok).toBe(true);
    expect(binding?.message).not.toContain("warn:");
    expect(binding?.message).toContain("reference Paybond metadata helpers");
  });
});
