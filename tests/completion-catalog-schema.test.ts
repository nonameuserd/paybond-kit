import { Ajv2020 } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { getCompletionPresetByTemplateId, loadCompletionCatalog } from "../src/completion-catalog.js";
import { verifyCatalogVendorContracts } from "../src/completion-contract-digest.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CATALOG_DIR = join(MODULE_DIR, "../../completion-presets");

describe("completion catalog schema", () => {
  it("validates catalog.json against catalog.schema.json", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(readFileSync(join(CATALOG_DIR, "catalog.schema.json"), "utf8"));
    const catalog = JSON.parse(readFileSync(join(CATALOG_DIR, "catalog.json"), "utf8"));
    const validate = ajv.compile(schema);
    const valid = validate(catalog);
    expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it("requires vendor_contract with matching digests on vendor_pack presets", () => {
    const catalog = loadCompletionCatalog();
    verifyCatalogVendorContracts(catalog);
    const vendorPacks = catalog.presets.filter((preset) => preset.kind === "vendor_pack");
    expect(vendorPacks).toHaveLength(9);
    for (const preset of vendorPacks) {
      expect(preset.vendor_contract, `${preset.preset_id}.vendor_contract`).toBeTruthy();
      expect(preset.vendor_contract?.quality_fields.length).toBeGreaterThan(0);
    }
  });

  it("requires scope, archetype_preset_id, and forbidden_evidence_fields on vendor_pack presets", () => {
    const catalog = loadCompletionCatalog();
    const vendorPacks = catalog.presets.filter((preset) => preset.kind === "vendor_pack");
    expect(vendorPacks.length).toBeGreaterThan(0);
    for (const preset of vendorPacks) {
      expect(preset.scope, `${preset.preset_id}.scope`).toBe("tool_completion");
      expect(preset.archetype_preset_id, `${preset.preset_id}.archetype_preset_id`).toBeTruthy();
      expect(
        preset.forbidden_evidence_fields?.length,
        `${preset.preset_id}.forbidden_evidence_fields`,
      ).toBeGreaterThan(0);
    }
  });

  it("prefers archetype presets when resolving by harbor template id", () => {
    const preset = getCompletionPresetByTemplateId("api_response_v1");
    expect(preset?.preset_id).toBe("api_response_ok");
    expect(preset?.kind).not.toBe("vendor_pack");
  });
});
