import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { loadCompletionCatalog } from "../src/completion-catalog.js";
import { BUNDLED_COMPLETION_CATALOG_SHA256_HEX } from "../src/completion-catalog-digest.js";
import { verifyBundledCompletionCatalogIntegrity } from "../src/completion-catalog-integrity.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const CATALOG_PATH = join(MODULE_DIR, "../completion-presets/catalog.json");

describe("completion catalog integrity", () => {
  it("loads bundled catalog when bytes match embedded digest", () => {
    const catalog = loadCompletionCatalog();
    expect(catalog.presets.length).toBeGreaterThan(0);
  });

  it("verifies canonical catalog bytes against embedded digest", () => {
    const raw = readFileSync(CATALOG_PATH, "utf8");
    verifyBundledCompletionCatalogIntegrity(raw);
  });

  it("rejects tampered catalog bytes", () => {
    expect(() => verifyBundledCompletionCatalogIntegrity('{"version":1,"presets":[]}')).toThrow(
      /integrity check failed/,
    );
  });

  it("embeds a valid sha256 hex digest", () => {
    expect(BUNDLED_COMPLETION_CATALOG_SHA256_HEX).toMatch(/^[0-9a-f]{64}$/);
  });
});
