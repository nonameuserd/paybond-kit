import { createHash } from "node:crypto";

import { BUNDLED_COMPLETION_CATALOG_SHA256_HEX } from "./completion-catalog-digest.js";

const INTEGRITY_SKIP = "skip";

function integrityCheckSkipped(): boolean {
  return process.env.PAYBOND_COMPLETION_CATALOG_INTEGRITY?.trim().toLowerCase() === INTEGRITY_SKIP;
}

/** Verifies raw catalog bytes against the bundled SHA-256 digest. */
export function verifyBundledCompletionCatalogIntegrity(raw: Buffer | string): void {
  if (integrityCheckSkipped()) {
    return;
  }
  const bytes = typeof raw === "string" ? Buffer.from(raw, "utf8") : raw;
  const digest = createHash("sha256").update(bytes).digest("hex");
  if (digest !== BUNDLED_COMPLETION_CATALOG_SHA256_HEX) {
    throw new Error(
      `completion preset catalog integrity check failed (sha256=${digest}, expected=${BUNDLED_COMPLETION_CATALOG_SHA256_HEX})`,
    );
  }
}
