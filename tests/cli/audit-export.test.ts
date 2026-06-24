import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  auditVerifyResult,
  buildManifestCore,
  verifyAuditManifest,
} from "../../src/cli/audit-export.js";

const FIXTURE_PATH = join(
  process.cwd(),
  "..",
  "cli-parity",
  "fixtures",
  "signed_audit_manifest.json",
);

describe("audit export verify", () => {
  it("builds manifest core in gateway field order", () => {
    const core = buildManifestCore({
      job_id: "job-1",
      kind: "paybond.audit_export_manifest_v1",
      schema_version: 1,
      signing_public_key_ed25519_hex: "ignored",
    });
    expect(Object.keys(core)).toEqual(["schema_version", "kind", "job_id"]);
  });

  it("verifies the shared signed audit manifest fixture and rejects tampering", () => {
    const manifest = JSON.parse(readFileSync(FIXTURE_PATH, "utf8")) as Record<
      string,
      unknown
    >;
    expect(verifyAuditManifest(manifest)).toBe(true);
    expect(auditVerifyResult(manifest, "bundle.zip").verified).toBe(true);

    const tampered = { ...manifest, tenant_realm_id: "realm_other" };
    expect(verifyAuditManifest(tampered)).toBe(false);
  });
});
