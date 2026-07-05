import { describe, expect, it, vi } from "vitest";

import {
  PaybondAuditExports,
  parseAuditExportJobGet,
  parseAuditExportList,
} from "../../src/audit/index.js";
import { verifyAuditManifest } from "../../src/audit/verify.js";

describe("PaybondAuditExports", () => {
  it("list parses gateway jobs and next cursor", async () => {
    const gateway = {
      getJson: vi.fn().mockResolvedValue({
        tenant_realm_id: "realm-1",
        jobs: [
          {
            id: "job-1",
            status: "ready",
            disclosure_tier: "standard",
            created_at: "2026-01-01T00:00:00Z",
            expires_at: "2026-02-01T00:00:00Z",
            manifest_sha256: "abc",
            bundle_sha256: "def",
            bundle_size_bytes: 42,
          },
        ],
        next_cursor: "cursor-2",
      }),
    };
    const exports = PaybondAuditExports.fromGateway(gateway);
    const page = await exports.list({ limit: 10 });
    expect(page.tenant_realm_id).toBe("realm-1");
    expect(page.jobs).toHaveLength(1);
    expect(page.jobs[0]?.id).toBe("job-1");
    expect(page.next_cursor).toBe("cursor-2");
    expect(gateway.getJson).toHaveBeenCalledWith("/v1/compliance/audit-exports?limit=10");
  });

  it("get requests issue_download when asked", async () => {
    const gateway = {
      getJson: vi.fn().mockResolvedValue({
        job: {
          id: "job-1",
          status: "ready",
          tenant_realm_id: "realm-1",
          disclosure_tier: "standard",
          created_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-02-01T00:00:00Z",
          error: "",
          manifest_sha256: "",
          bundle_sha256: "",
          download_token: "tok",
        },
      }),
    };
    const exports = PaybondAuditExports.fromGateway(gateway);
    const body = await exports.get("job-1", { issueDownload: true });
    expect(body.job.download_token).toBe("tok");
    expect(gateway.getJson).toHaveBeenCalledWith(
      "/v1/compliance/audit-exports/job-1?issue_download=1",
    );
  });

  it("verify accepts manifest objects", async () => {
    const exports = PaybondAuditExports.fromGateway({ getJson: vi.fn() });
    const manifest = {
      schema_version: 1,
      kind: "paybond.audit_export_manifest_v1",
      tenant_realm_id: "realm-1",
      job_id: "job-1",
      signed_payload_sha256_hex: "00",
    };
    const result = await exports.verify(manifest);
    expect(result.verified).toBe(false);
    expect(result.job_id).toBe("job-1");
    expect(verifyAuditManifest(manifest)).toBe(false);
  });

  it("delete delegates to gateway deleteJson", async () => {
    const gateway = {
      getJson: vi.fn(),
      deleteJson: vi.fn().mockResolvedValue({}),
    };
    const exports = PaybondAuditExports.fromGateway(gateway);
    await expect(exports.delete("job-9")).resolves.toEqual({
      job_id: "job-9",
      deleted: true,
    });
    expect(gateway.deleteJson).toHaveBeenCalledWith("/v1/compliance/audit-exports/job-9");
  });
});

describe("audit export wire parsers", () => {
  it("parseAuditExportList accepts items alias", () => {
    const page = parseAuditExportList({
      tenant_realm_id: "realm-1",
      items: [
        {
          job_id: "job-2",
          status: "pending",
          disclosure_tier: "extended",
          created_at: "2026-01-02T00:00:00Z",
          expires_at: "2026-02-02T00:00:00Z",
          bundle_size_bytes: 0,
        },
      ],
    });
    expect(page.jobs[0]?.id).toBe("job-2");
  });

  it("parseAuditExportJobGet accepts top-level job payload", () => {
    const body = parseAuditExportJobGet({
      id: "job-3",
      status: "ready",
      tenant_realm_id: "realm-1",
      disclosure_tier: "standard",
      created_at: "2026-01-03T00:00:00Z",
      expires_at: "2026-02-03T00:00:00Z",
    });
    expect(body.job.id).toBe("job-3");
  });
});
