/** Wire types for Gateway `GET /v1/compliance/audit-exports` responses. */

export type AuditExportJobSummary = Readonly<{
  id: string;
  status: string;
  disclosure_tier: string;
  created_at: string;
  expires_at: string;
  manifest_sha256: string;
  bundle_sha256: string;
  bundle_size_bytes: number;
}>;

export type AuditExportListPage = Readonly<{
  tenant_realm_id: string;
  jobs: ReadonlyArray<AuditExportJobSummary>;
  next_cursor?: string;
}>;

export type AuditExportJobDetail = Readonly<{
  id: string;
  status: string;
  tenant_realm_id: string;
  disclosure_tier: string;
  created_at: string;
  expires_at: string;
  error: string;
  manifest_sha256: string;
  bundle_sha256: string;
  download_token?: string;
}>;

export type AuditExportJobGetResponse = Readonly<{
  job: AuditExportJobDetail;
}>;

export type AuditVerifyResult = Readonly<{
  verified: boolean;
  manifest_kind: string;
  tenant_realm_id: string;
  job_id: string;
  path?: string;
}>;

function assertJsonObject(value: unknown): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Expected JSON object");
  }
}

function readString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function readNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`Invalid ${field}`);
  }
  return value;
}

function extractNextCursor(body: Record<string, unknown>): string | undefined {
  const cursor = body.next_cursor ?? body.nextCursor;
  if (typeof cursor === "string" && cursor.trim()) {
    return cursor.trim();
  }
  return undefined;
}

/** Parses list response from `GET /v1/compliance/audit-exports`. */
export function parseAuditExportList(json: unknown): AuditExportListPage {
  assertJsonObject(json);
  const tenantRealmId = readString(json.tenant_realm_id, "tenant_realm_id");
  const jobsRaw = json.jobs ?? json.items ?? json.exports;
  if (!Array.isArray(jobsRaw)) {
    throw new Error("Invalid export list: jobs");
  }
  const jobs: AuditExportJobSummary[] = jobsRaw.map((row) => {
    assertJsonObject(row);
    return {
      id: readString(row.id ?? row.job_id, "jobs[].id"),
      status: readString(row.status, "jobs[].status"),
      disclosure_tier: readString(row.disclosure_tier, "jobs[].disclosure_tier"),
      created_at: readString(row.created_at, "jobs[].created_at"),
      expires_at: readString(row.expires_at, "jobs[].expires_at"),
      manifest_sha256: typeof row.manifest_sha256 === "string" ? row.manifest_sha256 : "",
      bundle_sha256: typeof row.bundle_sha256 === "string" ? row.bundle_sha256 : "",
      bundle_size_bytes: readNumber(row.bundle_size_bytes ?? 0, "jobs[].bundle_size_bytes"),
    };
  });
  const nextCursor = extractNextCursor(json);
  return nextCursor ? { tenant_realm_id: tenantRealmId, jobs, next_cursor: nextCursor } : { tenant_realm_id: tenantRealmId, jobs };
}

/** Parses job detail from `GET /v1/compliance/audit-exports/{id}`. */
export function parseAuditExportJobGet(json: unknown): AuditExportJobGetResponse {
  assertJsonObject(json);
  const jobRaw = json.job ?? json;
  assertJsonObject(jobRaw);
  const job: AuditExportJobDetail = {
    id: readString(jobRaw.id ?? jobRaw.job_id, "job.id"),
    status: readString(jobRaw.status, "job.status"),
    tenant_realm_id: readString(jobRaw.tenant_realm_id, "job.tenant_realm_id"),
    disclosure_tier: readString(jobRaw.disclosure_tier, "job.disclosure_tier"),
    created_at: readString(jobRaw.created_at, "job.created_at"),
    expires_at: readString(jobRaw.expires_at, "job.expires_at"),
    error: typeof jobRaw.error === "string" ? jobRaw.error : "",
    manifest_sha256: typeof jobRaw.manifest_sha256 === "string" ? jobRaw.manifest_sha256 : "",
    bundle_sha256: typeof jobRaw.bundle_sha256 === "string" ? jobRaw.bundle_sha256 : "",
    download_token:
      typeof jobRaw.download_token === "string" && jobRaw.download_token ? jobRaw.download_token : undefined,
  };
  return { job };
}
