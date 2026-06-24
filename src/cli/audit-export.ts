import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";

import { verify as ed25519Verify } from "@noble/ed25519";

import { ensureEd25519Sha512Sync } from "../ed25519-sync.js";
import { CliError } from "./types.js";

export const MANIFEST_CORE_FIELD_ORDER = [
  "schema_version",
  "kind",
  "tenant_realm_id",
  "job_id",
  "generated_at_rfc3339",
  "gateway_build_version",
  "score_model_version",
  "disclosure_tier",
  "redaction_profile",
  "checkpoint_last_ledger_seq",
  "export_filter",
  "artifacts",
] as const;

export function buildManifestCore(manifest: Record<string, unknown>): Record<string, unknown> {
  const core: Record<string, unknown> = {};
  for (const key of MANIFEST_CORE_FIELD_ORDER) {
    if (key === "checkpoint_last_ledger_seq") {
      if (!(key in manifest)) {
        continue;
      }
      const value = manifest[key];
      if (value === 0 || value === null) {
        continue;
      }
      core[key] = value;
      continue;
    }
    if (key in manifest) {
      core[key] = manifest[key];
    }
  }
  return core;
}

export function manifestCoreBytes(manifest: Record<string, unknown>): Uint8Array {
  const core = buildManifestCore(manifest);
  return new TextEncoder().encode(JSON.stringify(core));
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim();
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export function verifyAuditManifest(manifest: Record<string, unknown>): boolean {
  const coreBytes = manifestCoreBytes(manifest);
  const digest = createHash("sha256").update(coreBytes).digest();
  const expected = String(manifest.signed_payload_sha256_hex ?? "").trim().toLowerCase();
  if (bytesToHex(new Uint8Array(digest)) !== expected) {
    return false;
  }
  const signatureHex = String(manifest.ed25519_signature_hex ?? "").trim();
  const publicKeyHex = String(manifest.signing_public_key_ed25519_hex ?? "").trim();
  if (!signatureHex || !publicKeyHex) {
    return false;
  }
  ensureEd25519Sha512Sync();
  return ed25519Verify(hexToBytes(signatureHex), digest, hexToBytes(publicKeyHex));
}

export function auditVerifyResult(manifest: Record<string, unknown>, path: string): Record<string, unknown> {
  return {
    verified: verifyAuditManifest(manifest),
    manifest_kind: String(manifest.kind ?? ""),
    tenant_realm_id: String(manifest.tenant_realm_id ?? ""),
    job_id: String(manifest.job_id ?? ""),
    path,
  };
}

export async function readManifestFromBundle(bundlePath: string, cwd: string): Promise<string> {
  if (bundlePath.endsWith(".zip")) {
    const result = await new Promise<{ code: number | null; stdout: string; stderr: string }>((resolvePromise) => {
      const child = spawn("unzip", ["-p", bundlePath, "manifest.json"], { cwd });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk: string | Uint8Array) => {
        stdout += String(chunk);
      });
      child.stderr.on("data", (chunk: string | Uint8Array) => {
        stderr += String(chunk);
      });
      child.on("close", (code: number | null) => resolvePromise({ code, stdout, stderr }));
      child.on("error", () => resolvePromise({ code: 127, stdout: "", stderr: "unzip not found" }));
    });
    if (result.code !== 0 || !result.stdout.trim()) {
      throw new CliError(result.stderr.trim() || "unable to read manifest.json from ZIP bundle", {
        category: "validation",
        code: "cli.audit.bundle_read_failed",
      });
    }
    return result.stdout;
  }
  const manifestPath = bundlePath.endsWith("manifest.json")
    ? bundlePath
    : `${bundlePath.replace(/\/+$/, "")}/manifest.json`;
  return readFile(manifestPath, "utf8");
}

export async function verifyAuditBundleLocal(path: string, cwd: string): Promise<Record<string, unknown>> {
  const manifestRaw = await readManifestFromBundle(path, cwd);
  const manifest = JSON.parse(manifestRaw) as Record<string, unknown>;
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    throw new CliError("manifest.json must be a JSON object", {
      category: "validation",
      code: "cli.audit.invalid_manifest",
    });
  }
  return auditVerifyResult(manifest, path);
}
