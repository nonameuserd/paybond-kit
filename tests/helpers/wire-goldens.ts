import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type EvidenceSignV1GoldenExpected = {
  evidence_sign_version: number;
  payload_digest_hex: string;
  artifacts_digest_hex: string;
  sign_bytes_hex: string;
};

export type EvidenceSignV1GoldenInput = {
  tenant_id: string;
  intent_id: string;
  payee_did: string;
  payload: Record<string, unknown>;
  artifacts_blake3_hex: string[];
  submitted_at_rfc3339: string;
};

export type EvidenceSignV1Golden = {
  input: EvidenceSignV1GoldenInput;
  expected: EvidenceSignV1GoldenExpected;
};

/** Walk parents until `kit/wire-goldens/evidence_sign_v1.json` is found. */
export function repoRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    const candidate = join(dir, "kit", "wire-goldens", "evidence_sign_v1.json");
    try {
      readFileSync(candidate, "utf8");
      return dir;
    } catch {
      const parent = dirname(dir);
      if (parent === dir) {
        throw new Error("kit/wire-goldens/evidence_sign_v1.json not found");
      }
      dir = parent;
    }
  }
}

/** Shared evidence signing fixture at kit/wire-goldens/evidence_sign_v1.json. */
export function loadEvidenceSignV1Golden(): EvidenceSignV1Golden {
  const path = join(repoRoot(), "kit", "wire-goldens", "evidence_sign_v1.json");
  return JSON.parse(readFileSync(path, "utf8")) as EvidenceSignV1Golden;
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
