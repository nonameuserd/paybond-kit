#!/usr/bin/env node
/**
 * Verify starter-template package-lock.json @paybond/kit integrity against npm.
 *
 * Usage:
 *   node kit/ts/scripts/verify-template-lock-integrity.mjs
 *   node kit/ts/scripts/verify-template-lock-integrity.mjs --fix
 *   node kit/ts/scripts/verify-template-lock-integrity.mjs --templates-dir=/path/to/templates
 */
import { mkdir, readFile } from "node:fs/promises";
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  fetchKitRegistryIntegrity,
  resolveKitLockIntegrity,
  verifyTemplateLockIntegrity,
} from "./template-lock-integrity.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const KIT_TS_DIR = join(SCRIPT_DIR, "..");
const REPO_ROOT = join(KIT_TS_DIR, "../..");

const args = process.argv.slice(2);
const fix = args.includes("--fix");
const templatesDirArg = args.find((arg) => arg.startsWith("--templates-dir="));
const templatesDir = templatesDirArg
  ? templatesDirArg.slice("--templates-dir=".length)
  : join(REPO_ROOT, "templates");

const kitPackageJson = JSON.parse(
  await readFile(join(KIT_TS_DIR, "package.json"), "utf8"),
);
const kitVersion = kitPackageJson.version;

async function packKitIfNeeded(version) {
  if (fetchKitRegistryIntegrity(version)) {
    return undefined;
  }
  const packDir = join(KIT_TS_DIR, ".template-pack");
  await mkdir(packDir, { recursive: true });
  const output = execSync(
    `npm pack --pack-destination "${packDir}" --silent --ignore-scripts`,
    { cwd: KIT_TS_DIR, encoding: "utf8" },
  );
  const tarballName = output.trim().split("\n").filter(Boolean).at(-1);
  if (!tarballName) {
    return undefined;
  }
  const tarballPath = join(packDir, tarballName);
  console.warn(
    `@paybond/kit@${version} is not on npm yet; verifying lockfiles against local npm pack integrity.`,
  );
  return tarballPath;
}

const tarballPath = await packKitIfNeeded(kitVersion);
const registryIntegrity = await resolveKitLockIntegrity(kitVersion, { tarballPath });
if (!registryIntegrity) {
  console.error(
    `Cannot verify template lockfiles: @paybond/kit@${kitVersion} is not on npm ` +
      `and local npm pack failed.`,
  );
  process.exit(1);
}

const { mismatches } = await verifyTemplateLockIntegrity(templatesDir, kitVersion, {
  fix,
  registryIntegrity,
});

if (mismatches.length === 0) {
  console.log(
    `OK: all template lockfiles match @paybond/kit@${kitVersion} ` +
      `(${registryIntegrity})`,
  );
  process.exit(0);
}

for (const { repo, problems } of mismatches) {
  console.error(`FAIL: ${repo}`);
  for (const problem of problems) {
    console.error(`  - ${problem}`);
  }
}

if (fix) {
  console.log(`Patched ${mismatches.length} lockfile(s) to registry integrity.`);
  process.exit(0);
}

console.error("");
console.error(
  "Template lockfiles are out of sync with the published npm tarball.",
);
console.error("Fix with:");
console.error("  node kit/ts/scripts/generate-templates.mjs");
console.error("Or patch in place:");
console.error("  node kit/ts/scripts/verify-template-lock-integrity.mjs --fix");
process.exit(1);
