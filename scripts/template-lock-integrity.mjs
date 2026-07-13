/**
 * Shared helpers for verifying @paybond/kit package-lock integrity against npm.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { existsSync, readdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";

/** @param {string} version */
export function isKitVersionOnRegistry(version) {
  try {
    execSync(`npm view @paybond/kit@${version} version`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

/** @param {string} version */
export function fetchKitRegistryIntegrity(version) {
  try {
    return execSync(`npm view @paybond/kit@${version} dist.integrity`, {
      stdio: "pipe",
      encoding: "utf8",
    }).trim();
  } catch {
    return undefined;
  }
}

/** @param {string} tarballPath */
export async function computeTarballIntegrity(tarballPath) {
  const bytes = await readFile(tarballPath);
  const digest = createHash("sha512").update(bytes).digest("base64");
  return `sha512-${digest}`;
}

/**
 * @param {string} kitVersion
 * @param {{ tarballPath?: string }} [options]
 */
export async function resolveKitLockIntegrity(kitVersion, options = {}) {
  const registryIntegrity = fetchKitRegistryIntegrity(kitVersion);
  if (registryIntegrity) {
    return registryIntegrity;
  }
  if (options.tarballPath) {
    return computeTarballIntegrity(options.tarballPath);
  }
  return undefined;
}

/** @param {string} version */
export function kitRegistryResolved(version) {
  return `https://registry.npmjs.org/@paybond/kit/-/kit-${version}.tgz`;
}

/**
 * @param {Record<string, unknown>} lock
 * @returns {{ key: string, entry: Record<string, unknown> } | undefined}
 */
export function findKitLockEntry(lock) {
  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    if (key === "node_modules/@paybond/kit" || entry.name === "@paybond/kit") {
      return { key, entry: /** @type {Record<string, unknown>} */ (entry) };
    }
  }
  return undefined;
}

/**
 * Keep package.json @paybond/kit range aligned with the stamped lock range.
 * @param {string} packageJsonPath
 * @param {string} kitVersion
 */
export async function patchKitPackageJsonRange(packageJsonPath, kitVersion) {
  if (!existsSync(packageJsonPath)) {
    return;
  }
  const pkg = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const kitRange = `^${kitVersion}`;
  if (!pkg.dependencies?.["@paybond/kit"]) {
    return;
  }
  if (pkg.dependencies["@paybond/kit"] === kitRange) {
    return;
  }
  pkg.dependencies["@paybond/kit"] = kitRange;
  await writeFile(packageJsonPath, `${JSON.stringify(pkg, null, 2)}\n`);
}

/**
 * @param {string} lockPath
 * @param {string} kitVersion
 * @param {string} registryIntegrity
 */
export async function patchKitLockIntegrity(lockPath, kitVersion, registryIntegrity) {
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  const kitRange = `^${kitVersion}`;
  const registryResolved = kitRegistryResolved(kitVersion);

  if (lock.packages?.[""]?.dependencies?.["@paybond/kit"]) {
    lock.packages[""].dependencies["@paybond/kit"] = kitRange;
  }

  const found = findKitLockEntry(lock);
  if (!found) {
    throw new Error(`${lockPath}: no @paybond/kit entry in package-lock.json`);
  }

  const { entry } = found;
  entry.version = kitVersion;
  entry.resolved = registryResolved;
  delete entry.link;
  entry.integrity = registryIntegrity;

  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);

  // package.json must declare the same range or `npm ci` rejects the lockfile.
  await patchKitPackageJsonRange(join(dirname(lockPath), "package.json"), kitVersion);
}

/**
 * @param {string} templatesDir
 * @param {string} kitVersion
 * @param {{ fix?: boolean, registryIntegrity?: string }} [options]
 */
export async function verifyTemplateLockIntegrity(templatesDir, kitVersion, options = {}) {
  const registryIntegrity =
    options.registryIntegrity ?? fetchKitRegistryIntegrity(kitVersion);

  if (!registryIntegrity) {
    throw new Error(
      `Cannot verify template lockfiles: @paybond/kit@${kitVersion} is not on npm ` +
        `(or dist.integrity is unavailable). Publish the kit first.`,
    );
  }

  const registryResolved = kitRegistryResolved(kitVersion);
  const mismatches = [];

  for (const repo of readdirSync(templatesDir, { withFileTypes: true })) {
    if (!repo.isDirectory()) {
      continue;
    }
    const lockPath = join(templatesDir, repo.name, "package-lock.json");
    if (!existsSync(lockPath)) {
      continue;
    }

    const packageJsonPath = join(templatesDir, repo.name, "package.json");
    const lock = JSON.parse(await readFile(lockPath, "utf8"));
    const found = findKitLockEntry(lock);
    if (!found) {
      continue;
    }

    const { entry } = found;
    const kitRange = `^${kitVersion}`;
    const problems = [];
    if (entry.integrity !== registryIntegrity) {
      problems.push(
        `integrity ${entry.integrity ?? "(missing)"} != registry ${registryIntegrity}`,
      );
    }
    if (entry.resolved !== registryResolved) {
      problems.push(
        `resolved ${entry.resolved ?? "(missing)"} != registry ${registryResolved}`,
      );
    }
    if (entry.version !== kitVersion) {
      problems.push(`version ${entry.version ?? "(missing)"} != ${kitVersion}`);
    }

    if (existsSync(packageJsonPath)) {
      const pkg = JSON.parse(await readFile(packageJsonPath, "utf8"));
      const declared = pkg.dependencies?.["@paybond/kit"];
      if (declared && declared !== kitRange) {
        problems.push(
          `package.json @paybond/kit ${declared} != ${kitRange} (npm ci requires lock sync)`,
        );
      }
      const lockRange = lock.packages?.[""]?.dependencies?.["@paybond/kit"];
      if (declared && lockRange && declared !== lockRange) {
        problems.push(
          `package.json @paybond/kit ${declared} != lock ${lockRange}`,
        );
      }
    }

    if (problems.length > 0) {
      mismatches.push({ repo: repo.name, lockPath, problems });
      if (options.fix) {
        await patchKitLockIntegrity(lockPath, kitVersion, registryIntegrity);
      }
    }
  }

  return { registryIntegrity, mismatches };
}
