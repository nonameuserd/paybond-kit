import { cpSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const npmBin = process.env.npm_execpath ?? "npm";
const tscBin = resolve(repoRoot, "node_modules", ".bin", "tsc");
const npmCache = resolve(repoRoot, ".npm-cache");

function run(cmd, args, cwd, options = {}) {
  return execFileSync(cmd, args, {
    cwd,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
    env: {
      ...process.env,
      NPM_CONFIG_CACHE: npmCache,
    },
    ...options,
  });
}

function runLogged(cmd, args, cwd) {
  execFileSync(cmd, args, {
    cwd,
    stdio: "inherit",
    env: {
      ...process.env,
      NPM_CONFIG_CACHE: npmCache,
    },
  });
}

runLogged(npmBin, ["run", "test"], repoRoot);
runLogged(npmBin, ["run", "build"], repoRoot);

const packJson = run(npmBin, ["pack", "--json"], repoRoot);
const packMeta = JSON.parse(packJson);
const tarball = resolve(repoRoot, packMeta[0].filename);

const packedFiles = run("tar", ["-tf", tarball], repoRoot)
  .trim()
  .split("\n")
  .filter(Boolean);

for (const banned of [
  "package/dist/index.test.js",
  "package/dist/index.test.d.ts",
  "package/dist/principal-intent-v2.js",
  "package/dist/principal-intent-v2.d.ts",
]) {
  if (packedFiles.includes(banned)) {
    throw new Error(`packed tarball should not include ${banned}`);
  }
}

for (const required of ["package/README.md", "package/LICENSE"]) {
  if (!packedFiles.includes(required)) {
    throw new Error(`packed tarball must include ${required}`);
  }
}

const scratch = mkdtempSync(join(tmpdir(), "paybond-kit-ts-"));
try {
  runLogged("tar", ["-xf", tarball, "-C", scratch], repoRoot);
  const consumerRoot = join(scratch, "consumer");
  const consumerNodeModules = join(consumerRoot, "node_modules");
  mkdirSync(consumerRoot, { recursive: true });
  mkdirSync(join(consumerNodeModules, "@paybond"), { recursive: true });
  cpSync(join(scratch, "package"), join(consumerNodeModules, "@paybond", "kit"), {
    recursive: true,
  });
  symlinkSync(resolve(repoRoot, "node_modules", "uuid"), join(consumerNodeModules, "uuid"), "dir");
  symlinkSync(resolve(repoRoot, "node_modules", "blake3"), join(consumerNodeModules, "blake3"), "dir");
  symlinkSync(resolve(repoRoot, "node_modules", "@noble"), join(consumerNodeModules, "@noble"), "dir");

  writeFileSync(
    join(consumerRoot, "package.json"),
    JSON.stringify(
      {
        name: "paybond-kit-smoke",
        private: true,
        type: "module",
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(consumerRoot, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noEmit: true,
        },
        include: ["index.ts"],
      },
      null,
      2,
    ),
  );
  writeFileSync(
    join(consumerRoot, "index.ts"),
    [
      'import { Paybond, HarborClient } from "@paybond/kit";',
      "",
      'const harbor = new HarborClient("https://harbor.example.com", "tenant-a");',
      'void harbor.tenantId;',
      'void Paybond;',
      "",
    ].join("\n"),
  );

  runLogged(tscBin, ["-p", consumerRoot], consumerRoot);
  runLogged(
    "node",
    [
      "--input-type=module",
      "-e",
      'const mod = await import("@paybond/kit"); if (!mod.Paybond || !mod.HarborClient) throw new Error("missing exports");',
    ],
    consumerRoot,
  );
} finally {
  rmSync(scratch, { force: true, recursive: true });
  rmSync(tarball, { force: true });
}
