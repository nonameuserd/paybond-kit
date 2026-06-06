import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
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

function runCombined(cmd, args, cwd) {
  const result = spawnSync(cmd, args, {
    cwd,
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8",
    env: {
      ...process.env,
      NPM_CONFIG_CACHE: npmCache,
    },
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} exited ${result.status}:\n${output}`);
  }
  return output;
}

function assertIncludesAll(text, fragments, label) {
  for (const fragment of fragments) {
    if (!text.includes(fragment)) {
      throw new Error(`${label} missing expected fragment: ${fragment}`);
    }
  }
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

for (const required of ["package/README.md", "package/LICENSE", "package/dist/login.js", "package/dist/login.d.ts"]) {
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
  const consumerBinRoot = join(consumerNodeModules, ".bin");
  mkdirSync(consumerBinRoot, { recursive: true });
  const loginBin = join(consumerBinRoot, "paybond");
  const initBin = join(consumerBinRoot, "paybond-init");
  const mcpBin = join(consumerBinRoot, "paybond-mcp-server");
  symlinkSync(join(consumerNodeModules, "@paybond", "kit", "dist", "login.js"), loginBin, "file");
  symlinkSync(join(consumerNodeModules, "@paybond", "kit", "dist", "init.js"), initBin, "file");
  symlinkSync(join(consumerNodeModules, "@paybond", "kit", "dist", "mcp-server.js"), mcpBin, "file");

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

  const loginCli = join(consumerNodeModules, "@paybond", "kit", "dist", "login.js");
  const loginHelp = run("node", [loginCli, "--help"], consumerRoot);
  assertIncludesAll(loginHelp, ["paybond login", "--env-file", "--gateway", "--no-open", "--force"], "paybond login help");
  const loginBinHelp = run("node", [loginBin, "--help"], consumerRoot);
  assertIncludesAll(loginBinHelp, ["paybond login", "--env-file", "--gateway", "--no-open", "--force"], "paybond .bin help");

  const initCli = join(consumerNodeModules, "@paybond", "kit", "dist", "init.js");
  const initBinHelp = run("node", [initBin, "--help"], consumerRoot);
  assertIncludesAll(initBinHelp, ["paybond-init", "paid-tool-guard", "--framework"], "paybond-init .bin help");
  const mcpBinHelp = runCombined("node", [mcpBin, "--help"], consumerRoot);
  assertIncludesAll(mcpBinHelp, ["paybond-mcp-server", "PAYBOND_API_KEY"], "paybond-mcp-server .bin help");

  const scaffoldPath = join(consumerRoot, "paybond-paid-tool-guard.ts");
  runLogged(
    "node",
    [
      initCli,
      "--preset",
      "paid-tool-guard",
      "--framework",
      "provider-agnostic",
      "--out",
      scaffoldPath,
    ],
    consumerRoot,
  );
  assertIncludesAll(
    readFileSync(scaffoldPath, "utf8"),
    [
      "declare const process",
      "openPaybondFromEnv",
      "loadPaybondEnvFile",
      "Production integration helpers only.",
      "bootstrapSandboxGuardrailIntent",
      "wrapPaidTool",
      "submitSandboxEvidence",
      "paybond.guardrails.bootstrapSandbox",
      "paybond.spendGuard(guardrail.intent_id, guardrail.capability_token)",
      "paybond.guardrails.submitSandboxEvidence",
      "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
    ],
    "paybond-init scaffold",
  );
  const symlinkScaffoldPath = join(consumerRoot, "paybond-symlink-tool-guard.ts");
  runLogged(
    "node",
    [
      initBin,
      "--preset",
      "paid-tool-guard",
      "--framework",
      "provider-agnostic",
      "--out",
      symlinkScaffoldPath,
    ],
    consumerRoot,
  );
  assertIncludesAll(
    readFileSync(symlinkScaffoldPath, "utf8"),
    ["openPaybondFromEnv", "bootstrapSandboxGuardrailIntent", "submitSandboxEvidence"],
    "paybond-init .bin scaffold",
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
        include: ["index.ts", "paybond-paid-tool-guard.ts"],
      },
      null,
      2,
    ),
  );
  runLogged(tscBin, ["-p", consumerRoot], consumerRoot);
  for (const banned of ["replaceableSmokeTestPaidTool", "runSandboxSmokePath", "sandbox-confirmation"]) {
    if (readFileSync(scaffoldPath, "utf8").includes(banned)) {
      throw new Error(`paybond-init scaffold should not include generated paid-tool implementation fragment: ${banned}`);
    }
  }

  let blockedOverwrite = false;
  try {
    run(
      "node",
      [
        initCli,
        "--preset",
        "paid-tool-guard",
        "--out",
        scaffoldPath,
      ],
      consumerRoot,
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (err) {
    const stderr = err && typeof err === "object" && "stderr" in err ? String(err.stderr) : "";
    blockedOverwrite = stderr.includes("already exists");
  }
  if (!blockedOverwrite) {
    throw new Error("paybond-init must refuse to overwrite scaffolds without --force");
  }

  runLogged(
    "node",
    [
      initCli,
      "--preset",
      "paid-tool-guard",
      "--framework",
      "mcp",
      "--out",
      scaffoldPath,
      "--force",
    ],
    consumerRoot,
  );
  assertIncludesAll(
    readFileSync(scaffoldPath, "utf8"),
    ["Call the guarded handler inside the MCP tool implementation before paid or external work runs."],
    "paybond-init --force scaffold",
  );
} finally {
  rmSync(scratch, { force: true, recursive: true });
  rmSync(tarball, { force: true });
}
