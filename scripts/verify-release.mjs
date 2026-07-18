import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const npmBin = process.env.npm_execpath ?? "npm";
const tscBin = resolve(repoRoot, "node_modules", ".bin", "tsc");
const npmCache = resolve(repoRoot, ".npm-cache");

function readJson(pathname) {
  return JSON.parse(readFileSync(pathname, "utf8"));
}

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

const packageJson = readJson(resolve(repoRoot, "package.json"));
const serverJsonPath = [resolve(repoRoot, "server.json"), resolve(repoRoot, "..", "..", "server.json")].find((path) =>
  existsSync(path),
);
if (!serverJsonPath) {
  throw new Error("could not find server.json in package root or monorepo root");
}
const rootServerJson = readJson(serverJsonPath);
const mcpServerSource = readFileSync(resolve(repoRoot, "src", "mcp-server.ts"), "utf8");
const mcpVersion = mcpServerSource.match(/const SERVER_VERSION = "([^"]+)";/)?.[1];
if (!mcpVersion) {
  throw new Error("could not read TypeScript MCP SERVER_VERSION from src/mcp-server.ts");
}
if (packageJson.version !== rootServerJson.version || packageJson.version !== mcpVersion) {
  throw new Error(
    `MCP version mismatch: kit/ts/package.json=${packageJson.version}, server.json=${rootServerJson.version}, src/mcp-server.ts=${mcpVersion}`,
  );
}
for (const pkg of rootServerJson.packages ?? []) {
  if (pkg.registryType === "npm" && pkg.version !== packageJson.version) {
    throw new Error(`server.json npm package version ${pkg.version} does not match ${packageJson.version}`);
  }
}

async function assertBuiltMcpServerInfoVersion(expectedVersion) {
  const { PaybondMCPServer } = await import(pathToFileURL(resolve(repoRoot, "dist", "mcp-server.js")).href);
  const server = new PaybondMCPServer({
    gatewayBaseUrl: "https://gateway.test",
    apiKey: `paybond_sk_${"a".repeat(32)}_${"b".repeat(64)}`,
  });
  const response = await server.handleMessage({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
  });
  const serverInfoVersion = response?.result?.serverInfo?.version;
  if (serverInfoVersion !== expectedVersion) {
    throw new Error(`TypeScript MCP initialize.serverInfo.version ${serverInfoVersion} does not match ${expectedVersion}`);
  }
}

runLogged(npmBin, ["run", "test"], repoRoot);
runLogged(npmBin, ["run", "build"], repoRoot);
await assertBuiltMcpServerInfoVersion(packageJson.version);

const packJson = run(npmBin, ["pack", "--json", "--ignore-scripts"], repoRoot);
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

for (const required of [
  "package/README.md",
  "package/LICENSE",
  "package/dist/login.js",
  "package/dist/login.d.ts",
  "package/completion-presets/catalog.json",
  "package/completion-presets/catalog.sha256",
  "package/policy/presets/travel.yaml",
  "package/policy/presets/domain/travel.yaml",
  "package/policy/presets/guardrails/default-travel.yaml",
]) {
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
  symlinkSync(resolve(repoRoot, "node_modules", "ajv"), join(consumerNodeModules, "ajv"), "dir");
  symlinkSync(resolve(repoRoot, "node_modules", "zod"), join(consumerNodeModules, "zod"), "dir");
  symlinkSync(resolve(repoRoot, "node_modules", "@noble"), join(consumerNodeModules, "@noble"), "dir");
  symlinkSync(resolve(repoRoot, "node_modules", "@types"), join(consumerNodeModules, "@types"), "dir");
  const consumerBinRoot = join(consumerNodeModules, ".bin");
  mkdirSync(consumerBinRoot, { recursive: true });
  const loginBin = join(consumerBinRoot, "paybond");
  const initBin = join(consumerBinRoot, "paybond-init");
  const mcpBin = join(consumerBinRoot, "paybond-mcp-server");
  const cliTarget = join(consumerNodeModules, "@paybond", "kit", "dist", "cli.js");
  const loginTarget = join(consumerNodeModules, "@paybond", "kit", "dist", "login.js");
  const initTarget = join(consumerNodeModules, "@paybond", "kit", "dist", "init.js");
  const mcpTarget = join(consumerNodeModules, "@paybond", "kit", "dist", "mcp-server.js");
  chmodSync(cliTarget, 0o755);
  chmodSync(loginTarget, 0o755);
  chmodSync(initTarget, 0o755);
  chmodSync(mcpTarget, 0o755);
  symlinkSync(cliTarget, loginBin, "file");
  symlinkSync(initTarget, initBin, "file");
  symlinkSync(mcpTarget, mcpBin, "file");

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
          skipLibCheck: true,
          noEmit: true,
          types: ["node"],
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
  const loginBinHelpViaNode = run("node", [loginBin, "--help"], consumerRoot);
  assertIncludesAll(loginBinHelpViaNode, ["paybond [--global-flags]", "login", "mcp", "doctor"], "paybond .bin root help via node");
  const loginBinHelp = run(loginBin, ["--help"], consumerRoot);
  assertIncludesAll(loginBinHelp, ["paybond [--global-flags]", "login", "mcp", "doctor"], "paybond .bin executable root help");
  const loginCommandHelp = run(loginBin, ["login", "--help"], consumerRoot);
  assertIncludesAll(loginCommandHelp, ["paybond login", "--env-file", "--gateway", "--no-open", "--force"], "paybond login .bin executable help");

  const initCli = join(consumerNodeModules, "@paybond", "kit", "dist", "init.js");
  const initBinHelpViaNode = run("node", [initBin, "--help"], consumerRoot);
  assertIncludesAll(initBinHelpViaNode, ["paybond init guardrail", "paid-tool-guard", "--framework"], "paybond-init .bin help via node");
  const initBinHelp = run(initBin, ["--help"], consumerRoot);
  assertIncludesAll(initBinHelp, ["paybond init guardrail", "paid-tool-guard", "--framework"], "paybond-init .bin executable help");
  const mcpBinHelpViaNode = runCombined("node", [mcpBin, "--help"], consumerRoot);
  assertIncludesAll(
    mcpBinHelpViaNode,
    ["Usage: paybond-mcp-server", "Paybond MCP server over stdio"],
    "paybond-mcp-server .bin help via node",
  );
  const mcpBinHelp = runCombined(mcpBin, ["--help"], consumerRoot);
  assertIncludesAll(
    mcpBinHelp,
    ["Usage: paybond-mcp-server", "Paybond MCP server over stdio"],
    "paybond-mcp-server .bin executable help",
  );

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
      "process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL",
      'const COMPLETION_PRESET_ID = "cost_and_completion"',
      "buildCompletionEvidence",
      "bootstrapSandboxGuardrailIntent",
      "wrapPaidTool",
      "submitSandboxEvidence",
      "completionPreset: COMPLETION_PRESET_ID",
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
          skipLibCheck: true,
          noEmit: true,
          types: ["node"],
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

  const npmConsumerRoot = join(scratch, "npm-consumer");
  mkdirSync(npmConsumerRoot, { recursive: true });
  writeFileSync(
    join(npmConsumerRoot, "package.json"),
    JSON.stringify(
      {
        name: "paybond-kit-tarball-consumer",
        private: true,
        type: "module",
        dependencies: {
          "@paybond/kit": `file:${tarball}`,
        },
      },
      null,
      2,
    ),
  );
  runLogged(npmBin, ["install", "--ignore-scripts"], npmConsumerRoot);
  const tarballConsumerLs = run(npmBin, ["ls", "ajv", "zod", "--json"], npmConsumerRoot);
  if (!tarballConsumerLs.includes('"ajv"')) {
    throw new Error("packed @paybond/kit consumer install must include ajv as a transitive dependency");
  }
  if (!tarballConsumerLs.includes('"zod"')) {
    throw new Error("packed @paybond/kit consumer install must include zod as a transitive dependency");
  }
  const tarballConsumerSmoke = join(npmConsumerRoot, "verify-completion-evidence.mjs");
  writeFileSync(
    tarballConsumerSmoke,
    [
      'import { pathToFileURL } from "node:url";',
      'import { join } from "node:path";',
      'const modulePath = pathToFileURL(',
      '  join(process.cwd(), "node_modules/@paybond/kit/dist/completion-validate-evidence.js"),',
      ").href;",
      'const { validateCompletionEvidence } = await import(modulePath);',
      "const result = validateCompletionEvidence({",
      '  presetId: "cost_and_completion",',
      '  canonicalPayload: { status: "completed", cost_cents: 100 },',
      "});",
      'if (!result.canonical_schema_ok) {',
      '  throw new Error(`validateCompletionEvidence failed: ${JSON.stringify(result)}`);',
      "}",
    ].join("\n"),
  );
  runLogged("node", [tarballConsumerSmoke], npmConsumerRoot);

  const tarballPolicySchemaSmoke = join(npmConsumerRoot, "verify-policy-schema.mjs");
  writeFileSync(
    tarballPolicySchemaSmoke,
    [
      'import { pathToFileURL } from "node:url";',
      'import { join } from "node:path";',
      'const schemaPath = pathToFileURL(',
      '  join(process.cwd(), "node_modules/@paybond/kit/dist/policy/schema.js"),',
      ").href;",
      'const { parsePaybondPolicyDocumentV1 } = await import(schemaPath);',
      "parsePaybondPolicyDocumentV1({",
      '  version: 1,',
      '  name: "smoke",',
      "  default_deny: true,",
      "  tools: {",
      '    "travel.book_hotel": {',
      "      side_effecting: true,",
      '      evidence_preset: "cost_and_completion",',
      "    },",
      "  },",
      "});",
    ].join("\n"),
  );
  runLogged("node", [tarballPolicySchemaSmoke], npmConsumerRoot);

  const tarballPeerSmoke = join(npmConsumerRoot, "verify-no-framework-peers.mjs");
  writeFileSync(
    tarballPeerSmoke,
    [
      'import { pathToFileURL } from "node:url";',
      'import { join } from "node:path";',
      'const presetsPath = pathToFileURL(',
      '  join(process.cwd(), "node_modules/@paybond/kit/dist/policy/presets.js"),',
      ").href;",
      'const { resolvePolicyPresetPath } = await import(presetsPath);',
      'const travelPath = resolvePolicyPresetPath("travel");',
      'if (!travelPath.includes("travel.yaml")) {',
      '  throw new Error(`expected travel preset path, got ${travelPath}`);',
      "}",
      'const cliPath = join(process.cwd(), "node_modules/@paybond/kit/dist/cli.js");',
      'const { spawnSync } = await import("node:child_process");',
      'const result = spawnSync(process.execPath, [cliPath, "dev", "smoke", "--offline", "--format", "json"], {',
      '  encoding: "utf8",',
      "});",
      'const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;',
      'if (output.includes("ERR_MODULE_NOT_FOUND")) {',
      '  throw new Error(`CLI must not require optional framework peers at import time:\\n${output}`);',
      "}",
      'if (output.includes("policy preset file not found for: travel")) {',
      '  throw new Error(`travel preset must ship in the published tarball:\\n${output}`);',
      "}",
    ].join("\n"),
  );
  runLogged("node", [tarballPeerSmoke], npmConsumerRoot);
} finally {
  rmSync(scratch, { force: true, recursive: true });
  rmSync(tarball, { force: true });
}
