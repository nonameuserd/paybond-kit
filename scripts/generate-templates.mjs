#!/usr/bin/env node
/**
 * Generates cloneable starter repos under kit/ts/templates/<repo>/ from manifest.json.
 * Run from repository root: node kit/ts/scripts/generate-templates.mjs
 */
import { cp, mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { mkdirSync } from "node:fs";
import { execSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const KIT_TS_DIR = join(SCRIPT_DIR, "..");
const TEMPLATES_DIR = join(KIT_TS_DIR, "templates");
const REPO_ROOT = join(KIT_TS_DIR, "../..");
const ROOT_TEMPLATES = join(REPO_ROOT, "templates");
const POLICY_PRESETS = join(REPO_ROOT, "kit/policy/presets");
const KIT_PACK_DIR = join(KIT_TS_DIR, ".template-pack");

const kitPackageJson = JSON.parse(
  await readFile(join(KIT_TS_DIR, "package.json"), "utf8"),
);
const KIT_VERSION = kitPackageJson.version;

const manifest = JSON.parse(await readFile(join(TEMPLATES_DIR, "manifest.json"), "utf8"));

const GITIGNORE = `node_modules/
dist/
.env.local
.paybond/
__pycache__/
*.pyc
.venv/
`;

const ENV_EXAMPLE = `# Copy to .env.local after paybond login
PAYBOND_API_KEY=
PAYBOND_GATEWAY_URL=https://api.paybond.ai
`;

const NPMRC = `legacy-peer-deps=true
`;

const TS_CONFIG = `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "skipLibCheck": true,
    "declaration": true
  },
  "include": ["src/**/*.ts"]
}
`;

const PAYBOND_CONFIG_TS = `import { Paybond } from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

function readEnvValue(body: string, key: string): string | undefined {
  const pattern = new RegExp("^\\\\s*(?:export\\\\s+)?" + key + "\\\\s*=\\\\s*(.*)$", "m");
  const match = body.match(pattern);
  if (!match) return undefined;
  let value = (match[1] ?? "").trim();
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      value = JSON.parse(value);
    } catch {
      value = value.slice(1, -1);
    }
  } else if (value.startsWith("'") && value.endsWith("'")) {
    value = value.slice(1, -1);
  }
  return value.trim() || undefined;
}

export async function loadPaybondEnvFile(envFile = ".env.local"): Promise<void> {
  if (process.env.PAYBOND_API_KEY?.trim()) return;
  let body: string;
  try {
    const { readFile } = await import("node:fs/promises");
    body = await readFile(envFile, "utf8");
  } catch (err) {
    if ((err).code === "ENOENT") return;
    throw err;
  }
  const apiKey = readEnvValue(body, "PAYBOND_API_KEY");
  if (apiKey) {
    process.env.PAYBOND_API_KEY = apiKey;
  }
}

export async function createPaybondClient(): Promise<Paybond> {
  await loadPaybondEnvFile(".env.local");
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login");
  }
  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}
`;

const PAYBOND_CONFIG_PY = `import os
from pathlib import Path

from paybond_kit import Paybond


def _read_env_value(body: str, key: str) -> str | None:
    for raw_line in body.splitlines():
        line = raw_line.strip()
        for prefix in (f"export {key}=", f"{key}="):
            if line.startswith(prefix):
                value = line[len(prefix):].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\\"":
                    value = value[1:-1]
                return value.strip() or None
    return None


def load_paybond_env_file(env_file: str = ".env.local") -> None:
    if os.environ.get("PAYBOND_API_KEY", "").strip():
        return
    path = Path(env_file)
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    api_key = _read_env_value(body, "PAYBOND_API_KEY")
    if api_key:
        os.environ["PAYBOND_API_KEY"] = api_key


async def create_paybond_client() -> Paybond:
    load_paybond_env_file(".env.local")
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required; run paybond login")
    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=(
            os.environ.get("PAYBOND_GATEWAY_URL")
            or os.environ.get("PAYBOND_GATEWAY_BASE_URL")
            or "https://api.paybond.ai"
        ),
        expected_environment="sandbox",
    )
`;

const CI_WORKFLOW = (smokeCommand) => `name: smoke

on:
  push:
    branches: [main]
  pull_request:

jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          cache: npm
      - run: npm ci
      - run: ${smokeCommand}
        env:
          PAYBOND_API_KEY: \${{ secrets.PAYBOND_SANDBOX_API_KEY }}
`;

const CI_WORKFLOW_PY = (smokeCommand) => `name: smoke

on:
  push:
    branches: [main]
  pull_request:

jobs:
  smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
      - run: ${smokeCommand}
        env:
          PAYBOND_API_KEY: \${{ secrets.PAYBOND_SANDBOX_API_KEY }}
`;

function smokeCommand(entry) {
  const resultBody = JSON.stringify(entry.smoke_result_body);
  return [
    "paybond agent sandbox smoke",
    "--policy-file paybond.policy.yaml",
    `--operation ${entry.primary_operation}`,
    `--requested-spend-cents ${entry.requested_spend_cents}`,
    `--result-body '${resultBody}'`,
    "--format json",
  ].join(" ");
}

function policyHeader(entry) {
  const regen = entry.preset
    ? `paybond policy init --preset ${entry.preset} --out paybond.policy.yaml`
    : "edit paybond.policy.yaml directly";
  return `# Reference implementation — edit freely. Regenerate with:\n# ${regen}\n\n`;
}

async function loadPolicyYaml(entry) {
  if (entry.preset) {
    const raw = await readFile(join(POLICY_PRESETS, `${entry.preset}.yaml`), "utf8");
    return policyHeader(entry) + raw;
  }
  if (entry.id === "mcp-coding-agent") {
    return `${policyHeader(entry)}version: 1
name: mcp-coding-agent-v1
default_deny: true

tools:
  search.web:
    side_effecting: false

  search.repo:
    side_effecting: false

  deploy.preview:
    side_effecting: true
    max_spend_cents: 500
    evidence_preset: cost_and_completion

intent:
  allowed_tools:
    - deploy.preview
  budget:
    currency: usd
    max_spend_usd: 50
`;
  }
  if (entry.id === "procurement-agent") {
    return `${policyHeader(entry)}version: 1
name: procurement-agent-v1
default_deny: true

tools:
  procurement.submit_po:
    side_effecting: true
    max_spend_cents: 25000
    evidence_preset: cost_and_completion

  procurement.list_vendors:
    side_effecting: false

  procurement.get_quote:
    side_effecting: false

intent:
  allowed_tools:
    - procurement.submit_po
  budget:
    currency: usd
    max_spend_usd: 250
`;
  }
  throw new Error(`missing policy for ${entry.id}`);
}

function tsIndexDemo(entry) {
  if (entry.demo_mode === "generic") {
    const op = entry.primary_operation;
    const cents = entry.requested_spend_cents;
    const evidence = entry.evidence_preset;
    return `/**
 * Generic Paybond agent — uses paybond.agent() with local paybond.policy.yaml.
 * No live LLM required for the sandbox smoke path.
 */
import { createPaybondClient } from "./paybond.config.js";

const PRIMARY_OPERATION = "${op}";
const REQUESTED_SPEND_CENTS = ${cents};

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const agent = await paybond.agent({
      policy: "./paybond.policy.yaml",
      framework: "generic",
      tools: {
        [PRIMARY_OPERATION]: async (args: { estimatedPriceCents: number }) => ({
          status: "completed",
          cost_cents: args.estimatedPriceCents,
        }),
      },
      sandbox: true,
    });

    const tool = agent.tools.find((entry) => entry.name === PRIMARY_OPERATION);
    if (!tool) {
      throw new Error(\`missing tool \${PRIMARY_OPERATION}\`);
    }

    const result = await tool.execute({
      toolName: PRIMARY_OPERATION,
      toolCallId: "demo-1",
      arguments: { estimatedPriceCents: REQUESTED_SPEND_CENTS },
    });

    console.log(
      JSON.stringify(
        {
          runId: agent.run.runId,
          intentId: agent.run.intentId,
          authorization: result.authorization,
          evidence: result.evidence,
          toolResult: result.toolResult,
        },
        null,
        2,
      ),
    );
  } finally {
    await paybond.aclose();
  }
}

void main();
`;
  }

  if (entry.framework === "mcp") {
    return `/**
 * MCP coding-agent starter — configure stdio MCP for Claude Desktop, Codex, or generic hosts.
 *
 * This file documents local smoke; wire MCP with:
 *   paybond mcp install --host claude --tool-policy spend-write
 */
import { createPaybondClient } from "./paybond.config.js";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const agent = await paybond.agent({
      policy: "./paybond.policy.yaml",
      framework: "generic",
      tools: {
        "deploy.preview": async (args: { estimatedPriceCents: number }) => ({
          status: "completed",
          cost_cents: args.estimatedPriceCents,
        }),
        searchWeb: async (args: { query: string }) => ({
          hits: [{ title: args.query, url: "https://example.com" }],
        }),
      },
      sandbox: true,
    });

    const paid = agent.tools.find((entry) => entry.name === "deploy.preview")!;
    const result = await paid.execute({
      toolName: "deploy.preview",
      toolCallId: "mcp-demo-1",
      arguments: { estimatedPriceCents: 500 },
    });

    console.log(JSON.stringify({ runId: agent.run.runId, result }, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
`;
  }

  return `/**
 * ${entry.title} — sandbox demo using bundled Kit helpers (no live LLM).
 */
import { createPaybondClient } from "./paybond.config.js";
import { ${entry.demo_export} } from "${entry.demo_import}";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const demo = await ${entry.demo_export}({
      paybond,
      operation: "${entry.primary_operation}",
      requestedSpendCents: ${entry.requested_spend_cents},
      evidencePreset: "${entry.evidence_preset}",
    });
    console.log(JSON.stringify(demo, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
`;
}

function pythonApp(entry) {
  return `"""${entry.title} — LangGraph sandbox demo (no live LLM)."""

from __future__ import annotations

import asyncio
import json

from paybond_config import create_paybond_client
from ${entry.demo_import} import ${entry.demo_export}


async def main() -> None:
    paybond = await create_paybond_client()
    try:
        demo = await ${entry.demo_export}(
            paybond,
            operation="${entry.primary_operation}",
            requested_spend_cents=${entry.requested_spend_cents},
            evidence_preset="${entry.evidence_preset}",
        )
        print(json.dumps(demo, indent=2, default=str))
    finally:
        await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
`;
}

function readme(entry, smoke) {
  const install =
    entry.language === "python"
      ? "pip install -r requirements.txt"
      : "npm install";
  const run = entry.language === "python" ? "python app.py" : "npm start";
  const login = entry.language === "python" ? "paybond-kit-login" : "paybond login";
  const mcpBlock =
    entry.framework === "mcp"
      ? `
## MCP host wiring

\`\`\`bash
${login}
paybond mcp install --host claude --tool-policy spend-write
paybond mcp verify-config --host claude
\`\`\`

Read-only tools pass through; side-effecting tools require Harbor authorization.
`
      : "";

  return `# ${entry.repo}

${entry.title}. Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

\`\`\`bash
git clone https://github.com/nonameuserd/${entry.repo}.git
cd ${entry.repo}
cp .env.example .env.local
${login}
${install}
npm run smoke   # or: ${smoke}
\`\`\`

## Run the demo

\`\`\`bash
${run}
\`\`\`
${mcpBlock}
## Policy

Local \`paybond.policy.yaml\` is yours to edit. Bundled preset: **${entry.preset ?? "custom"}**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
`;
}

function isKitVersionOnRegistry(version) {
  try {
    execSync(`npm view @paybond/kit@${version} version`, { stdio: "pipe" });
    return true;
  } catch {
    return false;
  }
}

function fetchKitRegistryIntegrity(version) {
  try {
    return execSync(`npm view @paybond/kit@${version} dist.integrity`, {
      stdio: "pipe",
      encoding: "utf8",
    }).trim();
  } catch {
    return undefined;
  }
}

function packLocalKitTarball() {
  mkdirSync(KIT_PACK_DIR, { recursive: true });
  const output = execSync(
    `npm pack --pack-destination "${KIT_PACK_DIR}" --silent --ignore-scripts`,
    {
      cwd: KIT_TS_DIR,
      encoding: "utf8",
    },
  );
  const tarballName = output
    .trim()
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .at(-1);
  if (!tarballName) {
    throw new Error("npm pack did not return a tarball name");
  }
  return join(KIT_PACK_DIR, tarballName);
}

async function rewriteKitLockToRegistry(lockPath, kitVersion) {
  const lock = JSON.parse(await readFile(lockPath, "utf8"));
  const kitRange = `^${kitVersion}`;
  const registryResolved = `https://registry.npmjs.org/@paybond/kit/-/kit-${kitVersion}.tgz`;
  const registryIntegrity = fetchKitRegistryIntegrity(kitVersion);

  if (lock.packages?.[""]?.dependencies?.["@paybond/kit"]) {
    lock.packages[""].dependencies["@paybond/kit"] = kitRange;
  }

  for (const [key, entry] of Object.entries(lock.packages ?? {})) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    if (key === "node_modules/@paybond/kit" || entry.name === "@paybond/kit") {
      entry.version = kitVersion;
      entry.resolved = registryResolved;
      delete entry.link;
      if (registryIntegrity) {
        entry.integrity = registryIntegrity;
      }
    }
  }

  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}

async function refreshTemplatePackageLock(dir, consumerPackageJson) {
  await writeFile(
    join(dir, "package.json"),
    `${JSON.stringify(consumerPackageJson, null, 2)}\n`,
  );

  const kitDependency = consumerPackageJson.dependencies?.["@paybond/kit"];
  if (!kitDependency || isKitVersionOnRegistry(KIT_VERSION)) {
    execSync("npm install --package-lock-only", { cwd: dir, stdio: "inherit" });
    return;
  }

  let tarballPath;
  try {
    tarballPath = packLocalKitTarball();
    const lockPackageJson = {
      ...consumerPackageJson,
      dependencies: {
        ...consumerPackageJson.dependencies,
        "@paybond/kit": `file:${tarballPath}`,
      },
    };
    await writeFile(
      join(dir, "package.json"),
      `${JSON.stringify(lockPackageJson, null, 2)}\n`,
    );
    execSync("npm install --package-lock-only", { cwd: dir, stdio: "inherit" });
    await writeFile(
      join(dir, "package.json"),
      `${JSON.stringify(consumerPackageJson, null, 2)}\n`,
    );
    await rewriteKitLockToRegistry(join(dir, "package-lock.json"), KIT_VERSION);
  } finally {
    if (tarballPath) {
      await unlink(tarballPath).catch(() => {});
    }
  }
}

async function writeTemplate(entry) {
  const dir = join(TEMPLATES_DIR, entry.repo);
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await mkdir(join(dir, ".github/workflows"), { recursive: true });

  const smoke = smokeCommand(entry);
  await writeFile(join(dir, "paybond.policy.yaml"), await loadPolicyYaml(entry));
  await writeFile(join(dir, ".env.example"), ENV_EXAMPLE);
  await writeFile(join(dir, ".gitignore"), GITIGNORE);
  await writeFile(join(dir, "README.md"), readme(entry, smoke));
  await cp(join(REPO_ROOT, "kit/ts/LICENSE"), join(dir, "LICENSE"));

  if (entry.language === "python") {
    await mkdir(join(dir, "src"), { recursive: true }).catch(() => {});
    await writeFile(join(dir, "paybond_config.py"), PAYBOND_CONFIG_PY);
    await writeFile(join(dir, "app.py"), pythonApp(entry));
    const deps = Object.entries(entry.python_dependencies)
      .map(([pkg, ver]) => `${pkg}${ver.startsWith(">=") ? ver : `>=${ver}`}`)
      .join("\n");
    await writeFile(join(dir, "requirements.txt"), `${deps}\n`);
    await writeFile(
      join(dir, ".github/workflows/smoke.yml"),
      CI_WORKFLOW_PY(smoke.replace("npm run smoke", smoke)),
    );
    await writeFile(
      join(dir, "package.json"),
      `${JSON.stringify({ private: true, scripts: { smoke } }, null, 2)}\n`,
    );
    return;
  }

  await mkdir(join(dir, "src"), { recursive: true });
  await writeFile(join(dir, "tsconfig.json"), TS_CONFIG);
  await writeFile(join(dir, "src/paybond.config.ts"), PAYBOND_CONFIG_TS);
  await writeFile(join(dir, "src/index.ts"), tsIndexDemo(entry));
  const consumerPackageJson = {
    name: entry.repo,
    private: false,
    type: "module",
    scripts: {
      build: "tsc -p tsconfig.json",
      start: "node dist/index.js",
      smoke,
    },
    dependencies: entry.dependencies,
    devDependencies: {
      "@types/node": "^22.10.1",
      typescript: "^5.7.2",
    },
    engines: { node: ">=22" },
  };
  await writeFile(join(dir, ".github/workflows/smoke.yml"), CI_WORKFLOW("npm run smoke"));
  await writeFile(join(dir, ".npmrc"), NPMRC);
  await refreshTemplatePackageLock(dir, consumerPackageJson);
}

for (const entry of manifest.templates) {
  await writeTemplate(entry);
  console.log(`generated ${entry.repo}`);
}

// Mirror to repo-root templates/ for GitHub publishing visibility
await rm(ROOT_TEMPLATES, { recursive: true, force: true });
await mkdir(ROOT_TEMPLATES, { recursive: true });
await writeFile(
  join(ROOT_TEMPLATES, "README.md"),
  `# Paybond starter templates

Clone-and-run GitHub template repositories. Each uses published \`@paybond/kit\` or \`paybond-kit\` — no monorepo \`file:\` wiring.

Scaffold into an empty directory:

\`\`\`bash
paybond init --template travel-agent
paybond init --template vercel-shopping-agent --force
\`\`\`

| Template | Stack | Policy |
| --- | --- | --- |
${manifest.templates
  .map(
    (t) =>
      `| [\`${t.repo}\`](./${t.repo}/) | ${t.framework} | ${t.preset ?? "custom"} |`,
  )
  .join("\n")}

Regenerate from manifest: \`node kit/ts/scripts/generate-templates.mjs\`
`,
);

const excludeGitMetadata = (src) =>
  !src.endsWith("/.git") && !src.includes("/.git/");

for (const entry of manifest.templates) {
  await cp(join(TEMPLATES_DIR, entry.repo), join(ROOT_TEMPLATES, entry.repo), {
    recursive: true,
    filter: excludeGitMetadata,
  });
}

console.log(`mirrored ${manifest.templates.length} templates to ${ROOT_TEMPLATES}`);

const PYTHON_TEMPLATES = join(REPO_ROOT, "kit/python/src/paybond_kit/data/templates");
await rm(PYTHON_TEMPLATES, { recursive: true, force: true });
await mkdir(PYTHON_TEMPLATES, { recursive: true });
await cp(join(TEMPLATES_DIR, "manifest.json"), join(PYTHON_TEMPLATES, "manifest.json"));
for (const entry of manifest.templates) {
  await cp(join(TEMPLATES_DIR, entry.repo), join(PYTHON_TEMPLATES, entry.repo), {
    recursive: true,
    filter: excludeGitMetadata,
  });
}
console.log(`synced ${manifest.templates.length} templates to ${PYTHON_TEMPLATES}`);
