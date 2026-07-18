#!/usr/bin/env node
/**
 * Generates cloneable starter repos under kit/ts/templates/<repo>/ from manifest.json.
 * Run from repository root: node kit/ts/scripts/generate-templates.mjs
 */
import { cp, mkdir, readFile, rm, unlink, writeFile } from "node:fs/promises";
import { mkdirSync, mkdtempSync } from "node:fs";
import { execSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  fetchKitRegistryIntegrity,
  isKitVersionOnRegistry,
  patchKitLockIntegrity,
  resolveKitLockIntegrity,
} from "./template-lock-integrity.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const KIT_TS_DIR = join(SCRIPT_DIR, "..");
const TEMPLATES_DIR = join(KIT_TS_DIR, "templates");
const REPO_ROOT = join(KIT_TS_DIR, "../..");
const ROOT_TEMPLATES = join(REPO_ROOT, "templates");
const POLICY_PRESETS = join(REPO_ROOT, "kit/policy/presets");
const KIT_PACK_DIR = mkdtempSync(join(tmpdir(), "paybond-kit-template-pack-"));
/** @type {string | undefined} */
let sharedPrepublishTarballPath;

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
    if ((err as { code?: string }).code === "ENOENT") return;
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
  if (entry.id === "procurement-agent" || entry.id === "crewai-procurement-agent") {
    if (entry.id === "crewai-procurement-agent") {
      return `${policyHeader(entry)}version: 1
name: procurement-agent-v1
default_deny: true

tools:
  procurement.submit_po:
    side_effecting: true
    spend_from_args: amount_cents
    evidence_preset: cost_and_completion

  procurement.list_vendors:
    side_effecting: false

  procurement.get_quote:
    side_effecting: false

  procurement.search_catalog:
    side_effecting: false

intent:
  allowed_tools:
    - procurement.submit_po
  budget:
    currency: usd
    max_spend_usd: 250
`;
    }
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
  if (entry.framework === "crewai") {
    return `"""${entry.title} — no live LLM required.

Modes:
  python app.py           # approve path (${entry.requested_spend_cents} cents, under intent budget)
  python app.py --deny    # over-budget deny path
"""

from __future__ import annotations

import asyncio
import json
import sys

from crewai.tools import tool

from paybond_config import create_paybond_client

PRIMARY_OPERATION = "${entry.primary_operation}"
APPROVE_SPEND_CENTS = ${entry.requested_spend_cents}
DENY_SPEND_CENTS = 50000  # above intent budget


@tool("procurement.search_catalog")
def search_catalog(query: str) -> str:
    """Search the procurement catalog (read-only; not side-effecting)."""
    return json.dumps({"query": query, "items": [{"sku": "LAP-14", "vendor_id": "vendor-acme"}]})


@tool("procurement.submit_po")
def submit_po(vendor_id: str, amount_cents: int) -> str:
    """Submit a purchase order. Paybond Harbor must approve before this runs."""
    return json.dumps(
        {
            "status": "completed",
            "vendor_id": vendor_id,
            "cost_cents": amount_cents,
            "po_id": f"po-{vendor_id}-{amount_cents}",
        }
    )


async def main() -> None:
    deny = "--deny" in sys.argv[1:]
    amount_cents = DENY_SPEND_CENTS if deny else APPROVE_SPEND_CENTS
    paybond = await create_paybond_client()
    try:
        result = await paybond.agent(
            policy="./paybond.policy.yaml",
            framework="crewai",
            tools=[search_catalog, submit_po],
            bootstrap={
                "operation": PRIMARY_OPERATION,
                "requested_spend_cents": amount_cents if not deny else APPROVE_SPEND_CENTS,
                "completion_preset": "${entry.evidence_preset}",
            },
        )
        guarded = next(
            (entry for entry in result.tools if getattr(entry, "name", None) == PRIMARY_OPERATION),
            result.tools[0],
        )
        raw = guarded.run(vendor_id="vendor-acme", amount_cents=amount_cents)
        print(
            json.dumps(
                {
                    "mode": "deny" if deny else "approve",
                    "run_id": result.run.run_id,
                    "intent_id": str(result.run.intent_id),
                    "tool_result": raw,
                },
                indent=2,
                default=str,
            )
        )
    finally:
        await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
`;
  }

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

function crewaiCrew(entry) {
  return `"""CrewAI procurement crew with Paybond spend gates on tool calls.

Requires OPENAI_API_KEY (or your CrewAI LLM provider env) for a live kickoff.
For Harbor authorize + evidence without an LLM, use \`python app.py\` instead.
"""

from __future__ import annotations

import asyncio
import json
import os

from crewai import Agent, Crew, Process, Task
from crewai.tools import tool

from paybond_config import create_paybond_client


@tool("procurement.search_catalog")
def search_catalog(query: str) -> str:
    """Search the procurement catalog (read-only; not side-effecting)."""
    return json.dumps(
        {
            "query": query,
            "items": [
                {"sku": "LAP-14", "vendor_id": "vendor-acme", "unit_cents": 12000},
                {"sku": "MON-27", "vendor_id": "vendor-north", "unit_cents": 8900},
            ],
        }
    )


@tool("procurement.submit_po")
def submit_po(vendor_id: str, amount_cents: int) -> str:
    """Submit a purchase order. Paybond Harbor must approve before this runs."""
    return json.dumps(
        {
            "status": "completed",
            "vendor_id": vendor_id,
            "cost_cents": amount_cents,
            "po_id": f"po-{vendor_id}-{amount_cents}",
        }
    )


async def build_crew() -> Crew:
    paybond = await create_paybond_client()
    result = await paybond.agent(
        policy="./paybond.policy.yaml",
        framework="crewai",
        tools=[search_catalog, submit_po],
    )
    guarded_tools = result.tools

    buyer = Agent(
        role="Procurement buyer",
        goal="Find a catalog item and submit a purchase order within policy limits",
        backstory="You buy hardware for an engineering team and never exceed approved spend.",
        tools=guarded_tools,
        verbose=True,
        allow_delegation=False,
    )
    reviewer = Agent(
        role="Spend reviewer",
        goal="Confirm the PO amount stays under the Harbor budget and summarize the receipt",
        backstory="You enforce corporate spend controls and call out denials or approval holds.",
        verbose=True,
        allow_delegation=False,
    )

    find_item = Task(
        description=(
            "Search the catalog for a 14-inch laptop. "
            "Then submit a PO for vendor-acme at 12000 cents using procurement.submit_po."
        ),
        expected_output="JSON PO confirmation or a clear Paybond deny/hold message",
        agent=buyer,
    )
    review = Task(
        description=(
            "Review the buyer result. If Paybond denied or held spend, explain why. "
            "If approved, summarize vendor_id, cost_cents, and po_id."
        ),
        expected_output="Short spend-control summary for an operator",
        agent=reviewer,
        context=[find_item],
    )

    crew = Crew(
        agents=[buyer, reviewer],
        tasks=[find_item, review],
        process=Process.sequential,
        verbose=True,
    )
    # Keep the Paybond client alive for the crew lifetime via closure.
    crew._paybond_client = paybond  # type: ignore[attr-defined]
    return crew


async def main() -> None:
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        raise SystemExit(
            "OPENAI_API_KEY is required for crew kickoff. "
            "Use \`python app.py\` for a no-LLM Harbor smoke, or set your LLM key."
        )
    crew = await build_crew()
    try:
        output = crew.kickoff()
        print(output)
    finally:
        paybond = getattr(crew, "_paybond_client", None)
        if paybond is not None:
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
  const crewaiBlock =
    entry.framework === "crewai"
      ? `
## What this crew shows

Paybond wraps CrewAI \`@tool\` / \`BaseTool\` handlers at the execution boundary:

| Path | What happens |
| --- | --- |
| **Approve** | Harbor verifies spend → \`procurement.submit_po\` runs → auto-evidence |
| **Deny** | Over-budget / hard deny → tool body never runs (error string returned) |
| **Approval hold** | Operator approves in the tenant console, then retry with \`approvalToken\` |

No-LLM Harbor smoke:

\`\`\`bash
python app.py          # approve (~$${entry.requested_spend_cents / 100})
python app.py --deny   # over-budget deny
\`\`\`

CrewAI adapter smoke (optional):

\`\`\`bash
paybond agent demo crewai smoke \\
  --operation ${entry.primary_operation} \\
  --requested-spend-cents ${entry.requested_spend_cents} \\
  --evidence-preset ${entry.evidence_preset} \\
  --format json
\`\`\`

Live CrewAI kickoff (needs an LLM key):

\`\`\`bash
export OPENAI_API_KEY=sk-...
python crew.py
\`\`\`

## CrewAI Marketplace

This repo is structured for [marketplace.crewai.com](https://marketplace.crewai.com) listing:

- Clear spend-gate story on a procurement PO tool
- Sandbox-first quickstart (\`paybond login\`)
- Apache-2.0 license
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
${mcpBlock}${crewaiBlock}
## Policy

Local \`paybond.policy.yaml\` is yours to edit. Bundled preset: **${entry.preset ?? "custom"}**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
${
    entry.framework === "crewai"
      ? `- [CrewAI adapter](https://docs.paybond.ai/kit/crewai)
- [CrewAI spend controls guide](https://docs.paybond.ai/guides/crewai-spend-controls)
`
      : ""
  }`;
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

async function stampKitLock(lockPath, kitVersion, tarballPath) {
  const integrity = await resolveKitLockIntegrity(kitVersion, { tarballPath });
  if (!integrity) {
    throw new Error(
      `@paybond/kit@${kitVersion} is not on the npm registry and no local pack tarball was provided. ` +
        `Publish the kit or run generate-templates after npm pack.`,
    );
  }
  if (!fetchKitRegistryIntegrity(kitVersion) && tarballPath) {
    console.warn(
      `@paybond/kit@${kitVersion} is not on npm yet; stamping template lockfiles from local npm pack integrity.`,
    );
  }
  await patchKitLockIntegrity(lockPath, kitVersion, integrity);
}

async function refreshTemplatePackageLock(dir, consumerPackageJson) {
  await writeFile(
    join(dir, "package.json"),
    `${JSON.stringify(consumerPackageJson, null, 2)}\n`,
  );

  const kitDependency = consumerPackageJson.dependencies?.["@paybond/kit"];
  if (!kitDependency) {
    return;
  }

  // Fail fast with a clear message if a template depends on an unpublished
  // @paybond/* wrapper (discoverability shims under kit/npm-wrappers). Prefer
  // @paybond/kit/<subpath> until those packages are published to npm.
  for (const [name, range] of Object.entries(consumerPackageJson.dependencies ?? {})) {
    if (!name.startsWith("@paybond/") || name === "@paybond/kit") {
      continue;
    }
    try {
      execSync(`npm view ${name}@${String(range).replace(/^\^/, "")} version`, {
        stdio: "pipe",
      });
    } catch {
      throw new Error(
        `${dir}: dependency ${name}@${range} is not on the npm registry. ` +
          `Use @paybond/kit/<subpath> instead, or publish ${name} before regenerating template locks.`,
      );
    }
  }

  if (isKitVersionOnRegistry(KIT_VERSION)) {
    execSync("npm install --package-lock-only", { cwd: dir, stdio: "inherit" });
    await stampKitLock(join(dir, "package-lock.json"), KIT_VERSION);
    return;
  }

  let tarballPath = sharedPrepublishTarballPath;
  if (!tarballPath) {
    tarballPath = packLocalKitTarball();
    sharedPrepublishTarballPath = tarballPath;
  }
  try {
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
    await stampKitLock(join(dir, "package-lock.json"), KIT_VERSION, tarballPath);
  } finally {
    // Shared tarball cleaned up after all templates are generated.
  }
}

/** Templates with custom sources that must not be wiped by scaffold regeneration. */
const HAND_MAINTAINED_TEMPLATE_IDS = new Set([
  "stripe-agent-demo",
  // Custom Workers/DO getTools scaffold in src/agent.ts
  "cloudflare-shopping-agent",
  // Catalog-backed spend (SKU×qty); function middleware sample for MAF
  "microsoft-agent-framework-procurement-agent",
  // Catalog-backed spend (SKU×qty); CrewAI @tool wrap
  "crewai-procurement-agent",
]);

/**
 * Refresh pins for hand-maintained templates without deleting custom sources.
 * Keeps @paybond/kit + typescript aligned with the monorepo kit toolchain.
 * @param {{ id: string, repo: string }} entry
 */
async function refreshHandMaintainedTemplate(entry) {
  const dir = join(TEMPLATES_DIR, entry.repo);
  const packageJsonPath = join(dir, "package.json");
  const existing = JSON.parse(await readFile(packageJsonPath, "utf8"));
  let changed = false;

  if (existing.dependencies?.["@paybond/kit"]) {
    existing.dependencies["@paybond/kit"] = `^${KIT_VERSION}`;
    changed = true;
  }
  // Templates must depend on published packages only. Prefer @paybond/kit/<subpath>
  // over unpublished @paybond/<framework> wrapper packages (npm discoverability shims).
  for (const dep of Object.keys(existing.dependencies ?? {})) {
    if (dep.startsWith("@paybond/") && dep !== "@paybond/kit") {
      delete existing.dependencies[dep];
      changed = true;
    }
  }
  if (existing.devDependencies && typeof existing.devDependencies === "object") {
    if (existing.devDependencies.typescript !== "^7.0.2") {
      existing.devDependencies.typescript = "^7.0.2";
      changed = true;
    }
  }

  if (changed || existing.dependencies?.["@paybond/kit"]) {
    await refreshTemplatePackageLock(dir, existing);
  }
  console.log(
    `skip ${entry.repo} sources (hand-maintained); refreshed @paybond/kit@${KIT_VERSION} + typescript lock`,
  );
}

async function writeTemplate(entry) {
  if (HAND_MAINTAINED_TEMPLATE_IDS.has(entry.id)) {
    await refreshHandMaintainedTemplate(entry);
    return;
  }
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
    if (entry.framework === "crewai") {
      await writeFile(join(dir, "crew.py"), crewaiCrew(entry));
    }
    // Pin paybond-kit to the monorepo kit version so requirements stay in sync
    // with published releases (avoids CI drift against stale lower bounds).
    const pythonDependencies = Object.fromEntries(
      Object.entries(entry.python_dependencies).map(([pkg, ver]) => {
        if (pkg === "paybond-kit" || pkg.startsWith("paybond-kit[")) {
          return [pkg, `>=${KIT_VERSION}`];
        }
        return [pkg, ver];
      }),
    );
    const deps = Object.entries(pythonDependencies)
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
  // Always pin @paybond/kit to the monorepo kit version. Lock stamping writes
  // ^KIT_VERSION into package-lock.json; package.json must match or npm ci fails.
  const dependencies = {
    ...entry.dependencies,
    ...(entry.dependencies?.["@paybond/kit"]
      ? { "@paybond/kit": `^${KIT_VERSION}` }
      : {}),
  };
  const consumerPackageJson = {
    name: entry.repo,
    private: false,
    type: "module",
    scripts: {
      build: "tsc -p tsconfig.json",
      start: "node dist/index.js",
      smoke,
    },
    dependencies,
    devDependencies: {
      "@types/node": "^22.10.1",
      typescript: "^7.0.2",
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

if (sharedPrepublishTarballPath) {
  await unlink(sharedPrepublishTarballPath).catch(() => {});
}
await rm(KIT_PACK_DIR, { force: true, recursive: true });
