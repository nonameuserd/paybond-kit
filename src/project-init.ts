import { access, readFile, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

import { scaffoldPolicyFromPreset } from "./policy/init.js";
import type { PolicyPresetId } from "./policy/presets.js";
import {
  getSolutionSmokeDefaults,
  isKnownSolutionId,
  loadSolutionManifest,
  type SolutionId,
} from "./solutions/catalog.js";

export type ProjectInitSolution = SolutionId | "mcp-server";
export type ProjectInitFramework = "openai" | "langgraph" | "mcp" | "generic";
export type ProjectInitLanguage = "typescript" | "python";

export type ProjectInitOptions = {
  cwd: string;
  solution?: ProjectInitSolution;
  maxSpendUsd?: number;
  framework?: ProjectInitFramework;
  language?: ProjectInitLanguage;
  nonInteractive?: boolean;
  force?: boolean;
  writeStdout?: (line: string) => void;
  prompt?: (question: string) => Promise<string>;
};

export type ProjectInitResult = {
  solution: ProjectInitSolution;
  preset_id: PolicyPresetId;
  max_spend_usd: number;
  framework: ProjectInitFramework;
  language: ProjectInitLanguage;
  files: string[];
  smoke_command: string;
};

type SolutionChoice = {
  id: ProjectInitSolution;
  label: string;
  presetId: PolicyPresetId;
};

type FrameworkChoice = {
  id: ProjectInitFramework;
  label: string;
};

const SOLUTION_CHOICES: SolutionChoice[] = [
  { id: "shopping", label: "Shopping", presetId: "shopping" },
  { id: "travel", label: "Travel", presetId: "travel" },
  { id: "saas", label: "SaaS", presetId: "saas" },
  { id: "mcp-server", label: "MCP server", presetId: "travel" },
  { id: "aws", label: "AWS operator", presetId: "aws" },
];

const FRAMEWORK_CHOICES: FrameworkChoice[] = [
  { id: "openai", label: "OpenAI Agents" },
  { id: "langgraph", label: "LangGraph" },
  { id: "mcp", label: "MCP" },
  { id: "generic", label: "Generic" },
];

const SOLUTION_ALIASES: Record<string, ProjectInitSolution> = {
  shopping: "shopping",
  shop: "shopping",
  travel: "travel",
  saas: "saas",
  "mcp-server": "mcp-server",
  mcp: "mcp-server",
  aws: "aws",
  "aws-operator": "aws",
};

const FRAMEWORK_ALIASES: Record<string, ProjectInitFramework> = {
  openai: "openai",
  "openai-agents": "openai",
  langgraph: "langgraph",
  mcp: "mcp",
  generic: "generic",
};

function usage(): string {
  return [
    "Usage: paybond init [--template <id>|--repo <slug>] [--force]",
    "       paybond init [--solution shopping|travel|saas|mcp-server|aws] [--max-spend-usd <n>] [--framework openai|langgraph|mcp|generic] [--language typescript|python] [--non-interactive] [--force]",
    "",
    "Interactive first-run scaffold: solution bundle policy, client bootstrap, framework instrument stub, .env.example, and npm smoke script.",
    "",
    "Examples:",
    "  paybond init --template travel-agent",
    "  paybond init",
    "  paybond init --solution travel --max-spend-usd 500 --framework langgraph --non-interactive",
  ].join("\n");
}

function normalizeSolution(raw: string): ProjectInitSolution {
  const normalized = SOLUTION_ALIASES[raw.trim().toLowerCase()];
  if (!normalized) {
    throw new Error(`invalid --solution: ${raw}`);
  }
  return normalized;
}

function normalizeFramework(raw: string): ProjectInitFramework {
  const normalized = FRAMEWORK_ALIASES[raw.trim().toLowerCase()];
  if (!normalized) {
    throw new Error(`invalid --framework: ${raw}`);
  }
  return normalized;
}

function normalizeLanguage(raw: string): ProjectInitLanguage {
  const value = raw.trim().toLowerCase();
  if (value === "typescript" || value === "ts") {
    return "typescript";
  }
  if (value === "python" || value === "py") {
    return "python";
  }
  throw new Error(`invalid --language: ${raw}`);
}

function presetIdForSolution(solution: ProjectInitSolution): PolicyPresetId {
  return SOLUTION_CHOICES.find((entry) => entry.id === solution)?.presetId ?? "travel";
}

function defaultMaxSpendUsd(solution: ProjectInitSolution): number {
  const presetId = presetIdForSolution(solution);
  if (!isKnownSolutionId(presetId)) {
    return 200;
  }
  const manifest = loadSolutionManifest(presetId);
  for (const guardrail of manifest.policy_default.guardrails) {
    const match = guardrail.match(/^max_spend_usd_(\d+)$/);
    if (match) {
      return Number(match[1]);
    }
  }
  return 200;
}

function defaultFrameworkForSolution(solution: ProjectInitSolution): ProjectInitFramework {
  return solution === "mcp-server" ? "mcp" : "generic";
}

async function detectLanguage(cwd: string): Promise<ProjectInitLanguage> {
  try {
    await access(`${cwd}/pyproject.toml`, constants.F_OK);
    return "python";
  } catch {
    // continue
  }
  try {
    await access(`${cwd}/requirements.txt`, constants.F_OK);
    return "python";
  } catch {
    // continue
  }
  try {
    await access(`${cwd}/package.json`, constants.F_OK);
    return "typescript";
  } catch {
    return "typescript";
  }
}

function parsePositiveUsd(raw: string): number {
  const value = Number(raw.trim());
  if (!Number.isFinite(value) || value <= 0) {
    throw new Error("max spend must be a positive number");
  }
  return value;
}

export type ProjectInitArgv = Omit<ProjectInitOptions, "cwd"> & {
  template?: string;
  help?: boolean;
};

export function parseProjectInitArgv(argv: string[]): ProjectInitArgv | "help" {
  let solution: ProjectInitSolution | undefined;
  let maxSpendUsd: number | undefined;
  let framework: ProjectInitFramework | undefined;
  let language: ProjectInitLanguage | undefined;
  let template: string | undefined;
  let nonInteractive = false;
  let force = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      return "help";
    }
    if (arg === "--non-interactive") {
      nonInteractive = true;
      continue;
    }
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--template" || arg === "--repo") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --template");
      }
      template = raw;
      continue;
    }
    if (arg === "--solution") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --solution");
      }
      solution = normalizeSolution(raw);
      continue;
    }
    if (arg === "--max-spend-usd" || arg === "--max-spend") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --max-spend-usd");
      }
      maxSpendUsd = parsePositiveUsd(raw);
      continue;
    }
    if (arg === "--framework") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --framework");
      }
      framework = normalizeFramework(raw);
      continue;
    }
    if (arg === "--language") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --language");
      }
      language = normalizeLanguage(raw);
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return {
    solution,
    maxSpendUsd,
    framework,
    language,
    template,
    nonInteractive,
    force,
  };
}

async function defaultPrompt(question: string): Promise<string> {
  const rl = createInterface({ input, output });
  try {
    return (await rl.question(question)).trim();
  } finally {
    rl.close();
  }
}

function formatChoices<T extends { label: string }>(choices: T[]): string {
  return choices.map((choice, index) => `[${index + 1}] ${choice.label}`).join("  ");
}

function resolveChoiceIndex<T>(raw: string, choices: T[], fallbackIndex: number): number {
  const trimmed = raw.trim();
  if (!trimmed) {
    return fallbackIndex;
  }
  const numeric = Number(trimmed);
  if (Number.isInteger(numeric) && numeric >= 1 && numeric <= choices.length) {
    return numeric - 1;
  }
  const lowered = trimmed.toLowerCase();
  const byLabel = choices.findIndex((choice) => {
    const label = (choice as { label?: string; id?: string }).label?.toLowerCase();
    const id = (choice as { id?: string }).id?.toLowerCase();
    return label === lowered || id === lowered || label?.replace(/\s+/g, "-") === lowered;
  });
  if (byLabel >= 0) {
    return byLabel;
  }
  throw new Error(`invalid choice: ${raw}`);
}

async function resolveInteractiveOptions(
  options: ProjectInitOptions,
): Promise<Required<Pick<ProjectInitOptions, "solution" | "maxSpendUsd" | "framework" | "language">>> {
  const prompt = options.prompt ?? defaultPrompt;
  const interactive = !options.nonInteractive && input.isTTY === true && output.isTTY === true;
  const language = options.language ?? (await detectLanguage(options.cwd));

  let solution = options.solution;
  if (!solution) {
    if (!interactive) {
      solution = "travel";
    } else {
      options.writeStdout?.(
        `What are you building?  ${formatChoices(SOLUTION_CHOICES)}\n`,
      );
      const answer = await prompt("> ");
      solution = SOLUTION_CHOICES[resolveChoiceIndex(answer, SOLUTION_CHOICES, 1)]!.id;
    }
  }

  let maxSpendUsd = options.maxSpendUsd ?? defaultMaxSpendUsd(solution);
  if (options.maxSpendUsd === undefined && interactive) {
    const answer = await prompt(`Maximum spend? [$${maxSpendUsd}] `);
    if (answer.trim()) {
      maxSpendUsd = parsePositiveUsd(answer);
    }
  }

  let framework = options.framework ?? defaultFrameworkForSolution(solution);
  if (options.framework === undefined && solution !== "mcp-server" && interactive) {
    options.writeStdout?.(`Framework?  ${formatChoices(FRAMEWORK_CHOICES)}\n`);
    const answer = await prompt("> ");
    framework = FRAMEWORK_CHOICES[resolveChoiceIndex(answer, FRAMEWORK_CHOICES, 3)]!.id;
  }

  return {
    solution,
    maxSpendUsd,
    framework,
    language,
  };
}

async function writeFileIfAllowed(
  path: string,
  body: string,
  force: boolean,
): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    if (!force) {
      throw new Error(`${path} already exists (pass --force to overwrite)`);
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("already exists")) {
      throw err;
    }
  }
  await writeFile(path, body, "utf8");
  return true;
}

function smokeCommandFor(presetId: PolicyPresetId): string {
  const preset = isKnownSolutionId(presetId) ? presetId : "travel";
  const defaults = getSolutionSmokeDefaults(preset);
  const resultBody = JSON.stringify(defaults.resultBody);
  return [
    "paybond agent sandbox smoke",
    "--policy-file paybond.policy.yaml",
    `--operation ${defaults.operation}`,
    `--requested-spend-cents ${defaults.requestedSpendCents}`,
    `--evidence-preset ${defaults.evidencePreset}`,
    `--result-body '${resultBody}'`,
    "--format json",
  ].join(" ");
}

function envExampleBody(): string {
  return [
    "# Copy to .env.local after paybond login",
    "PAYBOND_API_KEY=",
    "PAYBOND_GATEWAY_URL=https://api.paybond.ai",
    "",
  ].join("\n");
}

function typescriptConfigTemplate(): string {
  return `import { Paybond } from "@paybond/kit";

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
    if ((err as { code?: unknown })?.code === "ENOENT") return;
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
}

function pythonConfigTemplate(): string {
  return `import os
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
}

type ToolStub = {
  primaryName: string;
  primaryArgsType: string;
  primaryHandler: string;
  secondaryName: string;
  secondaryHandler: string;
  registryPrimary: string;
  toolMap: string;
};

function toolStubsForSolution(solution: ProjectInitSolution): ToolStub {
  switch (solution) {
    case "shopping":
      return {
        primaryName: "commerce.checkout",
        primaryArgsType: "{ sku: string; quantity: number; estimatedTotalCents: number }",
        primaryHandler: `async function checkout(args: { sku: string; quantity: number; estimatedTotalCents: number }) {
  return {
    order: {
      status: "completed" as const,
      total_cents: args.estimatedTotalCents,
      sku: args.sku,
      quantity: args.quantity,
    },
  };
}`,
        secondaryName: "search.products",
        secondaryHandler: `async function searchProducts(args: { query: string }) {
  return { products: [{ title: args.query, sku: "SKU-001" }] };
}`,
        registryPrimary: `"commerce.checkout": {
      spendCents: (args: { estimatedTotalCents: number }) => args.estimatedTotalCents,
      evidencePreset: COMPLETION_PRESET_ID,
      evidenceMapper: (result: Awaited<ReturnType<typeof checkout>>) => ({
        status: result.order.status,
        cost_cents: result.order.total_cents,
      }),
    }`,
        toolMap: `{
    "commerce.checkout": async (args: { sku: string; quantity: number; estimatedTotalCents: number }) =>
      checkout(args),
    searchProducts: async (args: { query: string }) => searchProducts(args),
  }`,
      };
    case "saas":
      return {
        primaryName: "saas.provision_seat",
        primaryArgsType: "{ planId: string; seats: number; monthlyCents: number }",
        primaryHandler: `async function provisionSeat(args: { planId: string; seats: number; monthlyCents: number }) {
  return {
    subscription: {
      status: "active" as const,
      plan_id: args.planId,
      seats: args.seats,
      monthly_cents: args.monthlyCents,
    },
  };
}`,
        secondaryName: "saas.list_plans",
        secondaryHandler: `async function listPlans() {
  return { plans: [{ id: "pro", monthly_cents: 2900 }] };
}`,
        registryPrimary: `"saas.provision_seat": {
      spendCents: (args: { monthlyCents: number }) => args.monthlyCents,
      evidencePreset: COMPLETION_PRESET_ID,
      evidenceMapper: (result: Awaited<ReturnType<typeof provisionSeat>>) => ({
        status: "completed",
        cost_cents: result.subscription.monthly_cents,
      }),
    }`,
        toolMap: `{
    "saas.provision_seat": async (args: { planId: string; seats: number; monthlyCents: number }) =>
      provisionSeat(args),
    listPlans: async () => listPlans(),
  }`,
      };
    case "aws":
      return {
        primaryName: "aws.ec2.start_instance",
        primaryArgsType: "{ instanceId: string; estimatedHourlyCents: number }",
        primaryHandler: `async function startInstance(args: { instanceId: string; estimatedHourlyCents: number }) {
  return {
    instance: {
      id: args.instanceId,
      state: "running" as const,
      hourly_cents: args.estimatedHourlyCents,
    },
  };
}`,
        secondaryName: "aws.ec2.describe_instances",
        secondaryHandler: `async function describeInstances() {
  return { instances: [{ id: "i-abc123", state: "stopped" }] };
}`,
        registryPrimary: `"aws.ec2.start_instance": {
      spendCents: (args: { estimatedHourlyCents: number }) => args.estimatedHourlyCents,
      evidencePreset: COMPLETION_PRESET_ID,
      evidenceMapper: (result: Awaited<ReturnType<typeof startInstance>>) => ({
        status: "completed",
        cost_cents: result.instance.hourly_cents,
      }),
    }`,
        toolMap: `{
    "aws.ec2.start_instance": async (args: { instanceId: string; estimatedHourlyCents: number }) =>
      startInstance(args),
    describeInstances: async () => describeInstances(),
  }`,
      };
    case "mcp-server":
    case "travel":
    default:
      return {
        primaryName: "travel.book_hotel",
        primaryArgsType: "{ city: string; estimatedPriceCents: number }",
        primaryHandler: `async function bookHotel(args: { city: string; estimatedPriceCents: number }) {
  return {
    reservation: {
      status: "confirmed" as const,
      price_cents: args.estimatedPriceCents,
      city: args.city,
    },
  };
}`,
        secondaryName: "search.web",
        secondaryHandler: `async function searchWeb(args: { query: string }) {
  return { hits: [{ title: args.query, url: "https://example.com" }] };
}`,
        registryPrimary: `"travel.book_hotel": {
      spendCents: (args: { estimatedPriceCents: number }) => args.estimatedPriceCents,
      evidencePreset: COMPLETION_PRESET_ID,
      evidenceMapper: (result: Awaited<ReturnType<typeof bookHotel>>) => ({
        status: result.reservation.status === "confirmed" ? "completed" : result.reservation.status,
        cost_cents: result.reservation.price_cents,
      }),
    }`,
        toolMap: `{
    "travel.book_hotel": async (args: { city: string; estimatedPriceCents: number }) => bookHotel(args),
    searchWeb: async (args: { query: string }) => searchWeb(args),
  }`,
      };
  }
}

function instrumentMethod(framework: ProjectInitFramework): string {
  switch (framework) {
    case "openai":
      return "instrumentOpenAI";
    case "langgraph":
      return "instrumentLangGraph";
    case "mcp":
      return "instrumentMCP";
    default:
      return "instrument";
  }
}

function typescriptInstrumentTemplate(
  solution: ProjectInitSolution,
  framework: ProjectInitFramework,
  maxSpendUsd: number,
): string {
  const presetId = presetIdForSolution(solution);
  const manifest = isKnownSolutionId(presetId) ? loadSolutionManifest(presetId) : null;
  const completionPreset = manifest?.completion_preset ?? "cost_and_completion";
  const primaryOperation = manifest?.primary_operation ?? "travel.book_hotel";
  const stubs = toolStubsForSolution(solution);
  const requestedSpendCents = Math.round(maxSpendUsd * 100);

  return `import { createPaybondClient } from "./paybond.config.js";
import { Paybond, createPaybondToolRegistry } from "@paybond/kit";

const POLICY_FILE = "./paybond.policy.yaml";
const COMPLETION_PRESET_ID = "${completionPreset}";
const DEFAULT_OPERATION = "${primaryOperation}";
const DEFAULT_REQUESTED_SPEND_CENTS = ${requestedSpendCents};

${stubs.primaryHandler}

${stubs.secondaryHandler}

export function createAgentToolRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      ${stubs.registryPrimary},
    },
    defaultDeny: true,
  });
}

export async function createInstrumentedAgent() {
  const paybond = await createPaybondClient();
  const tools = ${stubs.toolMap};
  return paybond.${instrumentMethod(framework)}({
    policy: POLICY_FILE,
    tools,
    sandbox: true,
  });
}

/** Sandbox bind helper when you need an explicit PaybondAgentRun. */
export async function bindSandboxAgentRun() {
  const paybond = await createPaybondClient();
  return paybond.agentRun.bind({
    bootstrap: {
      kind: "sandbox",
      operation: DEFAULT_OPERATION,
      requestedSpendCents: DEFAULT_REQUESTED_SPEND_CENTS,
      completionPreset: COMPLETION_PRESET_ID,
    },
    registry: createAgentToolRegistry(),
  });
}
`;
}

function pythonInstrumentTemplate(
  solution: ProjectInitSolution,
  framework: ProjectInitFramework,
  maxSpendUsd: number,
): string {
  const presetId = presetIdForSolution(solution);
  const manifest = isKnownSolutionId(presetId) ? loadSolutionManifest(presetId) : null;
  const completionPreset = manifest?.completion_preset ?? "cost_and_completion";
  const primaryOperation = manifest?.primary_operation ?? "travel.book_hotel";
  const requestedSpendCents = Math.round(maxSpendUsd * 100);
  const instrumentCall =
    framework === "generic"
      ? "await paybond.instrument(policy=POLICY_FILE, tools=tools, sandbox=True)"
      : framework === "langgraph"
        ? "await paybond.instrument_langgraph(policy=POLICY_FILE, tools=tools, sandbox=True)"
        : framework === "openai"
          ? "await paybond.instrument_openai(policy=POLICY_FILE, tools=tools, sandbox=True)"
          : "await paybond.instrument_mcp(policy=POLICY_FILE, tools=tools, sandbox=True)";

  const toolBlock = (() => {
    switch (solution) {
      case "shopping":
        return `async def checkout(args: dict[str, object]) -> dict[str, object]:
    total_cents = int(args["estimated_total_cents"])
    return {
        "order": {
            "status": "completed",
            "total_cents": total_cents,
            "sku": str(args["sku"]),
            "quantity": int(args["quantity"]),
        },
    }


async def search_products(args: dict[str, object]) -> dict[str, object]:
    return {"products": [{"title": str(args["query"]), "sku": "SKU-001"}]}


def create_agent_tool_registry() -> object:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "commerce.checkout": {
                    "spend_cents": lambda args: int(args["estimated_total_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {
                        "status": result["order"]["status"],
                        "cost_cents": result["order"]["total_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


TOOLS = {
    "commerce.checkout": checkout,
    "search.products": search_products,
}`;
      case "saas":
        return `async def provision_seat(args: dict[str, object]) -> dict[str, object]:
    monthly_cents = int(args["monthly_cents"])
    return {
        "subscription": {
            "status": "active",
            "plan_id": str(args["plan_id"]),
            "seats": int(args["seats"]),
            "monthly_cents": monthly_cents,
        },
    }


async def list_plans() -> dict[str, object]:
    return {"plans": [{"id": "pro", "monthly_cents": 2900}]}


def create_agent_tool_registry() -> object:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "saas.provision_seat": {
                    "spend_cents": lambda args: int(args["monthly_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {
                        "status": "completed",
                        "cost_cents": result["subscription"]["monthly_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


TOOLS = {
    "saas.provision_seat": provision_seat,
    "saas.list_plans": list_plans,
}`;
      case "aws":
        return `async def start_instance(args: dict[str, object]) -> dict[str, object]:
    hourly_cents = int(args["estimated_hourly_cents"])
    return {
        "instance": {
            "id": str(args["instance_id"]),
            "state": "running",
            "hourly_cents": hourly_cents,
        },
    }


async def describe_instances() -> dict[str, object]:
    return {"instances": [{"id": "i-abc123", "state": "stopped"}]}


def create_agent_tool_registry() -> object:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "aws.ec2.start_instance": {
                    "spend_cents": lambda args: int(args["estimated_hourly_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {
                        "status": "completed",
                        "cost_cents": result["instance"]["hourly_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


TOOLS = {
    "aws.ec2.start_instance": start_instance,
    "aws.ec2.describe_instances": describe_instances,
}`;
      default:
        return `async def book_hotel(args: dict[str, object]) -> dict[str, object]:
    price_cents = int(args["estimated_price_cents"])
    return {
        "reservation": {
            "status": "confirmed",
            "price_cents": price_cents,
            "city": str(args["city"]),
        },
    }


async def search_web(args: dict[str, object]) -> dict[str, object]:
    return {"hits": [{"title": str(args["query"]), "url": "https://example.com"}]}


def create_agent_tool_registry() -> object:
    return create_paybond_tool_registry(
        {
            "side_effecting": {
                "travel.book_hotel": {
                    "spend_cents": lambda args: int(args["estimated_price_cents"]),
                    "evidence_preset": COMPLETION_PRESET_ID,
                    "evidence_mapper": lambda result, _ctx: {
                        "status": (
                            "completed"
                            if result["reservation"]["status"] == "confirmed"
                            else result["reservation"]["status"]
                        ),
                        "cost_cents": result["reservation"]["price_cents"],
                    },
                },
            },
            "default_deny": True,
        }
    )


TOOLS = {
    "travel.book_hotel": book_hotel,
    "search.web": search_web,
}`;
    }
  })();

  return `from paybond_config import create_paybond_client
from paybond_kit.agent import create_paybond_tool_registry

POLICY_FILE = "./paybond.policy.yaml"
COMPLETION_PRESET_ID = "${completionPreset}"
DEFAULT_OPERATION = "${primaryOperation}"
DEFAULT_REQUESTED_SPEND_CENTS = ${requestedSpendCents}

${toolBlock}


async def create_instrumented_agent():
    paybond = await create_paybond_client()
    tools = TOOLS
    return ${instrumentCall}


async def bind_sandbox_agent_run():
    paybond = await create_paybond_client()
    return await paybond.agent_run.bind(
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": DEFAULT_OPERATION,
                "requested_spend_cents": DEFAULT_REQUESTED_SPEND_CENTS,
                "completion_preset": COMPLETION_PRESET_ID,
            },
            "registry": create_agent_tool_registry(),
        }
    )
`;
}

async function upsertPackageJsonSmokeScript(
  cwd: string,
  smokeCommand: string,
  force: boolean,
): Promise<string | null> {
  const packageJsonPath = `${cwd}/package.json`;
  let existing: Record<string, unknown> | null = null;
  try {
    existing = JSON.parse(await readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  } catch {
    existing = null;
  }

  if (!existing) {
    const body = `${JSON.stringify(
      {
        private: true,
        type: "module",
        scripts: { smoke: smokeCommand },
      },
      null,
      2,
    )}\n`;
    await writeFileIfAllowed(packageJsonPath, body, force);
    return packageJsonPath;
  }

  const scripts =
    existing.scripts && typeof existing.scripts === "object" && !Array.isArray(existing.scripts)
      ? { ...(existing.scripts as Record<string, string>) }
      : {};
  if (scripts.smoke && scripts.smoke !== smokeCommand && !force) {
    throw new Error(`${packageJsonPath} already defines scripts.smoke (pass --force to overwrite)`);
  }
  scripts.smoke = smokeCommand;
  existing.scripts = scripts;
  await writeFile(packageJsonPath, `${JSON.stringify(existing, null, 2)}\n`, "utf8");
  return packageJsonPath;
}

/** Run the interactive or flag-driven project scaffold wizard. */
export async function runProjectInit(options: ProjectInitOptions): Promise<ProjectInitResult> {
  const resolved = await resolveInteractiveOptions(options);
  const presetId = presetIdForSolution(resolved.solution);
  const policyFile = `${options.cwd}/paybond.policy.yaml`;
  const configFile =
    resolved.language === "python"
      ? `${options.cwd}/paybond.config.py`
      : `${options.cwd}/paybond.config.ts`;
  const instrumentFile =
    resolved.language === "python"
      ? `${options.cwd}/paybond.instrument.py`
      : `${options.cwd}/paybond.instrument.ts`;
  const envExampleFile = `${options.cwd}/.env.example`;
  const files: string[] = [];

  await scaffoldPolicyFromPreset({
    out: policyFile,
    presetId,
    maxSpendUsd: resolved.maxSpendUsd,
    force: options.force,
  });
  files.push("paybond.policy.yaml");

  await writeFileIfAllowed(
    configFile,
    resolved.language === "python" ? pythonConfigTemplate() : typescriptConfigTemplate(),
    options.force ?? false,
  );
  files.push(resolved.language === "python" ? "paybond.config.py" : "paybond.config.ts");

  await writeFileIfAllowed(
    instrumentFile,
    resolved.language === "python"
      ? pythonInstrumentTemplate(resolved.solution, resolved.framework, resolved.maxSpendUsd)
      : typescriptInstrumentTemplate(resolved.solution, resolved.framework, resolved.maxSpendUsd),
    options.force ?? false,
  );
  files.push(
    resolved.language === "python" ? "paybond.instrument.py" : "paybond.instrument.ts",
  );

  await writeFileIfAllowed(envExampleFile, envExampleBody(), options.force ?? false);
  files.push(".env.example");

  const smokeCommand = smokeCommandFor(presetId);
  if (resolved.language === "typescript") {
    const packageJsonPath = await upsertPackageJsonSmokeScript(
      options.cwd,
      smokeCommand,
      options.force ?? false,
    );
    if (packageJsonPath) {
      files.push("package.json");
    }
  }

  const writeStdout = options.writeStdout ?? ((line: string) => output.write(`${line}\n`));
  for (const file of files) {
    writeStdout(`Created ${file}`);
  }
  writeStdout("");
  writeStdout("Ready to run:");
  writeStdout("  paybond login");
  if (resolved.language === "typescript") {
    writeStdout("  npm run smoke");
  } else {
    writeStdout(`  ${smokeCommand}`);
  }

  return {
    solution: resolved.solution,
    preset_id: presetId,
    max_spend_usd: resolved.maxSpendUsd,
    framework: resolved.framework,
    language: resolved.language,
    files,
    smoke_command: smokeCommand,
  };
}

export { usage as projectInitUsage };
