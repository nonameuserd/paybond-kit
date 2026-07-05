import { access, cp, readFile, readdir } from "node:fs/promises";
import { constants } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { PolicyPresetId } from "./policy/presets.js";

export type TemplateId =
  | "travel-agent"
  | "mastra-travel-agent"
  | "vercel-shopping-agent"
  | "openai-agents-demo"
  | "openai-shopping-agent"
  | "claude-agents-demo"
  | "mcp-coding-agent"
  | "procurement-agent"
  | "invoice-agent"
  | "aws-operator";

export type TemplateManifestEntry = {
  id: TemplateId;
  repo: string;
  title: string;
  language: "typescript" | "python";
  framework: string;
  preset: PolicyPresetId | null;
  primary_operation: string;
  requested_spend_cents: number;
  evidence_preset: string;
  smoke_result_body: Record<string, unknown>;
};

type TemplateManifest = {
  version: number;
  templates: TemplateManifestEntry[];
};

export type TemplateFramework =
  | "generic"
  | "langgraph"
  | "vercel-ai"
  | "openai-agents"
  | "claude-agents"
  | "mcp"
  | "mastra";

const TEMPLATE_FRAMEWORK_ALIASES: Record<string, TemplateFramework> = {
  generic: "generic",
  langgraph: "langgraph",
  "vercel-ai": "vercel-ai",
  vercel: "vercel-ai",
  openai: "openai-agents",
  "openai-agents": "openai-agents",
  claude: "claude-agents",
  "claude-agents": "claude-agents",
  mcp: "mcp",
  mastra: "mastra",
};

/** Normalize CLI `--framework` values to bundled template framework ids. */
export function normalizeTemplateFramework(raw: string): TemplateFramework {
  const normalized = TEMPLATE_FRAMEWORK_ALIASES[raw.trim().toLowerCase()];
  if (!normalized) {
    throw new Error(`invalid --framework for template init: ${raw}`);
  }
  return normalized;
}

function frameworkForEntry(entry: TemplateManifestEntry): TemplateFramework {
  return normalizeTemplateFramework(entry.framework);
}

const TEMPLATE_ALIASES: Record<string, TemplateId> = {
  "travel-agent": "travel-agent",
  "paybond-travel-agent": "travel-agent",
  "mastra-travel-agent": "mastra-travel-agent",
  "paybond-mastra-travel-agent": "mastra-travel-agent",
  "vercel-shopping-agent": "vercel-shopping-agent",
  "paybond-vercel-shopping-agent": "vercel-shopping-agent",
  "openai-agents-demo": "openai-agents-demo",
  "paybond-openai-agents-demo": "openai-agents-demo",
  "openai-shopping-agent": "openai-shopping-agent",
  "claude-agents-demo": "claude-agents-demo",
  "paybond-claude-agents-demo": "claude-agents-demo",
  "mcp-coding-agent": "mcp-coding-agent",
  "paybond-mcp-coding-agent": "mcp-coding-agent",
  "procurement-agent": "procurement-agent",
  "paybond-procurement-agent": "procurement-agent",
  "invoice-agent": "invoice-agent",
  "paybond-invoice-agent": "invoice-agent",
  "aws-operator": "aws-operator",
  "paybond-aws-operator": "aws-operator",
};

function moduleDir(): string {
  return dirname(fileURLToPath(import.meta.url));
}

function resolveTemplatesRoots(): string[] {
  const dir = moduleDir();
  return [
    join(dir, "../templates"),
    join(dir, "../../templates"),
    join(dir, "../../../kit/ts/templates"),
  ];
}

async function firstExistingDir(candidates: string[]): Promise<string> {
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.F_OK);
      return candidate;
    } catch {
      // try next
    }
  }
  throw new Error("bundled Paybond templates directory not found");
}

let cachedManifest: TemplateManifest | null = null;

/** Load the bundled starter-template manifest shipped with @paybond/kit. */
export async function loadTemplateManifest(): Promise<TemplateManifest> {
  if (cachedManifest) {
    return cachedManifest;
  }
  const root = await firstExistingDir(resolveTemplatesRoots());
  const raw = await readFile(join(root, "manifest.json"), "utf8");
  cachedManifest = JSON.parse(raw) as TemplateManifest;
  return cachedManifest;
}

/** Normalize template id or repo slug to a canonical template id. */
export function normalizeTemplateId(raw: string): TemplateId {
  const normalized = TEMPLATE_ALIASES[raw.trim().toLowerCase()];
  if (!normalized) {
    throw new Error(`invalid --template: ${raw}`);
  }
  return normalized;
}

/** List bundled starter templates for CLI and docs. */
export async function listTemplateEntries(): Promise<TemplateManifestEntry[]> {
  const manifest = await loadTemplateManifest();
  return [...manifest.templates];
}

export async function resolveTemplateEntry(templateId: TemplateId): Promise<TemplateManifestEntry> {
  const manifest = await loadTemplateManifest();
  const entry = manifest.templates.find((candidate) => candidate.id === templateId);
  if (!entry) {
    throw new Error(`unknown template: ${templateId}`);
  }
  return entry;
}

/** Resolve a bundled template and optionally validate `--framework`. */
export async function resolveTemplateForInit(input: {
  templateId: TemplateId;
  framework?: string;
}): Promise<TemplateManifestEntry> {
  const entry = await resolveTemplateEntry(input.templateId);
  if (input.framework) {
    const normalized = normalizeTemplateFramework(input.framework);
    if (frameworkForEntry(entry) !== normalized) {
      throw new Error(
        `template ${entry.id} uses framework ${entry.framework}; --framework ${input.framework} does not match`,
      );
    }
  }
  return entry;
}

function smokeCommandForEntry(entry: TemplateManifestEntry): string {
  const resultBody = JSON.stringify(entry.smoke_result_body);
  return [
    "paybond agent sandbox smoke",
    "--policy-file paybond.policy.yaml",
    `--operation ${entry.primary_operation}`,
    `--requested-spend-cents ${entry.requested_spend_cents}`,
    `--evidence-preset ${entry.evidence_preset}`,
    `--result-body '${resultBody}'`,
    "--format json",
  ].join(" ");
}

export type CopyTemplateOptions = {
  cwd: string;
  templateId: TemplateId;
  framework?: string;
  force?: boolean;
  writeStdout?: (line: string) => void;
};

export type CopyTemplateResult = {
  template_id: TemplateId;
  repo: string;
  title: string;
  language: TemplateManifestEntry["language"];
  framework: string;
  preset: PolicyPresetId | null;
  files: string[];
  smoke_command: string;
};

async function pathExists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

/** Copy a bundled starter template tree into the target directory. */
export async function copyTemplateToDirectory(
  options: CopyTemplateOptions,
): Promise<CopyTemplateResult> {
  const entry = await resolveTemplateForInit({
    templateId: options.templateId,
    framework: options.framework,
  });
  const templatesRoot = await firstExistingDir(resolveTemplatesRoots());
  const sourceDir = join(templatesRoot, entry.repo);

  try {
    await access(sourceDir, constants.F_OK);
  } catch {
    throw new Error(`template source missing: ${entry.repo}`);
  }

  const writeStdout = options.writeStdout;
  const copied: string[] = [];
  const entries = await readdir(sourceDir, { withFileTypes: true });

  for (const dirent of entries) {
    const relativePath = dirent.name;
    const sourcePath = join(sourceDir, relativePath);
    const targetPath = join(options.cwd, relativePath);
    if (await pathExists(targetPath) && !options.force) {
      throw new Error(`${relativePath} already exists (pass --force to overwrite)`);
    }
    await cp(sourcePath, targetPath, {
      recursive: true,
      force: options.force ?? false,
      errorOnExist: !options.force,
    });
    copied.push(relativePath);
    writeStdout?.(`Created ${relativePath}`);
  }

  const smokeCommand = smokeCommandForEntry(entry);
  writeStdout?.("");
  writeStdout?.("Ready to run:");
  writeStdout?.("  paybond login");
  if (entry.language === "python") {
    writeStdout?.("  pip install -r requirements.txt");
  } else {
    writeStdout?.("  npm install");
  }
  writeStdout?.(`  ${entry.language === "typescript" ? "npm run smoke" : smokeCommand}`);

  return {
    template_id: entry.id,
    repo: entry.repo,
    title: entry.title,
    language: entry.language,
    framework: entry.framework,
    preset: entry.preset,
    files: copied,
    smoke_command: smokeCommand,
  };
}

export function templateInitUsage(): string {
  return [
    "Usage: paybond init [--template <id>|--repo <slug>] [--framework <name>] [--force]",
    "       paybond init [--solution ...] [--framework ...]  (wizard scaffold)",
    "",
    "Templates:",
    "  travel-agent, mastra-travel-agent, vercel-shopping-agent, openai-agents-demo, openai-shopping-agent,",
    "  claude-agents-demo, mcp-coding-agent, procurement-agent, invoice-agent, aws-operator",
    "",
    "Frameworks (with --template): generic|langgraph|vercel-ai|openai|openai-agents|claude-agents|mcp|mastra",
    "",
    "Examples:",
    "  paybond init --template travel-agent --framework langgraph",
    "  paybond init --template mastra-travel-agent --framework mastra",
    "  paybond init --template paybond-vercel-shopping-agent --force",
    "  paybond init --solution travel --framework langgraph --non-interactive",
  ].join("\n");
}