import { readFile } from "node:fs/promises";
import { extname } from "node:path";

import { getCompletionPreset, listCompletionPresetIds } from "../completion-catalog.js";
import { PaybondToolRegistry, createPaybondToolRegistry } from "./registry.js";
import {
  PaybondSideEffectingToolPolicy,
  PaybondToolRegistryConfig,
  PaybondToolRegistryValidationError,
} from "./types.js";

export type AgentRegistryFileDocument = {
  version?: number;
  default_deny?: boolean;
  defaultDeny?: boolean;
  tools?: Record<string, AgentRegistryToolEntry>;
};

export type AgentRegistryToolEntry = {
  side_effecting?: boolean;
  sideEffecting?: boolean;
  evidence_preset?: string;
  evidencePreset?: string;
  operation?: string;
};

export type AgentRegistryValidationIssue = {
  code: string;
  message: string;
  tool?: string;
};

export type AgentRegistryValidationResult = {
  ok: boolean;
  version: number | null;
  default_deny: boolean;
  tool_count: number;
  side_effecting_count: number;
  issues: AgentRegistryValidationIssue[];
  registry?: PaybondToolRegistry;
};

function isSideEffecting(entry: AgentRegistryToolEntry): boolean {
  const raw = entry.side_effecting ?? entry.sideEffecting;
  return raw !== false;
}

function evidencePreset(entry: AgentRegistryToolEntry): string | undefined {
  const raw = entry.evidence_preset ?? entry.evidencePreset;
  return typeof raw === "string" && raw.trim() ? raw.trim() : undefined;
}

function normalizeDocument(raw: unknown): AgentRegistryFileDocument {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new PaybondToolRegistryValidationError("registry file must be a JSON or YAML object");
  }
  return raw as AgentRegistryFileDocument;
}

/** Parse registry file text (JSON or YAML). */
export function parseAgentRegistryText(text: string, sourceLabel = "registry file"): AgentRegistryFileDocument {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new PaybondToolRegistryValidationError(`${sourceLabel} is empty`);
  }
  try {
    return normalizeDocument(JSON.parse(trimmed));
  } catch {
    return normalizeDocument(parseSimpleYamlRegistry(trimmed, sourceLabel));
  }
}

/** Load and parse a registry file from disk. */
export async function loadAgentRegistryFile(path: string): Promise<AgentRegistryFileDocument> {
  const text = await readFile(path, "utf8");
  return parseAgentRegistryText(text, path);
}

function parseSimpleYamlRegistry(text: string, sourceLabel: string): Record<string, unknown> {
  const ext = extname(sourceLabel).toLowerCase();
  if (ext !== ".yaml" && ext !== ".yml" && !text.includes("\n") && !text.includes(":")) {
    throw new PaybondToolRegistryValidationError(`${sourceLabel} is not valid JSON`);
  }
  const root: Record<string, unknown> = {};
  let section: "root" | "tools" = "root";
  let currentTool: string | null = null;
  const tools: Record<string, Record<string, unknown>> = {};

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const match = /^(\S+?):\s*(.*)$/.exec(line);
    if (!match) {
      throw new PaybondToolRegistryValidationError(`${sourceLabel} has invalid YAML line: ${rawLine}`);
    }
    const [, key, rawValue] = match;
    const value = rawValue.trim();
    if (section === "root" && key === "tools" && !value) {
      section = "tools";
      continue;
    }
    if (section === "tools" && !value) {
      currentTool = key;
      tools[currentTool] = {};
      continue;
    }
    const parsedValue = parseYamlScalar(value);
    if (section === "tools" && currentTool) {
      tools[currentTool]![key] = parsedValue;
      continue;
    }
    root[key] = parsedValue;
  }

  if (Object.keys(tools).length > 0) {
    root.tools = tools;
  }
  return root;
}

function parseYamlScalar(value: string): unknown {
  if (!value) {
    return "";
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (/^-?\d+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

/** Convert a registry file document into middleware registry config. */
export function agentRegistryDocumentToConfig(doc: AgentRegistryFileDocument): PaybondToolRegistryConfig {
  const defaultDeny = Boolean(doc.default_deny ?? doc.defaultDeny ?? false);
  const sideEffecting: PaybondToolRegistryConfig["sideEffecting"] = {};
  for (const [toolName, entry] of Object.entries(doc.tools ?? {})) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    if (!isSideEffecting(entry)) {
      continue;
    }
    const preset = evidencePreset(entry);
    if (!preset) {
      throw new PaybondToolRegistryValidationError(
        `side-effecting tool "${toolName}" must declare evidence_preset`,
      );
    }
    const policy: PaybondSideEffectingToolPolicy = {
      evidencePreset: preset,
    };
    if (entry.operation?.trim()) {
      policy.operation = entry.operation.trim();
    }
    sideEffecting[toolName] = policy;
  }
  return { defaultDeny, sideEffecting };
}

/** Validate registry document semantics before bind or smoke tests. */
export function validateAgentRegistryDocument(doc: AgentRegistryFileDocument): AgentRegistryValidationResult {
  const issues: AgentRegistryValidationIssue[] = [];
  const version = typeof doc.version === "number" ? doc.version : null;
  if (version !== null && version !== 1) {
    issues.push({
      code: "registry.unsupported_version",
      message: `unsupported registry version ${version}; expected 1`,
    });
  }

  const defaultDeny = Boolean(doc.default_deny ?? doc.defaultDeny ?? false);
  if (defaultDeny) {
    issues.push({
      code: "registry.default_deny_documented",
      message: "default_deny is enabled: every intent allowed operation must be registered as side-effecting",
    });
  }

  const tools = doc.tools ?? {};
  const operations = new Map<string, string>();
  let sideEffectingCount = 0;

  for (const [toolName, entry] of Object.entries(tools)) {
    if (!entry || typeof entry !== "object") {
      issues.push({
        code: "registry.invalid_tool_entry",
        message: `tool "${toolName}" must be an object`,
        tool: toolName,
      });
      continue;
    }
    if (!isSideEffecting(entry)) {
      continue;
    }
    sideEffectingCount += 1;
    const preset = evidencePreset(entry);
    if (!preset) {
      issues.push({
        code: "registry.missing_evidence_preset",
        message: `side-effecting tool "${toolName}" must declare evidence_preset`,
        tool: toolName,
      });
      continue;
    }
    try {
      getCompletionPreset(preset);
    } catch {
      issues.push({
        code: "registry.unknown_evidence_preset",
        message: `tool "${toolName}" references unknown evidence_preset "${preset}" (catalog: ${listCompletionPresetIds().join(", ")})`,
        tool: toolName,
      });
    }
    const operation = (entry.operation?.trim() || toolName).trim();
    const previous = operations.get(operation);
    if (previous !== undefined && previous !== toolName) {
      issues.push({
        code: "registry.duplicate_operation",
        message: `duplicate operation "${operation}" for tools "${previous}" and "${toolName}"`,
        tool: toolName,
      });
    } else {
      operations.set(operation, toolName);
    }
  }

  let registry: PaybondToolRegistry | undefined;
  if (issues.every((issue) => issue.code === "registry.default_deny_documented")) {
    try {
      registry = createPaybondToolRegistry(agentRegistryDocumentToConfig(doc));
    } catch (err) {
      issues.push({
        code: "registry.invalid_config",
        message: err instanceof Error ? err.message : String(err),
      });
    }
  }

  const blocking = issues.filter((issue) => issue.code !== "registry.default_deny_documented");
  return {
    ok: blocking.length === 0,
    version,
    default_deny: defaultDeny,
    tool_count: Object.keys(tools).length,
    side_effecting_count: sideEffectingCount,
    issues,
    registry,
  };
}

/** Build a single-tool registry for sandbox smoke when no registry file is supplied. */
export function buildSmokeRegistry(operation: string, evidencePresetId: string): PaybondToolRegistry {
  return createPaybondToolRegistry({
    defaultDeny: true,
    sideEffecting: {
      [operation]: { evidencePreset: evidencePresetId, operation },
    },
  });
}
