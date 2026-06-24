import { spawnSync } from "node:child_process";
import { mkdtempSync, renameSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { CliError } from "./types.js";

/** Stable machine-readable warning codes for automation consumers. */
export const CLI_WARN_PARTIAL_RESULTS = "cli.warn.partial_results";
export const CLI_WARN_GATEWAY_RETRY = "cli.warn.gateway_retry";
export const CLI_WARN_DEPRECATED_ALIAS = "cli.warn.deprecated_alias";
export const CLI_WARN_ENV_FALLBACK = "cli.warn.env_fallback";

export function formatWarning(code: string, detail?: string): string {
  return detail ? `${code}: ${detail}` : code;
}

const LEGACY_INVOCATION_ALIASES: Record<string, string> = {
  "paybond-kit-login": "paybond login",
  "paybond-init": "paybond init guardrail",
  "paybond-kit-init": "paybond init guardrail",
  "paybond-mcp-server": "paybond mcp serve",
};

export function deprecatedAliasWarning(argv0: string | undefined): string | undefined {
  const base = (argv0 ?? "").split(/[/\\]/).pop() ?? "";
  const canonical = LEGACY_INVOCATION_ALIASES[base];
  if (!canonical) {
    return undefined;
  }
  return formatWarning(CLI_WARN_DEPRECATED_ALIAS, `use ${canonical} instead of ${base}`);
}

export function parseJsonFields(raw: string): string[] {
  const fields = raw
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (fields.length === 0) {
    throw new CliError("invalid --json (expected comma-separated field names)", {
      category: "usage",
      code: "cli.usage.invalid_json_fields",
    });
  }
  return fields;
}

function readNestedField(row: Record<string, unknown>, field: string): unknown {
  const parts = field.split(".").filter(Boolean);
  let current: unknown = row;
  for (const part of parts) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export function selectJsonFields(rows: Record<string, unknown>[], fields: string[]): Record<string, unknown>[] {
  return rows.map((row) => {
    const selected: Record<string, unknown> = {};
    for (const field of fields) {
      const value = field.includes(".") ? readNestedField(row, field) : row[field];
      if (field.includes(".")) {
        selected[field] = value;
      } else {
        selected[field] = value;
      }
    }
    return selected;
  });
}

const LIST_ARRAY_KEYS = ["items", "keys", "exports", "intents", "tools", "entries", "contracts", "jobs"] as const;

export function extractListArray(data: Record<string, unknown>): Record<string, unknown>[] | null {
  for (const key of LIST_ARRAY_KEYS) {
    const value = data[key];
    if (Array.isArray(value)) {
      return value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === "object" && !Array.isArray(item));
    }
  }
  return null;
}

export function applyJsonFieldSelection(
  command: string,
  data: Record<string, unknown>,
  fields: string[],
): Record<string, unknown> | Record<string, unknown>[] {
  const rows = extractListArray(data);
  if (rows) {
    return selectJsonFields(rows, fields);
  }
  return selectJsonFields([data], fields)[0] ?? {};
}

function trySimpleJqPath(data: unknown, expr: string): unknown | undefined {
  const trimmed = expr.trim();
  if (!trimmed || trimmed === ".") {
    return data;
  }
  const pipeParts = trimmed.split("|").map((part) => part.trim());
  let current: unknown = data;
  for (const part of pipeParts) {
    if (part === ".") {
      continue;
    }
    if (part === ".[]") {
      if (!Array.isArray(current)) {
        return undefined;
      }
      current = current;
      continue;
    }
    if (part.endsWith("[]")) {
      const key = part.slice(0, -2);
      if (key === ".") {
        if (!Array.isArray(current)) {
          return undefined;
        }
        continue;
      }
      if (!key.startsWith(".") || !current || typeof current !== "object" || Array.isArray(current)) {
        return undefined;
      }
      const field = key.slice(1);
      const nested = (current as Record<string, unknown>)[field];
      if (!Array.isArray(nested)) {
        return undefined;
      }
      current = nested;
      continue;
    }
    if (part.startsWith(".")) {
      const arraySubfield = part.match(/^\.([^.[]+)(\[\])(?:\.(.+))?$/);
      if (arraySubfield) {
        const [, field, , subfield] = arraySubfield;
        if (!current || typeof current !== "object" || Array.isArray(current)) {
          return undefined;
        }
        const nested = (current as Record<string, unknown>)[field!];
        if (!Array.isArray(nested)) {
          return undefined;
        }
        if (!subfield) {
          current = nested;
          continue;
        }
        current = nested.map((item) =>
          item && typeof item === "object" && !Array.isArray(item)
            ? (item as Record<string, unknown>)[subfield]
            : undefined,
        );
        continue;
      }
      const pathParts = part.slice(1).split(".").filter(Boolean);
      for (const segment of pathParts) {
        if (!current || typeof current !== "object" || Array.isArray(current)) {
          return undefined;
        }
        current = (current as Record<string, unknown>)[segment];
      }
      continue;
    }
    return undefined;
  }
  return current;
}

function runJqBinary(data: unknown, expr: string): unknown | undefined {
  try {
    const result = spawnSync("jq", ["-c", expr], {
      input: JSON.stringify(data),
      encoding: "utf8",
      maxBuffer: 10 * 1024 * 1024,
    });
    if (result.status !== 0 || result.error) {
      return undefined;
    }
    const output = result.stdout.trim();
    if (!output) {
      return null;
    }
    return JSON.parse(output) as unknown;
  } catch {
    return undefined;
  }
}

export function applyJqFilter(data: unknown, expr: string): unknown {
  const trimmed = expr.trim();
  if (!trimmed || trimmed === ".") {
    return data;
  }
  const simple = trySimpleJqPath(data, trimmed);
  if (simple !== undefined) {
    return simple;
  }
  const fromBinary = runJqBinary(data, trimmed);
  if (fromBinary !== undefined) {
    return fromBinary;
  }
  throw new CliError(`invalid --jq expression: ${expr}`, {
    category: "usage",
    code: "cli.usage.invalid_jq",
  });
}

export function supportsAutomationOutput(command: string): boolean {
  return (
    command.endsWith(" list") ||
    command.endsWith(" get") ||
    command === "whoami" ||
    command === "mcp tools" ||
    command === "a2a contracts" ||
    command === "a2a card"
  );
}

export function applyAutomationTransforms(
  command: string,
  data: Record<string, unknown>,
  options: { jsonFields?: string; jqExpr?: string },
): unknown {
  if (!supportsAutomationOutput(command)) {
    if (options.jsonFields || options.jqExpr) {
      throw new CliError(`--json/--jq are not supported for ${command}`, {
        category: "usage",
        code: "cli.usage.automation_unsupported",
      });
    }
    return data;
  }
  let current: unknown = data;
  if (options.jsonFields) {
    current = applyJsonFieldSelection(command, data, parseJsonFields(options.jsonFields));
  }
  if (options.jqExpr) {
    current = applyJqFilter(current, options.jqExpr);
  }
  return current;
}

export function extractNextCursor(body: Record<string, unknown>): string | undefined {
  const raw = body.next_cursor ?? body.nextCursor ?? body.cursor_next;
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return undefined;
}

export function partialResultsWarning(nextCursor: string | undefined): string | undefined {
  if (!nextCursor) {
    return undefined;
  }
  return formatWarning(CLI_WARN_PARTIAL_RESULTS, "more items available; pass --cursor");
}

export function buildListQueryParams(
  limit: string | undefined,
  cursor: string | undefined,
  defaults: { limit?: string } = {},
): URLSearchParams {
  const params = new URLSearchParams({ limit: limit?.trim() || defaults.limit || "20" });
  if (cursor?.trim()) {
    params.set("cursor", cursor.trim());
  }
  return params;
}

export async function readJsonBody(source: string, stdin?: NodeJS.ReadableStream): Promise<Record<string, unknown>> {
  const normalized = source.trim();
  let raw: string;
  if (normalized === "-" || normalized === "stdin") {
    if (!stdin) {
      throw new CliError("JSON body requires --body - with stdin piped in", {
        category: "usage",
        code: "cli.usage.missing_stdin",
      });
    }
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    }
    raw = Buffer.concat(chunks).toString("utf8");
  } else {
    raw = await readFile(normalized, "utf8");
  }
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new CliError("JSON body must be an object", { category: "validation", code: "cli.validation.invalid_json_body" });
  }
  return parsed as Record<string, unknown>;
}

export function writeAtomicFile(path: string, content: string | Uint8Array, mode = 0o600): void {
  const dir = dirname(path);
  const prefix = join(dir, ".paybond-write-");
  const tempDir = mkdtempSync(prefix);
  const tempFile = join(tempDir, "payload");
  try {
    writeFileSync(tempFile, content);
    chmodSync(tempFile, mode);
    renameSync(tempFile, path);
    rmSync(tempDir, { recursive: true, force: true });
  } catch (err) {
    rmSync(tempDir, { recursive: true, force: true });
    throw err;
  }
}

export async function writeAtomicFileAsync(path: string, content: string | Uint8Array, mode = 0o600): Promise<void> {
  const { mkdir, writeFile, chmod, rename, rm } = await import("node:fs/promises");
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  const tempDir = await import("node:fs/promises").then((mod) =>
    mod.mkdtemp(join(tmpdir(), "paybond-write-")),
  );
  const tempFile = join(tempDir, "payload");
  try {
    await writeFile(tempFile, content);
    await chmod(tempFile, mode);
    await rename(tempFile, path);
    await rm(tempDir, { recursive: true, force: true });
  } catch (err) {
    await rm(tempDir, { recursive: true, force: true });
    throw err;
  }
}
