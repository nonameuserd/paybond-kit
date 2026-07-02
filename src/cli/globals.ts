import { generateRequestId } from "./request-id.js";
import { parseColorMode, resolveColorModeFromEnv } from "./color.js";
import { formatUnknownGlobalFlagMessage } from "./suggest.js";
import { InsecureGatewayURLError, requireSecureGatewayUrl } from "../gateway-url.js";
import { CliError, type GlobalOptions, type OutputFormat } from "./types.js";

export const DEFAULT_GATEWAY = "https://api.paybond.ai";
export const DEFAULT_ENV_FILE = ".env.local";

export const TENANT_OVERRIDE_FLAGS = ["--tenant-id", "--tenant", "--tenant_id"] as const;

export function rejectsTenantOverrideFlag(arg: string): boolean {
  for (const flag of TENANT_OVERRIDE_FLAGS) {
    if (arg === flag || arg.startsWith(`${flag}=`)) {
      return true;
    }
  }
  return false;
}

export function validateCliGateway(url: string): string {
  try {
    return requireSecureGatewayUrl(url);
  } catch (err) {
    const message = err instanceof InsecureGatewayURLError ? err.message : String(err);
    throw new CliError(message, { category: "validation", code: "cli.validation.insecure_gateway" });
  }
}

export function parseRequiredNonNegativeInt(raw: string, field: string): number {
  const text = raw.trim();
  if (!text) {
    throw new CliError(`invalid ${field} (expected non-negative integer)`, {
      category: "validation",
      code: "cli.validation.invalid_integer",
    });
  }
  const value = Number(text);
  if (!Number.isInteger(value) || value < 0) {
    throw new CliError(`invalid ${field} (expected non-negative integer)`, {
      category: "validation",
      code: "cli.validation.invalid_integer",
    });
  }
  return value;
}

export function parseOptionalNonNegativeInt(raw: string | undefined, field: string): number {
  if (!raw?.trim()) {
    return 0;
  }
  return parseRequiredNonNegativeInt(raw, field);
}

const GLOBAL_FLAGS = new Set([
  "--gateway",
  "--env-file",
  "--format",
  "--json",
  "--jq",
  "--profile",
  "--request-id",
  "--yes",
  "--no-open",
  "--color",
  "--no-color",
]);

export function defaultGlobalOptions(): GlobalOptions {
  return {
    gateway: DEFAULT_GATEWAY,
    envFile: DEFAULT_ENV_FILE,
    format: "table",
    color: resolveColorModeFromEnv(),
    requestId: generateRequestId(),
    yes: false,
    noOpen: false,
  };
}

export type ParsedCliArgv = {
  globals: GlobalOptions;
  command: string[];
};

function parseFormat(raw: string): OutputFormat {
  const value = raw.trim().toLowerCase();
  if (value === "table" || value === "json") {
    return value;
  }
  throw new CliError("invalid --format (expected table|json)", { category: "usage", code: "cli.usage.invalid_format" });
}

function readFlagValue(argv: string[], index: number, flag: string): { value: string; consumed: number } {
  const arg = argv[index]!;
  if (arg.startsWith(`${flag}=`)) {
    return { value: arg.slice(flag.length + 1), consumed: 1 };
  }
  const next = argv[index + 1];
  if (!next || next.startsWith("-")) {
    throw new CliError(`missing value for ${flag}`, { category: "usage", code: "cli.usage.missing_flag_value" });
  }
  return { value: next, consumed: 2 };
}

export function parseCliArgv(argv: string[]): ParsedCliArgv {
  for (const arg of argv) {
    if (rejectsTenantOverrideFlag(arg)) {
      throw new CliError("tenant scope comes from authenticated credentials; do not pass --tenant-id", {
        category: "usage",
        code: "cli.usage.tenant_override_forbidden",
      });
    }
  }
  const globals = defaultGlobalOptions();
  const command: string[] = [];
  let i = 0;
  while (i < argv.length) {
    const arg = argv[i]!;
    if (arg === "--help" || arg === "-h") {
      command.push(arg);
      i += 1;
      continue;
    }
    if (arg === "--yes") {
      globals.yes = true;
      i += 1;
      continue;
    }
    if (arg === "--no-open") {
      globals.noOpen = true;
      i += 1;
      continue;
    }
    if (arg === "--no-color") {
      globals.color = "never";
      i += 1;
      continue;
    }
    if (arg === "--color" || arg.startsWith("--color=")) {
      const { value, consumed } = readFlagValue(argv, i, "--color");
      try {
        globals.color = parseColorMode(value);
      } catch (err) {
        throw new CliError(err instanceof Error ? err.message : String(err), {
          category: "usage",
          code: "cli.usage.invalid_color",
        });
      }
      i += consumed;
      continue;
    }
    if (arg === "--gateway" || arg.startsWith("--gateway=")) {
      const { value, consumed } = readFlagValue(argv, i, "--gateway");
      if (!value.trim()) {
        throw new CliError("invalid --gateway", { category: "usage", code: "cli.usage.invalid_gateway" });
      }
      globals.gateway = validateCliGateway(value.trim());
      i += consumed;
      continue;
    }
    if (arg === "--env-file" || arg.startsWith("--env-file=")) {
      const { value, consumed } = readFlagValue(argv, i, "--env-file");
      if (!value.trim()) {
        throw new CliError("invalid --env-file", { category: "usage", code: "cli.usage.invalid_env_file" });
      }
      globals.envFile = value.trim();
      i += consumed;
      continue;
    }
    if (arg === "--format" || arg.startsWith("--format=")) {
      const { value, consumed } = readFlagValue(argv, i, "--format");
      globals.format = parseFormat(value);
      i += consumed;
      continue;
    }
    if (arg === "--profile" || arg.startsWith("--profile=")) {
      const { value, consumed } = readFlagValue(argv, i, "--profile");
      if (!value.trim()) {
        throw new CliError("invalid --profile", { category: "usage", code: "cli.usage.invalid_profile" });
      }
      globals.profile = value.trim();
      i += consumed;
      continue;
    }
    if (arg === "--request-id" || arg.startsWith("--request-id=")) {
      const { value, consumed } = readFlagValue(argv, i, "--request-id");
      if (!value.trim()) {
        throw new CliError("invalid --request-id", { category: "usage", code: "cli.usage.invalid_request_id" });
      }
      globals.requestId = value.trim();
      i += consumed;
      continue;
    }
    if (arg === "--json" || arg.startsWith("--json=")) {
      const { value, consumed } = readFlagValue(argv, i, "--json");
      if (!value.trim()) {
        throw new CliError("invalid --json (expected comma-separated field names)", {
          category: "usage",
          code: "cli.usage.invalid_json_fields",
        });
      }
      globals.jsonFields = value.trim();
      i += consumed;
      continue;
    }
    if (arg === "--jq" || arg.startsWith("--jq=")) {
      const { value, consumed } = readFlagValue(argv, i, "--jq");
      if (!value.trim()) {
        throw new CliError("invalid --jq (expected filter expression)", { category: "usage", code: "cli.usage.invalid_jq" });
      }
      globals.jqExpr = value.trim();
      i += consumed;
      continue;
    }
    if (arg.startsWith("--") && !GLOBAL_FLAGS.has(arg.split("=")[0]!)) {
      if (command.length === 0) {
        throw new CliError(formatUnknownGlobalFlagMessage(arg), {
          category: "usage",
          code: "cli.usage.unknown_flag",
        });
      }
    }
    command.push(arg);
    i += 1;
  }
  return { globals, command };
}

export function consumeFlag(argv: string[], flag: string): { present: boolean; value?: string; rest: string[] } {
  const rest: string[] = [];
  let present = false;
  let value: string | undefined;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === flag) {
      present = true;
      const next = argv[i + 1];
      if (!next || next.startsWith("-")) {
        throw new CliError(`missing value for ${flag}`, { category: "usage", code: "cli.usage.missing_flag_value" });
      }
      value = next;
      i += 1;
      continue;
    }
    if (arg.startsWith(`${flag}=`)) {
      present = true;
      value = arg.slice(flag.length + 1);
      continue;
    }
    rest.push(arg);
  }
  return { present, value, rest };
}

export function consumeBooleanFlag(argv: string[], flag: string): { present: boolean; rest: string[] } {
  const rest = argv.filter((arg) => {
    if (arg === flag) {
      return false;
    }
    return true;
  });
  return { present: argv.length !== rest.length, rest };
}
