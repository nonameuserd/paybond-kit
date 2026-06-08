#!/usr/bin/env node

declare const process: {
  argv: string[];
  cwd(): string;
  exitCode?: number;
  stderr: { write(chunk: string): boolean };
  stdout: { write(chunk: string): boolean };
};

type Framework =
  | "generic"
  | "provider-agnostic"
  | "openai"
  | "claude"
  | "anthropic"
  | "gemini"
  | "google-ai"
  | "vercel-ai"
  | "langgraph"
  | "mcp";

type Preset = "paid-tool-guard";

const FRAMEWORKS = new Set<Framework>([
  "generic",
  "provider-agnostic",
  "openai",
  "claude",
  "anthropic",
  "gemini",
  "google-ai",
  "vercel-ai",
  "langgraph",
  "mcp",
]);

const PRESETS = new Set<Preset>(["paid-tool-guard"]);

const FRAMEWORK_NOTES: Record<Framework, string> = {
  generic: "Wrap the returned function around any side-effecting tool handler.",
  "provider-agnostic": "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
  openai: "Call the guarded handler before the OpenAI tool call performs paid or external work.",
  claude: "Call the guarded handler before the Claude tool-use action performs paid or external work.",
  anthropic: "Call the guarded handler before the Anthropic tool-use action performs paid or external work.",
  gemini: "Call the guarded handler before the Gemini function call performs paid or external work.",
  "google-ai": "Call the guarded handler before the Google AI function call performs paid or external work.",
  "vercel-ai": "Call the guarded handler from your Vercel AI SDK tool execute function.",
  langgraph: "Call the guarded handler from the LangGraph JS node or tool wrapper that performs paid work.",
  mcp: "Call the guarded handler inside the MCP tool implementation before paid or external work runs.",
};

function usage(): string {
  return [
    "Usage: paybond-init [--preset paid-tool-guard] [--framework generic|provider-agnostic|openai|claude|anthropic|gemini|google-ai|vercel-ai|langgraph|mcp] [--out paybond-paid-tool-guard.ts] [--force]",
    "",
    "Scaffolds a production-shaped Paybond guardrail integration helper.",
  ].join("\n");
}

function parseArgs(argv: string[]): { preset: Preset; framework: Framework; out: string; force: boolean } {
  let preset: Preset = "paid-tool-guard";
  let framework: Framework = "provider-agnostic";
  let out = "paybond-paid-tool-guard.ts";
  let force = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exitCode = 0;
      return { preset, framework, out, force };
    }
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--preset") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || !PRESETS.has(raw as Preset)) {
        throw new Error("invalid --preset");
      }
      preset = raw as Preset;
      continue;
    }
    if (arg === "--framework") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || !FRAMEWORKS.has(raw as Framework)) {
        throw new Error("invalid --framework");
      }
      framework = raw as Framework;
      continue;
    }
    if (arg === "--out") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || raw.startsWith("-")) {
        throw new Error("invalid --out");
      }
      out = raw;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  return { preset, framework, out, force };
}

function template(framework: Framework): string {
  return `import {
  Paybond,
  type SandboxGuardrailBootstrapResult,
  type SandboxGuardrailEvidenceResult,
} from "@paybond/kit";

declare const process: {
  env: Record<string, string | undefined>;
};

// Production integration helpers only. Add your paid-tool handler in
// application code and pass it to wrapPaidTool(...).
const DEFAULT_OPERATION = "paid_tool.operation";
const DEFAULT_REQUESTED_SPEND_CENTS = 500;

export type PaidToolHandler<TInput, TResult> = (input: TInput) => TResult | Promise<TResult>;

export type SandboxGuardrailIntentOptions = {
  operation?: string;
  requestedSpendCents?: number;
  currency?: string;
  evidenceSchema?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
  idempotencyKey?: string;
};

export type SubmitSandboxEvidenceOptions = {
  operation?: string;
  requestedSpendCents?: number;
  metadata?: Record<string, unknown>;
  artifacts?: string[];
  idempotencyKey?: string;
};

export type OpenPaybondFromEnvOptions = {
  /**
   * Load PAYBOND_API_KEY from this local env file when the process environment
   * does not already provide it. Pass false when your agent host injects secrets.
   */
  envFile?: string | false;
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

async function readTextFile(envFile: string): Promise<string | undefined> {
  // @ts-ignore Node builtins are available in agent and CLI Node runtimes.
  const fs: { readFile(path: string, encoding: "utf8"): Promise<string> } = await import("node:fs/promises");
  try {
    return await fs.readFile(envFile, "utf8");
  } catch (err) {
    if ((err as { code?: unknown })?.code === "ENOENT") return undefined;
    throw err;
  }
}

export async function loadPaybondEnvFile(envFile = ".env.local"): Promise<void> {
  if (process.env.PAYBOND_API_KEY?.trim()) return;
  const body = await readTextFile(envFile);
  if (body === undefined) return;
  const apiKey = readEnvValue(body, "PAYBOND_API_KEY");
  if (apiKey) {
    process.env.PAYBOND_API_KEY = apiKey;
  }
}

export async function openPaybondFromEnv(options: OpenPaybondFromEnvOptions = {}): Promise<Paybond> {
  if (options.envFile !== false) {
    await loadPaybondEnvFile(options.envFile ?? ".env.local");
  }
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required; run paybond login or configure your agent host to pass it");
  }

  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL,
    expectedEnvironment: "sandbox",
  });
}

export async function bootstrapSandboxGuardrailIntent(
  paybond: Paybond,
  options: SandboxGuardrailIntentOptions = {},
): Promise<SandboxGuardrailBootstrapResult> {
  return paybond.guardrails.bootstrapSandbox({
    operation: options.operation ?? DEFAULT_OPERATION,
    requestedSpendCents: options.requestedSpendCents ?? DEFAULT_REQUESTED_SPEND_CENTS,
    currency: options.currency ?? "usd",
    evidenceSchema: options.evidenceSchema ?? {
      type: "object",
      required: ["confirmation_id", "charged_cents"],
      properties: {
        confirmation_id: { type: "string" },
        charged_cents: { type: "integer" },
      },
    },
    metadata: options.metadata,
    idempotencyKey: options.idempotencyKey,
  });
}

export function wrapPaidTool<TInput, TResult>(
  paybond: Paybond,
  guardrail: Pick<
    SandboxGuardrailBootstrapResult,
    "intent_id" | "capability_token" | "operation" | "requested_spend_cents"
  >,
  handler: PaidToolHandler<TInput, TResult>,
): (input: TInput) => Promise<Awaited<TResult>> {
  if (!guardrail.capability_token.trim()) {
    throw new Error("sandbox guardrail bootstrap did not return a capability token");
  }

  const guard = paybond.spendGuard(guardrail.intent_id, guardrail.capability_token);

  // ${FRAMEWORK_NOTES[framework]}
  return guard.guardTool(
    {
      operation: guardrail.operation,
      requestedSpendCents: guardrail.requested_spend_cents,
    },
    handler,
  );
}

export async function submitSandboxEvidence(
  paybond: Paybond,
  guardrail: Pick<SandboxGuardrailBootstrapResult, "intent_id" | "operation" | "requested_spend_cents">,
  payload: Record<string, unknown>,
  options: SubmitSandboxEvidenceOptions = {},
): Promise<SandboxGuardrailEvidenceResult> {
  return paybond.guardrails.submitSandboxEvidence({
    intentId: guardrail.intent_id,
    payload,
    artifacts: options.artifacts,
    operation: options.operation ?? guardrail.operation,
    requestedSpendCents: options.requestedSpendCents ?? guardrail.requested_spend_cents,
    metadata: options.metadata,
    idempotencyKey: options.idempotencyKey,
  });
}
`;
}

async function writeScaffold(out: string, body: string, force: boolean): Promise<void> {
  // @ts-expect-error Node builtins are available in the published CLI runtime.
  const fs = await import("node:fs/promises");
  try {
    await fs.stat(out);
    if (!force) {
      throw new Error(`${out} already exists; pass --force to overwrite`);
    }
  } catch (err) {
    if (!(err && typeof err === "object" && "code" in err && err.code === "ENOENT")) {
      if (!force) {
        throw err;
      }
    }
  }
  await fs.writeFile(out, body, "utf8");
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let parsed: { preset: Preset; framework: Framework; out: string; force: boolean };
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n\n${usage()}\n`);
    return 1;
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    return 0;
  }
  try {
    await writeScaffold(parsed.out, template(parsed.framework), parsed.force);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  process.stdout.write(`Created Paybond guardrail integration: ${parsed.out}\n`);
  return 0;
}

function normalizeFileURL(url: string): string {
  return url.startsWith("file:///var/") ? url.replace("file:///var/", "file:///private/var/") : url;
}

async function invokedFromCLI(): Promise<boolean> {
  const scriptPath = process.argv[1];
  if (!scriptPath) {
    return false;
  }
  // @ts-ignore Node builtins are available in the published CLI runtime.
  const fs = (await import("node:fs/promises")) as { realpath(path: string): Promise<string> };
  // @ts-ignore Node builtins are available in the published CLI runtime.
  const path = (await import("node:path")) as { resolve(...parts: string[]): string };
  // @ts-ignore Node builtins are available in the published CLI runtime.
  const url = (await import("node:url")) as {
    fileURLToPath(value: string): string;
    pathToFileURL(value: string): { href: string };
  };

  async function realFileURL(filePath: string): Promise<string> {
    let resolved = path.resolve(filePath);
    try {
      resolved = await fs.realpath(resolved);
    } catch {
      // If realpath fails, compare the absolute path. This keeps direct execution
      // working even when the script path disappears during process startup.
    }
    return normalizeFileURL(url.pathToFileURL(resolved).href);
  }

  return (await realFileURL(scriptPath)) === (await realFileURL(url.fileURLToPath(import.meta.url)));
}

invokedFromCLI().then((invoked) => {
  if (!invoked) {
    return;
  }
  main().then((code) => {
    process.exitCode = code;
  }, (err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}, (err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
