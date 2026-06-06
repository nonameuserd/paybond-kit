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
    "Usage: paybond-init [--preset paid-tool-guard] [--framework generic|provider-agnostic|openai|claude|anthropic|gemini|google-ai|vercel-ai|langgraph|mcp] [--out paybond-guardrail-demo.ts] [--force]",
    "",
    "Scaffolds a production-shaped Paybond guardrail integration with a sandbox smoke path.",
  ].join("\n");
}

function parseArgs(argv: string[]): { preset: Preset; framework: Framework; out: string; force: boolean } {
  let preset: Preset = "paid-tool-guard";
  let framework: Framework = "provider-agnostic";
  let out = "paybond-guardrail-demo.ts";
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

const DEFAULT_OPERATION = "paid_tool.smoke_test";
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

export type SmokePaidToolInput = {
  itemId: string;
  maxPriceCents: number;
};

export type SmokePaidToolResult = {
  confirmationId: string;
  itemId: string;
  chargedCents: number;
  sandbox: true;
};

export async function openPaybondFromEnv(): Promise<Paybond> {
  const apiKey = process.env.PAYBOND_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("PAYBOND_API_KEY is required");
  }

  return Paybond.open({
    apiKey,
    gatewayBaseUrl: process.env.PAYBOND_GATEWAY_BASE_URL,
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

export async function replaceableSmokeTestPaidTool(
  input: SmokePaidToolInput,
): Promise<SmokePaidToolResult> {
  // Replace this sandbox smoke-test function with the real paid side-effecting tool.
  return {
    confirmationId: "sandbox-confirmation-" + input.itemId,
    itemId: input.itemId,
    chargedCents: Math.min(input.maxPriceCents, DEFAULT_REQUESTED_SPEND_CENTS),
    sandbox: true,
  };
}

export async function runSandboxSmokePath(): Promise<{
  guardrail: SandboxGuardrailBootstrapResult;
  toolResult: SmokePaidToolResult;
  evidence: SandboxGuardrailEvidenceResult;
}> {
  const paybond = await openPaybondFromEnv();
  const guardrail = await bootstrapSandboxGuardrailIntent(paybond);
  const guardedTool = wrapPaidTool(paybond, guardrail, replaceableSmokeTestPaidTool);
  const toolResult = await guardedTool({
    itemId: "replace-with-your-tool-input",
    maxPriceCents: DEFAULT_REQUESTED_SPEND_CENTS,
  });
  const evidence = await submitSandboxEvidence(paybond, guardrail, {
    confirmation_id: toolResult.confirmationId,
    charged_cents: toolResult.chargedCents,
    item_id: toolResult.itemId,
    sandbox: toolResult.sandbox,
  });
  return { guardrail, toolResult, evidence };
}

async function main(): Promise<void> {
  const result = await runSandboxSmokePath();
  console.log(JSON.stringify(result, null, 2));
}

function normalizeFileURL(url: string): string {
  return url.startsWith("file:///var/") ? url.replace("file:///var/", "file:///private/var/") : url;
}

const invokedPath = process.argv[1] ? normalizeFileURL(new URL("file://" + process.argv[1]).href) : "";
if (invokedPath && normalizeFileURL(import.meta.url) === invokedPath) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
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

function invokedFromCLI(): boolean {
  const invokedPath = process.argv[1] ? normalizeFileURL(new URL("file://" + process.argv[1]).href) : "";
  return Boolean(invokedPath && normalizeFileURL(import.meta.url) === invokedPath);
}

if (invokedFromCLI()) {
  main().then((code) => {
    process.exitCode = code;
  }, (err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}
