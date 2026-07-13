#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { runCli } from "./cli/router.js";
import { getCompletionPreset, jsonLiteral } from "./completion-catalog.js";

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

type AgentMiddlewareFramework =
  | "generic"
  | "claude-agents"
  | "langgraph"
  | "vercel-ai"
  | "openai"
  | "mastra"
  | "cloudflare-agents"
  | "google-adk"
  | "mcp";

type Preset = "paid-tool-guard" | "agent-middleware";

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

const AGENT_MIDDLEWARE_FRAMEWORKS = new Set<AgentMiddlewareFramework>([
  "generic",
  "claude-agents",
  "openai",
  "langgraph",
  "vercel-ai",
  "mastra",
  "cloudflare-agents",
  "google-adk",
  "mcp",
]);

const AGENT_MIDDLEWARE_FRAMEWORK_ALIASES: Record<string, AgentMiddlewareFramework> = {
  "provider-agnostic": "generic",
};

const PRESETS = new Set<Preset>(["paid-tool-guard", "agent-middleware"]);

const PRESET_DEFAULT_OUT: Record<Preset, string> = {
  "paid-tool-guard": "paybond-paid-tool-guard.ts",
  "agent-middleware": "paybond-agent-middleware.ts",
};

/** Comment block for production intent create via policy_binding (signing v7). */
function productionPolicyBindingComments(harborTemplateId: string): string {
  return `// Production (signing v7): publish managed template head for ${harborTemplateId}, then create a funded intent.
// import { PaybondPolicy } from "@paybond/kit";
// const policy = await PaybondPolicy.load("./paybond.policy.yaml");
// const publishedHead = {
//   templateId: "<template_id>",
//   versionSeq: 1,
//   materializedPredicate: { /* from publish response */ },
//   policyContentDigestHex: "<digest_hex>",
// };
// const intentInput = policy.toIntentCreateInput({
//   principalDid,
//   principalSigningSeed: principalSeed32,
//   payeeDid,
//   payeeSigningSeed: payeeSeed32,
//   deadlineRfc3339,
//   settlementRail: "stripe_connect",
//   recognitionProof,
//   publishedPolicyHead: publishedHead,
// });
// const created = await paybond.intents.createWithPolicyBinding(intentInput);
// Fund if needed, then attach middleware: paybond.agentRun.bind({ attach: { intentId, capabilityToken, productionEvidence }, registry })`;
}

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
    "Usage: paybond-init [--preset paid-tool-guard|agent-middleware] [--framework <name>] [--out <path>] [--force]",
    "",
    "Presets:",
    "  paid-tool-guard     Per-tool guardTool helper (default)",
    "  agent-middleware    PaybondAgentRun + tool registry middleware",
    "",
    "Frameworks (paid-tool-guard): generic|provider-agnostic|openai|claude|anthropic|gemini|google-ai|vercel-ai|langgraph|mcp",
    "Frameworks (agent-middleware): generic|claude-agents|openai|langgraph|vercel-ai|mastra|cloudflare-agents|mcp",
  ].join("\n");
}

function normalizeAgentMiddlewareFramework(framework: Framework): AgentMiddlewareFramework {
  const alias = AGENT_MIDDLEWARE_FRAMEWORK_ALIASES[framework];
  if (alias) {
    return alias;
  }
  if (!AGENT_MIDDLEWARE_FRAMEWORKS.has(framework as AgentMiddlewareFramework)) {
    throw new Error("invalid --framework for agent-middleware preset");
  }
  return framework as AgentMiddlewareFramework;
}

function validateFrameworkForPreset(preset: Preset, framework: Framework): void {
  if (preset === "agent-middleware") {
    normalizeAgentMiddlewareFramework(framework);
    return;
  }
  if (!FRAMEWORKS.has(framework)) {
    throw new Error("invalid --framework");
  }
}

function parseArgs(argv: string[]): { preset: Preset; framework: Framework; out: string; force: boolean } {
  let preset: Preset = "paid-tool-guard";
  let framework: Framework = "provider-agnostic";
  let frameworkExplicit = false;
  let out = PRESET_DEFAULT_OUT["paid-tool-guard"];
  let outExplicit = false;
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
      if (!outExplicit) {
        out = PRESET_DEFAULT_OUT[preset];
      }
      continue;
    }
    if (arg === "--framework") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw) {
        throw new Error("invalid --framework");
      }
      framework = raw as Framework;
      frameworkExplicit = true;
      continue;
    }
    if (arg === "--out") {
      const raw = argv[i + 1];
      i += 1;
      if (!raw || raw.startsWith("-")) {
        throw new Error("invalid --out");
      }
      out = raw;
      outExplicit = true;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  if (preset === "agent-middleware" && !frameworkExplicit) {
    framework = "generic";
  }
  validateFrameworkForPreset(preset, framework);
  return { preset, framework, out, force };
}

function envHelpersBlock(): string {
  return `declare const process: {
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

async function readTextFile(envFile: string): Promise<string | undefined> {
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

export type OpenPaybondFromEnvOptions = {
  /**
   * Load PAYBOND_API_KEY from this local env file when the process environment
   * does not already provide it. Pass false when your agent host injects secrets.
   */
  envFile?: string | false;
};

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
}`;
}

function agentMiddlewareHeaderComments(framework: AgentMiddlewareFramework): string {
  const smokeCommands: Record<AgentMiddlewareFramework, string> = {
    generic:
      'paybond agent sandbox smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --result-body \'{"reservation":{"status":"confirmed","price_cents":20000}}\'',
    "claude-agents":
      "paybond agent demo claude-agents smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    openai:
      "paybond agent demo openai smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    langgraph:
      "paybond agent demo langgraph smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    "vercel-ai":
      "paybond agent demo vercel-ai smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    mastra:
      "paybond agent demo mastra smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    "cloudflare-agents":
      "paybond agent demo cloudflare-agents smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
    "google-adk":
      "paybond agent demo google-adk smoke --operation paid-tool --requested-spend-cents 100 --evidence-preset cost_and_completion --format json",
    mcp:
      "paybond agent demo mcp smoke --operation travel.book_hotel --requested-spend-cents 20000 --evidence-preset cost_and_completion --format json",
  };
  return [
    "// Paybond for paid tools; provider-native limits for LLM token caps only.",
    "// Policy: ./paybond.policy.yaml (scaffold with paybond policy init).",
    `// Smoke: ${smokeCommands[framework]}`,
    "// Production: createWithPolicyBinding after publishing the managed template head — see block below.",
  ].join("\n");
}

function agentMiddlewareFrameworkBlock(framework: AgentMiddlewareFramework): string {
  switch (framework) {
    case "claude-agents":
      return `import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import {
  createGuardedAgent,
  createGuardedAgentRunner,
  type CreateGuardedAgentResult,
} from "@paybond/kit/agent";

const TRAVEL_AGENT_POLICY = {
  version: 1,
  name: "travel-agent-v1",
  default_deny: true,
  tools: {
    "travel.book_hotel": {
      side_effecting: true,
      max_spend_cents: DEFAULT_REQUESTED_SPEND_CENTS,
      evidence_preset: COMPLETION_PRESET_ID,
    },
    "search.web": {
      side_effecting: false,
    },
  },
  intent: {
    allowed_tools: ["travel.book_hotel"],
    budget: { currency: "usd", max_spend_usd: 200 },
  },
} as const;

/** Policy-driven Claude Agent SDK wiring: bind run, wrap \`tool()\` handlers, expose MCP server config. */
export async function createClaudeAgentsGuardedRunner(
  paybond: Paybond,
): Promise<CreateGuardedAgentResult> {
  const sdkTools = [
    tool(
      "travel.book_hotel",
      "Book a hotel room",
      { city: z.string(), estimatedPriceCents: z.number().int().nonnegative() },
      async (args) => ({
        content: [{ type: "text" as const, text: JSON.stringify(await bookHotel(args)) }],
        structuredContent: await bookHotel(args),
      }),
    ),
  ];
  return createGuardedAgent(paybond, {
    policy: TRAVEL_AGENT_POLICY,
    framework: "claude-agents",
    tools: sdkTools,
    bootstrap: {
      operation: DEFAULT_OPERATION,
      requestedSpendCents: DEFAULT_REQUESTED_SPEND_CENTS,
      completionPreset: COMPLETION_PRESET_ID,
    },
  });
}

/** Alias matching {@link createGuardedAgentRunner} naming. */
export const createClaudeAgentsGuardedAgentRunner = createClaudeAgentsGuardedRunner;

export { createGuardedAgentRunner };`;
    case "openai":
      return `import { createOpenAIAgentsAdapter } from "@paybond/kit/openai-agents";
import type { FunctionTool } from "@openai/agents";

/** Wrap OpenAI Agents SDK function tools with Paybond middleware (verify → execute → auto-evidence). */
export function wrapOpenAIAgentTools<TContext>(
  run: PaybondAgentRun,
  tools: Array<FunctionTool<TContext>>,
): Array<FunctionTool<TContext>> {
  return createOpenAIAgentsAdapter(run).guardFunctionTools(tools);
}`;
    case "langgraph":
      return `import { paybondAwrapToolCall, paybondToolNode } from "@paybond/kit/langgraph";
import type { PaybondAgentRun } from "@paybond/kit/agent";

/** LangGraph ToolNode hook — use with \`paybondToolNode(tools, run)\` or \`new ToolNode(tools, { awrapToolCall })\` when supported. */
export function createLangGraphToolCallWrapper(run: PaybondAgentRun) {
  return paybondAwrapToolCall(run);
}

/** Convenience factory around LangGraph \`ToolNode\` with Paybond interceptor wiring. */
export function createPaybondLangGraphToolNode(
  run: PaybondAgentRun,
  tools: Parameters<typeof paybondToolNode>[0],
) {
  return paybondToolNode(tools, run);
}`;
    case "vercel-ai":
      return `import { generateText, tool } from "ai";
import { z } from "zod";
import {
  paybondVercelToolApproval,
  paybondVercelWrapTools,
} from "@paybond/kit/vercel-ai";

export function createGuardedVercelTools(run: PaybondAgentRun) {
  const tools = {
    bookHotel: tool({
      description: "Book a hotel room",
      inputSchema: z.object({
        city: z.string(),
        estimatedPriceCents: z.number().int().nonnegative(),
      }),
      execute: async (args) => bookHotel(args),
    }),
    searchWeb: tool({
      description: "Search the web",
      inputSchema: z.object({ query: z.string() }),
      execute: async (args) => searchWeb(args),
    }),
  };
  return paybondVercelWrapTools(run, tools);
}

/** Example \`generateText\` wiring with Paybond \`toolApproval\` + wrapped tools. */
export async function runGuardedGenerateText(
  run: PaybondAgentRun,
  model: Parameters<typeof generateText>[0]["model"],
  prompt: string,
) {
  const tools = createGuardedVercelTools(run);
  return generateText({
    model,
    tools,
    toolApproval: paybondVercelToolApproval(run),
    prompt,
  });
}`;
    case "mastra":
      return `import { createTool } from "@mastra/core/tools";
import { z } from "zod";
import { createPaybondMastraConfig } from "@paybond/kit/mastra";
import type { PaybondAgentRun } from "@paybond/kit/agent";

/** Wrap Mastra \`createTool()\` definitions with Paybond middleware on \`execute\`. */
export function createGuardedMastraTools(run: PaybondAgentRun) {
  const tools = [
    createTool({
      id: "travel.book_hotel",
      description: "Book a hotel room",
      inputSchema: z.object({
        city: z.string(),
        estimatedPriceCents: z.number().int().nonnegative(),
      }),
      execute: async (args) => bookHotel(args),
    }),
    createTool({
      id: "search.web",
      description: "Search the web",
      inputSchema: z.object({ query: z.string() }),
      execute: async (args) => searchWeb(args),
    }),
  ];
  return createPaybondMastraConfig(run, tools).tools;
}`;
    case "google-adk":
      return `import { FunctionTool } from "@google/adk";
import { z } from "zod";
import { createPaybondGoogleAdkConfig } from "@paybond/kit/google-adk";
import type { PaybondAgentRun } from "@paybond/kit/agent";

/** Wrap Google ADK FunctionTool definitions with Paybond middleware on \`execute\`. */
export function createGuardedGoogleAdkTools(run: PaybondAgentRun) {
  const tools = [
    new FunctionTool({
      name: "travel.book_hotel",
      description: "Book a hotel room",
      parameters: z.object({
        city: z.string(),
        estimatedPriceCents: z.number().int().nonnegative(),
      }),
      execute: async (args) => bookHotel(args),
    }),
    new FunctionTool({
      name: "search.web",
      description: "Search the web",
      parameters: z.object({ query: z.string() }),
      execute: async (args) => searchWeb(args),
    }),
  ];
  return createPaybondGoogleAdkConfig(run, tools).tools;
}`;
    case "cloudflare-agents":
      return `import { tool } from "ai";
import { z } from "zod";
import { createPaybondCloudflareAgentsConfig } from "@paybond/kit/cloudflare-agents";
import type { PaybondAgentRun } from "@paybond/kit/agent";

/** Wrap Cloudflare Agents \`getTools()\` AI SDK tool definitions with Paybond middleware on \`execute\`. */
export function createGuardedCloudflareAgentTools(run: PaybondAgentRun) {
  const tools = {
    "travel.book_hotel": tool({
      description: "Book a hotel room",
      inputSchema: z.object({
        city: z.string(),
        estimatedPriceCents: z.number().int().nonnegative(),
      }),
      execute: async (args) => bookHotel(args),
    }),
    searchWeb: tool({
      description: "Search the web",
      inputSchema: z.object({ query: z.string() }),
      execute: async (args) => searchWeb(args),
    }),
  };
  return createPaybondCloudflareAgentsConfig(run, tools);
}`;
    case "mcp":
      return `import { createPaybondMcpToolSurface } from "@paybond/kit/mcp";
import type { PaybondAgentRun } from "@paybond/kit/agent";

/** Stdio MCP host config — bind a run first, then \`paybond mcp install\` for coding-agent hosts. */
export function createMcpToolSurface(run: PaybondAgentRun) {
  return createPaybondMcpToolSurface(run, { envFile: ".env.local" });
}`;
    default:
      return `import { createPaybondGenericAgentConfig } from "@paybond/kit/agent";

/** Recommended default when the agent framework is unknown. */
export function createGenericAgentConfig(
  run: PaybondAgentRun,
  tools: Array<{ name: string; execute: (args: unknown) => unknown | Promise<unknown> }>,
) {
  return createPaybondGenericAgentConfig(run, tools);
}

/** Wrap \`{ name, execute }\` tools for any agent-agnostic runtime. */
export function wrapAgentTools(
  run: PaybondAgentRun,
  tools: Array<{ name: string; execute: (args: unknown) => unknown | Promise<unknown> }>,
) {
  return createGenericAgentConfig(run, tools).tools;
}`;
  }
}

function agentMiddlewareTemplate(framework: AgentMiddlewareFramework): string {
  const completionPreset = getCompletionPreset("cost_and_completion");
  const evidenceSchema = jsonLiteral(completionPreset.evidence_schema, 2);
  return `import fs from "node:fs/promises";
import { Paybond } from "@paybond/kit";
import {
  createPaybondToolRegistry,
  type PaybondAgentRun,
  type PaybondAgentRunBindInput,
} from "@paybond/kit/agent";

${envHelpersBlock()}

${agentMiddlewareHeaderComments(framework)}

// Agent middleware preset maps to completion catalog archetype: cost_and_completion (${completionPreset.harbor_template_id}).
const COMPLETION_PRESET_ID = "cost_and_completion";
const DEFAULT_OPERATION = "travel.book_hotel";
const DEFAULT_REQUESTED_SPEND_CENTS = 20_000;

export type BookHotelArgs = {
  city: string;
  estimatedPriceCents: number;
};

export async function bookHotel(args: BookHotelArgs) {
  return {
    reservation: {
      status: "confirmed" as const,
      price_cents: args.estimatedPriceCents,
      city: args.city,
    },
  };
}

export async function searchWeb(args: { query: string }) {
  return { hits: [{ title: args.query, url: "https://example.com" }] };
}

export function createAgentToolRegistry() {
  return createPaybondToolRegistry({
    sideEffecting: {
      "travel.book_hotel": {
        spendCents: (args: BookHotelArgs) => args.estimatedPriceCents,
        evidencePreset: COMPLETION_PRESET_ID,
        evidenceMapper: (result: Awaited<ReturnType<typeof bookHotel>>) => ({
          status: result.reservation.status === "confirmed" ? "completed" : result.reservation.status,
          cost_cents: result.reservation.price_cents,
        }),
      },
    },
    defaultDeny: true,
  });
}

export type BindAgentRunOptions = {
  operation?: string;
  requestedSpendCents?: number;
  evidenceSchema?: Record<string, unknown>;
  runId?: string;
};

export async function bindAgentRun(
  paybond: Paybond,
  registry: ReturnType<typeof createAgentToolRegistry>,
  options: BindAgentRunOptions = {},
): Promise<PaybondAgentRun> {
  const bindInput: PaybondAgentRunBindInput = {
    bootstrap: {
      kind: "sandbox",
      operation: options.operation ?? DEFAULT_OPERATION,
      requestedSpendCents: options.requestedSpendCents ?? DEFAULT_REQUESTED_SPEND_CENTS,
      completionPreset: COMPLETION_PRESET_ID,
      evidenceSchema: options.evidenceSchema ?? ${evidenceSchema},
    },
    registry,
    runId: options.runId,
  };
  return paybond.agentRun.bind(bindInput);
}

${productionPolicyBindingComments(completionPreset.harbor_template_id)}

${agentMiddlewareFrameworkBlock(framework)}
`;
}

function paidToolGuardTemplate(framework: Framework): string {
  const completionPreset = getCompletionPreset("cost_and_completion");
  const evidenceSchema = jsonLiteral(completionPreset.evidence_schema, 2);
  return `import fs from "node:fs/promises";
import {
  Paybond,
  type SandboxGuardrailBootstrapResult,
  type SandboxGuardrailEvidenceResult,
} from "@paybond/kit";

${envHelpersBlock()}

// Paid-tool guardrail preset maps to completion catalog archetype: cost_and_completion (${completionPreset.harbor_template_id}).
const COMPLETION_PRESET_ID = "cost_and_completion";
const HARBOR_TEMPLATE_ID = "${completionPreset.harbor_template_id}";

export type CompletionEvidence = {
  status: string;
  cost_cents: number;
};

export function buildCompletionEvidence(fields: CompletionEvidence): Record<string, unknown> {
  return { ...fields };
}

export const policyBindingStub = {
  template_id: HARBOR_TEMPLATE_ID,
  parameters: ${jsonLiteral(completionPreset.parameters, 2)} as const,
  // version_seq and head_digest are assigned after publishing the managed template head.
};

${productionPolicyBindingComments(completionPreset.harbor_template_id)}

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

export async function bootstrapSandboxGuardrailIntent(
  paybond: Paybond,
  options: SandboxGuardrailIntentOptions = {},
): Promise<SandboxGuardrailBootstrapResult> {
  return paybond.guardrails.bootstrapSandbox({
    operation: options.operation ?? DEFAULT_OPERATION,
    requestedSpendCents: options.requestedSpendCents ?? DEFAULT_REQUESTED_SPEND_CENTS,
    currency: options.currency ?? "usd",
    evidenceSchema: options.evidenceSchema ?? ${evidenceSchema},
    completionPreset: COMPLETION_PRESET_ID,
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

// Prefer buildCompletionEvidence({ status: "completed", cost_cents }) for catalog-aligned evidence.
`;
}

function scaffoldBody(preset: Preset, framework: Framework): string {
  if (preset === "agent-middleware") {
    return agentMiddlewareTemplate(normalizeAgentMiddlewareFramework(framework));
  }
  return paidToolGuardTemplate(framework);
}

function scaffoldLabel(preset: Preset): string {
  return preset === "agent-middleware" ? "agent middleware integration" : "guardrail integration";
}

async function writeScaffold(out: string, body: string, force: boolean): Promise<void> {
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
    await writeScaffold(parsed.out, scaffoldBody(parsed.preset, parsed.framework), parsed.force);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
  process.stdout.write(`Created Paybond ${scaffoldLabel(parsed.preset)}: ${parsed.out}\n`);
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

  async function realFileURL(filePath: string): Promise<string> {
    let resolved = path.resolve(filePath);
    try {
      resolved = await fs.realpath(resolved);
    } catch {
      // If realpath fails, compare the absolute path. This keeps direct execution
      // working even when the script path disappears during process startup.
    }
    return normalizeFileURL(pathToFileURL(resolved).href);
  }

  return (await realFileURL(scriptPath)) === (await realFileURL(fileURLToPath(import.meta.url)));
}

invokedFromCLI().then((invoked) => {
  if (!invoked) {
    return;
  }
  const argv = process.argv.slice(2);
  const hasTemplateInit = argv.some((arg, index) => {
    if (arg === "--template" || arg === "--repo") {
      return Boolean(argv[index + 1]);
    }
    return false;
  });
  const initPath = hasTemplateInit ? ["init", ...argv] : ["init", "guardrail", ...argv];
  runCli(initPath).then((code) => {
    process.exitCode = code;
  }, (err) => {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  });
}, (err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
