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
  | "openai-agents"
  | "claude"
  | "anthropic"
  | "gemini"
  | "google-ai"
  | "vercel-ai"
  | "langgraph"
  | "mcp";

const FRAMEWORKS = new Set<Framework>([
  "generic",
  "provider-agnostic",
  "openai-agents",
  "claude",
  "anthropic",
  "gemini",
  "google-ai",
  "vercel-ai",
  "langgraph",
  "mcp",
]);

const FRAMEWORK_NOTES: Record<Framework, string> = {
  generic: "Wrap the returned function around any side-effecting tool handler.",
  "provider-agnostic": "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
  "openai-agents": "Register the guarded handler where your OpenAI Agents tool handler is defined.",
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
    "Usage: paybond-init [--framework generic|provider-agnostic|openai-agents|claude|anthropic|gemini|google-ai|vercel-ai|langgraph|mcp] [--out paybond-spend-guard.ts] [--force]",
    "",
    "Scaffolds a Paybond spend guard wrapper for delegated agent spend controls.",
  ].join("\n");
}

function parseArgs(argv: string[]): { framework: Framework; out: string; force: boolean } {
  let framework: Framework = "generic";
  let out = "paybond-spend-guard.ts";
  let force = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      process.stdout.write(`${usage()}\n`);
      process.exitCode = 0;
      return { framework, out, force };
    }
    if (arg === "--force") {
      force = true;
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
  return { framework, out, force };
}

function template(framework: Framework): string {
  return `import { Paybond, PaybondCapabilityBinding, PaybondSpendGuard } from "@paybond/kit";

type ToolInput = {
  city: string;
  maxPriceCents: number;
};

async function bookHotel(input: ToolInput): Promise<{ confirmation: string }> {
  // Put the side-effecting tool call here.
  return { confirmation: \`demo-\${input.city}-\${input.maxPriceCents}\` };
}

export async function buildGuardedHotelTool(params: {
  intentId: string;
  capabilityToken: string;
}): Promise<(input: ToolInput) => Promise<{ confirmation: string }>> {
  const paybond = await Paybond.open({
    apiKey: process.env.PAYBOND_API_KEY!,
    expectedEnvironment: "sandbox",
  });
  const binding = new PaybondCapabilityBinding(
    paybond.harbor,
    params.intentId,
    params.capabilityToken,
  );
  const guard = new PaybondSpendGuard(binding);

  // ${FRAMEWORK_NOTES[framework]}
  return guard.guardTool(
    {
      operation: "travel.book_hotel",
      requestedSpendCents: 20_000,
    },
    bookHotel,
  );
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
  let parsed: { framework: Framework; out: string; force: boolean };
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n\n${usage()}\n`);
    return 1;
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    return 0;
  }
  await writeScaffold(parsed.out, template(parsed.framework), parsed.force);
  process.stdout.write(`Created ${parsed.out}\n`);
  return 0;
}

main().then((code) => {
  process.exitCode = code;
}, (err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
