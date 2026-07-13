import { CliError } from "../types.js";

function missingPeerDependencyError(
  packageName: string,
  integration: string,
): CliError {
  return new CliError(
    `${integration} demo requires the optional peer dependency "${packageName}"; install it with: npm install ${packageName}`,
    {
      category: "validation",
      code: "cli.agent.missing_peer_dependency",
      exitCode: 1,
      details: { package: packageName, integration },
    },
  );
}

function isMissingModuleError(err: unknown, packageName: string): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  const code = "code" in err ? String(err.code) : "";
  return (
    code === "ERR_MODULE_NOT_FOUND" &&
    err.message.includes(`'${packageName}'`)
  );
}

export async function loadRunVercelAiSandboxDemo() {
  try {
    const mod = await import("../../vercel-ai/sandbox-demo.js");
    return mod.runVercelAiSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "ai")) {
      throw missingPeerDependencyError("ai", "vercel-ai");
    }
    throw err;
  }
}

export async function loadRunLangGraphSandboxDemo() {
  try {
    const mod = await import("../../langgraph/sandbox-demo.js");
    return mod.runLangGraphSandboxDemo;
  } catch (err) {
    if (
      isMissingModuleError(err, "@langchain/core") ||
      isMissingModuleError(err, "@langchain/langgraph")
    ) {
      throw missingPeerDependencyError(
        "@langchain/core @langchain/langgraph",
        "langgraph",
      );
    }
    throw err;
  }
}

export async function loadRunClaudeAgentsSandboxDemo() {
  try {
    const mod = await import("../../claude-agents/sandbox-demo.js");
    return mod.runClaudeAgentsSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "@anthropic-ai/claude-agent-sdk")) {
      throw missingPeerDependencyError(
        "@anthropic-ai/claude-agent-sdk",
        "claude-agents",
      );
    }
    throw err;
  }
}

export async function loadRunOpenAIAgentsSandboxDemo() {
  try {
    const mod = await import("../../openai-agents/sandbox-demo.js");
    return mod.runOpenAIAgentsSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "@openai/agents")) {
      throw missingPeerDependencyError("@openai/agents", "openai-agents");
    }
    throw err;
  }
}

export async function loadRunGoogleAdkSandboxDemo() {
  try {
    const mod = await import("../../google-adk/sandbox-demo.js");
    return mod.runGoogleAdkSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "@google/adk")) {
      throw missingPeerDependencyError("@google/adk", "google-adk");
    }
    throw err;
  }
}

export async function loadRunMastraSandboxDemo() {
  try {
    const mod = await import("../../mastra/sandbox-demo.js");
    return mod.runMastraSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "@mastra/core")) {
      throw missingPeerDependencyError("@mastra/core", "mastra");
    }
    throw err;
  }
}

export async function loadRunCloudflareAgentsSandboxDemo() {
  try {
    const mod = await import("../../cloudflare-agents/sandbox-demo.js");
    return mod.runCloudflareAgentsSandboxDemo;
  } catch (err) {
    if (isMissingModuleError(err, "ai")) {
      throw missingPeerDependencyError("ai", "cloudflare-agents");
    }
    throw err;
  }
}
