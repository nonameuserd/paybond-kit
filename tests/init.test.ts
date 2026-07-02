import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { main } from "../src/init.js";

describe("paybond-init", () => {
  const originalExitCode = process.exitCode;

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = originalExitCode;
  });

  it("scaffolds a provider-agnostic guardrail integration", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-paid-tool-guard.ts");
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(
      main(["--preset", "paid-tool-guard", "--framework", "provider-agnostic", "--out", out]),
    ).resolves.toBe(0);

    expect(stdout).toHaveBeenCalledWith(`Created Paybond guardrail integration: ${out}\n`);
    const body = await readFile(out, "utf8");
    for (const fragment of [
      "Paid-tool guardrail preset maps to completion catalog archetype",
      "loadPaybondEnvFile",
      "openPaybondFromEnv",
      "process.env.PAYBOND_GATEWAY_URL ?? process.env.PAYBOND_GATEWAY_BASE_URL",
      "bootstrapSandboxGuardrailIntent",
      "wrapPaidTool",
      "submitSandboxEvidence",
      "buildCompletionEvidence",
      "cost_and_completion",
      "completion_budget_v1",
      "status",
      "cost_cents",
      "paybond.guardrails.bootstrapSandbox",
      "paybond.spendGuard(guardrail.intent_id, guardrail.capability_token)",
      "paybond.guardrails.submitSandboxEvidence",
      "Use the guarded handler with OpenAI, Gemini, Claude/Anthropic, local models, or any custom runtime.",
    ]) {
      expect(body).toContain(fragment);
    }
    for (const fragment of [
      "replaceableSmokeTestPaidTool",
      "runSandboxSmokePath",
      "SmokePaidToolInput",
      "SmokePaidToolResult",
      "sandbox-confirmation",
    ]) {
      expect(body).not.toContain(fragment);
    }
  });

  it("refuses to overwrite without --force", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-paid-tool-guard.ts");
    await writeFile(out, "existing", "utf8");

    await expect(main(["--out", out])).resolves.toBe(1);
    expect(await readFile(out, "utf8")).toBe("existing");
  });

  it("overwrites with --force and applies framework notes", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-paid-tool-guard.ts");
    await writeFile(out, "existing", "utf8");

    await expect(main(["--framework", "mcp", "--out", out, "--force"])).resolves.toBe(0);
    expect(await readFile(out, "utf8")).toContain(
      "Call the guarded handler inside the MCP tool implementation before paid or external work runs.",
    );
  });

  it("scaffolds agent-middleware with PaybondAgentRun and registry", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware.ts");
    const stdout = vi.spyOn(process.stdout, "write").mockImplementation(() => true);

    await expect(main(["--preset", "agent-middleware", "--out", out])).resolves.toBe(0);

    expect(stdout).toHaveBeenCalledWith(`Created Paybond agent middleware integration: ${out}\n`);
    const body = await readFile(out, "utf8");
    for (const fragment of [
      "Agent middleware preset maps to completion catalog archetype",
      "createPaybondToolRegistry",
      "createAgentToolRegistry",
      "bindAgentRun",
      "paybond.agentRun.bind",
      "defaultDeny: true",
      "createPaybondGenericAgentConfig",
      "createGenericAgentConfig",
      "wrapAgentTools",
      "travel.book_hotel",
      "cost_and_completion",
    ]) {
      expect(body).toContain(fragment);
    }
    expect(body).not.toContain("wrapPaidTool");
  });

  it("accepts provider-agnostic alias for generic agent-middleware scaffold", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware-alias.ts");

    await expect(
      main(["--preset", "agent-middleware", "--framework", "provider-agnostic", "--out", out]),
    ).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    expect(body).toContain("createPaybondGenericAgentConfig");
  });

  it("scaffolds agent-middleware claude-agents with createGuardedAgent runner", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-claude-agents.ts");

    await expect(
      main(["--preset", "agent-middleware", "--framework", "claude-agents", "--out", out]),
    ).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    expect(body).toContain("@anthropic-ai/claude-agent-sdk");
    expect(body).toContain("createGuardedAgent");
    expect(body).toContain("createClaudeAgentsGuardedRunner");
    expect(body).toContain("createGuardedAgentRunner");
    expect(body).toContain('framework: "claude-agents"');
  });

  it("scaffolds agent-middleware openai framework with real adapter imports", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware-openai.ts");

    await expect(main(["--preset", "agent-middleware", "--framework", "openai", "--out", out])).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    expect(body).toContain('from "@paybond/kit/openai-agents"');
    expect(body).toContain("createOpenAIAgentsAdapter");
    expect(body).toContain("guardFunctionTools");
  });

  it("scaffolds agent-middleware vercel-ai framework with real wiring", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware-vercel.ts");

    await expect(main(["--preset", "agent-middleware", "--framework", "vercel-ai", "--out", out])).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    expect(body).toContain('import { generateText, tool } from "ai"');
    expect(body).toContain('from "@paybond/kit/vercel-ai"');
    expect(body).toContain("paybondVercelToolApproval");
    expect(body).toContain("paybondVercelWrapTools");
    expect(body).toContain("createGuardedVercelTools");
  });

  it("scaffolds agent-middleware langgraph framework with interceptor wrapper", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware-langgraph.ts");

    await expect(main(["--preset", "agent-middleware", "--framework", "langgraph", "--out", out])).resolves.toBe(0);

    const body = await readFile(out, "utf8");
    expect(body).toContain("createLangGraphToolCallWrapper");
    expect(body).toContain("paybondAwrapToolCall");
    expect(body).toContain("@paybond/kit/langgraph");
    expect(body).toContain("paybondToolNode");
  });

  it("rejects invalid framework for agent-middleware preset", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-init-"));
    const out = join(cwd, "paybond-agent-middleware.ts");

    await expect(
      main(["--preset", "agent-middleware", "--framework", "mcp", "--out", out]),
    ).resolves.toBe(1);
  });
});
