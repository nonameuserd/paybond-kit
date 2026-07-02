/**
 * MCP coding-agent starter — configure stdio MCP for Claude Desktop, Codex, or generic hosts.
 *
 * This file documents local smoke; wire MCP with:
 *   paybond mcp install --host claude --tool-policy spend-write
 */
import { createPaybondClient } from "./paybond.config.js";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const agent = await paybond.agent({
      policy: "./paybond.policy.yaml",
      framework: "generic",
      tools: {
        "deploy.preview": async (args: { estimatedPriceCents: number }) => ({
          status: "completed",
          cost_cents: args.estimatedPriceCents,
        }),
        searchWeb: async (args: { query: string }) => ({
          hits: [{ title: args.query, url: "https://example.com" }],
        }),
      },
      sandbox: true,
    });

    const paid = agent.tools.find((entry) => entry.name === "deploy.preview")!;
    const result = await paid.execute({
      toolName: "deploy.preview",
      toolCallId: "mcp-demo-1",
      arguments: { estimatedPriceCents: 500 },
    });

    console.log(JSON.stringify({ runId: agent.run.runId, result }, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
