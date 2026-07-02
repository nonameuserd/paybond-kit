/**
 * Generic Paybond agent — uses paybond.agent() with local paybond.policy.yaml.
 * No live LLM required for the sandbox smoke path.
 */
import { createPaybondClient } from "./paybond.config.js";

const PRIMARY_OPERATION = "procurement.submit_po";
const REQUESTED_SPEND_CENTS = 12000;

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const agent = await paybond.agent({
      policy: "./paybond.policy.yaml",
      framework: "generic",
      tools: {
        [PRIMARY_OPERATION]: async (args: { estimatedPriceCents: number }) => ({
          status: "completed",
          cost_cents: args.estimatedPriceCents,
        }),
      },
      sandbox: true,
    });

    const tool = agent.tools.find((entry) => entry.name === PRIMARY_OPERATION);
    if (!tool) {
      throw new Error(`missing tool ${PRIMARY_OPERATION}`);
    }

    const result = await tool.execute({
      toolName: PRIMARY_OPERATION,
      toolCallId: "demo-1",
      arguments: { estimatedPriceCents: REQUESTED_SPEND_CENTS },
    });

    console.log(
      JSON.stringify(
        {
          runId: agent.run.runId,
          intentId: agent.run.intentId,
          authorization: result.authorization,
          evidence: result.evidence,
          toolResult: result.toolResult,
        },
        null,
        2,
      ),
    );
  } finally {
    await paybond.aclose();
  }
}

void main();
