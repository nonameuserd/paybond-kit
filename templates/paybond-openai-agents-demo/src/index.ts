/**
 * SaaS provisioning agent (OpenAI Agents) — sandbox demo using bundled Kit helpers (no live LLM).
 */
import { createPaybondClient } from "./paybond.config.js";
import { runOpenAIAgentsSandboxDemo } from "@paybond/kit/openai-agents";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const demo = await runOpenAIAgentsSandboxDemo({
      paybond,
      operation: "saas.provision_seat",
      requestedSpendCents: 2900,
      evidencePreset: "cost_and_completion",
    });
    console.log(JSON.stringify(demo, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
