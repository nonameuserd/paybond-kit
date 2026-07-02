/**
 * Travel booking agent (LangGraph) — sandbox demo using bundled Kit helpers (no live LLM).
 */
import { createPaybondClient } from "./paybond.config.js";
import { runLangGraphSandboxDemo } from "@paybond/kit/langgraph";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const demo = await runLangGraphSandboxDemo({
      paybond,
      operation: "travel.book_hotel",
      requestedSpendCents: 18700,
      evidencePreset: "cost_and_completion",
    });
    console.log(JSON.stringify(demo, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
