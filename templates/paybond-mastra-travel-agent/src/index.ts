/**
 * Travel booking agent (Mastra) — sandbox demo using bundled Kit helpers (no live LLM).
 */
import { createPaybondClient } from "./paybond.config.js";
import { runMastraSandboxDemo } from "@paybond/kit/mastra";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const demo = await runMastraSandboxDemo({
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
