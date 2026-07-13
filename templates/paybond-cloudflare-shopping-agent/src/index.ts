/**
 * Shopping checkout agent (Cloudflare Agents) — sandbox demo using bundled Kit helpers (no live LLM).
 */
import { createPaybondClient } from "./paybond.config.js";
import { runCloudflareAgentsSandboxDemo } from "@paybond/kit/cloudflare-agents";

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    const demo = await runCloudflareAgentsSandboxDemo({
      paybond,
      operation: "commerce.checkout",
      requestedSpendCents: 4500,
      evidencePreset: "cost_and_completion",
    });
    console.log(JSON.stringify(demo, null, 2));
  } finally {
    await paybond.aclose();
  }
}

void main();
