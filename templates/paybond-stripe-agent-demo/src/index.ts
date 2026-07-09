/**
 * Stripe commerce agent (generic TypeScript) — instrumented mock `payments.charge_customer`.
 * Uses `buildPaybondStripeMetadata` + `mapStripeToolResultToEvidence` from @paybond/kit.
 * No live LLM required for the sandbox smoke path.
 */
import { createPaybondClient } from "./paybond.config.js";
import {
  chargeCustomer,
  mapChargeEvidence,
  type PaybondSessionBinding,
} from "./charge-customer.js";

const PRIMARY_OPERATION = "payments.charge_customer";
const REQUESTED_SPEND_CENTS = 2500;

async function main(): Promise<void> {
  const paybond = await createPaybondClient();
  try {
    // tenant_id and paybond_intent_id are populated after sandbox bind — never from client input.
    // environment is server-derived (gateway principal); the Stripe test key is sandbox-only.
    const bindingRef: PaybondSessionBinding = {
      tenantId: "",
      intentId: "",
      environment: paybond.environment ?? "unknown",
    };

    const agent = await paybond.agent({
      policy: "./paybond.policy.yaml",
      framework: "generic",
      tools: {
        [PRIMARY_OPERATION]: async (args: { amountCents: number; customerId?: string }) =>
          chargeCustomer(bindingRef, args),
      },
      sandbox: true,
    });

    bindingRef.tenantId = agent.run.tenantId;
    bindingRef.intentId = agent.run.intentId;

    const tool = agent.tools.find((entry) => entry.name === PRIMARY_OPERATION);
    if (!tool) {
      throw new Error(`missing tool ${PRIMARY_OPERATION}`);
    }

    const result = await tool.execute({
      toolName: PRIMARY_OPERATION,
      toolCallId: "demo-1",
      arguments: { amountCents: REQUESTED_SPEND_CENTS },
    });

    const toolResult =
      typeof result.toolResult === "object" && result.toolResult !== null
        ? (result.toolResult as Record<string, unknown>)
        : {};

    const mappedEvidence = mapChargeEvidence(toolResult, "stripe_charge");

    console.log(
      JSON.stringify(
        {
          runId: agent.run.runId,
          intentId: agent.run.intentId,
          tenantId: agent.run.tenantId,
          authorization: result.authorization,
          evidence: result.evidence,
          mappedEvidence,
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
