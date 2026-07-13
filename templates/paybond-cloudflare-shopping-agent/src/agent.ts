/**
 * Cloudflare Agent scaffold — guarded getTools() for Workers / Durable Objects.
 *
 * Wire this class into your Worker entrypoint (see Cloudflare Agents docs).
 * Model calls stay on your provider; Paybond guards paid tool execute only.
 */
import { tool } from "ai";
import { z } from "zod";
import type { Paybond } from "@paybond/kit";
import { createPaybondCloudflareAgentsConfig } from "@paybond/kit/cloudflare-agents";
import type { PaybondAgentRun } from "@paybond/kit/agent";

type ShoppingAgentEnv = {
  PAYBOND_API_KEY: string;
  GEMINI_API_KEY?: string;
};

export type ShoppingAgentSession = {
  run: PaybondAgentRun;
  toolApproval: ReturnType<typeof createPaybondCloudflareAgentsConfig>["toolApproval"];
  tools: ReturnType<typeof createPaybondCloudflareAgentsConfig>["tools"];
};

/** Bind Paybond once per agent session, then reuse guarded tools across turns. */
export async function createShoppingAgentSession(
  paybond: Paybond,
  options?: { intentId?: string; capabilityToken?: string; sandbox?: boolean },
): Promise<ShoppingAgentSession> {
  // sandbox:true or an explicit attach context both return a bound runtime
  // (PaybondInstrumentRuntime). Deferred PaybondInstrumented.bind(context) is
  // only for lazy per-request attach — not used by this scaffold.
  const runtime = await paybond.instrument({
    policy: "./paybond.policy.yaml",
    framework: "cloudflare-agents",
    tools: {
      "commerce.checkout": tool({
        description: "Complete a shopping checkout",
        inputSchema: z.object({
          estimatedPriceCents: z.number().int().nonnegative(),
        }),
        execute: async (args) => checkout(args),
      }),
      "search.products": tool({
        description: "Search product catalog (read-only)",
        inputSchema: z.object({ query: z.string() }),
        execute: async (args) => searchProducts(args),
      }),
    },
    ...(options?.sandbox === false && options.intentId && options.capabilityToken
      ? {
          sandbox: false,
          context: {
            intentId: options.intentId,
            capabilityToken: options.capabilityToken,
          },
        }
      : { sandbox: true }),
  });

  if (!("run" in runtime)) {
    throw new Error(
      "expected a bound Paybond instrument runtime; pass sandbox: true or context with intentId/capabilityToken",
    );
  }

  return {
    run: runtime.run,
    tools: runtime.tools,
    toolApproval: runtime.hooks.toolApproval!,
  };
}

/**
 * Example Agent class shape for Cloudflare Agents SDK hosts.
 * Return `session.tools` from `getTools()` and pass `session.toolApproval` to AI SDK turns.
 */
export class ShoppingCheckoutAgent {
  constructor(
    private readonly env: ShoppingAgentEnv,
    private session: ShoppingAgentSession | null = null,
  ) {}

  async initSession(paybond: Paybond): Promise<ShoppingAgentSession> {
    this.session = await createShoppingAgentSession(paybond, { sandbox: true });
    return this.session;
  }

  getTools() {
    if (!this.session) {
      throw new Error("call initSession() before getTools()");
    }
    return this.session.tools;
  }

  get toolApproval() {
    if (!this.session) {
      throw new Error("call initSession() before toolApproval");
    }
    return this.session.toolApproval;
  }
}

async function checkout(args: { estimatedPriceCents: number }) {
  return { status: "completed", cost_cents: args.estimatedPriceCents };
}

async function searchProducts(args: { query: string }) {
  return { query: args.query, items: [] };
}
