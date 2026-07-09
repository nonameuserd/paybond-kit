import type { Paybond } from "../index.js";
import type { PaybondPolicyLoadSource } from "../policy/load.js";
import type { PaybondInstrumentInput } from "../agent/instrument.js";
import { createCheckoutWithBinding } from "./checkout.js";
import type {
  ShopifyCheckoutExecuteInput,
  ShopifyCheckoutToolArgs,
  ShopifyCheckoutToolResult,
} from "./types.js";
import { PAYBOND_UCP_AGENT_PROFILE_URL } from "./types.js";

/** Paybond session binding for Shopify checkout — never sourced from client input. */
export type ShopifyCheckoutSessionBinding = {
  tenantId: string;
  intentId: string;
};

export type ShopifyCheckoutExecutor = (
  input: ShopifyCheckoutExecuteInput,
) => Promise<ShopifyCheckoutToolResult>;

export type CreateGuardedShopifyCheckoutHandlerOptions = {
  binding: () => ShopifyCheckoutSessionBinding;
  executeCheckout: ShopifyCheckoutExecutor;
  agentProfileUrl?: string;
};

export type InstrumentShopifyCheckoutInput = Omit<
  PaybondInstrumentInput<{ "commerce.checkout": (args: ShopifyCheckoutToolArgs) => Promise<ShopifyCheckoutToolResult> }>,
  "tools"
> & {
  policy: PaybondPolicyLoadSource;
  executeCheckout: ShopifyCheckoutExecutor;
  agentProfileUrl?: string;
  /**
   * Mutable binding populated after sandbox bind or production attach.
   * When omitted, a private ref is created for sandbox quickstarts.
   */
  bindingRef?: ShopifyCheckoutSessionBinding;
};

/**
 * Wraps a checkout executor so binding metadata is injected on every call.
 *
 * `tenantId` and `intentId` are read from the Paybond session binding ref — never from tool args.
 */
export function createGuardedShopifyCheckoutHandler(
  options: CreateGuardedShopifyCheckoutHandlerOptions,
): (args: ShopifyCheckoutToolArgs) => Promise<ShopifyCheckoutToolResult> {
  const profileUrl = (options.agentProfileUrl ?? PAYBOND_UCP_AGENT_PROFILE_URL).trim();

  return async (args: ShopifyCheckoutToolArgs): Promise<ShopifyCheckoutToolResult> => {
    const { tenantId, intentId } = options.binding();
    if (!tenantId.trim() || !intentId.trim()) {
      throw new Error("Paybond session binding is required before commerce.checkout");
    }

    const checkoutPayload = createCheckoutWithBinding({
      tenantId,
      intentId,
      lineItems: args.lineItems,
      existingNoteAttributes: args.noteAttributes,
      cartId: args.cartId,
      agentProfileUrl: profileUrl,
    });

    return options.executeCheckout({
      ...args,
      tenantId,
      intentId,
      checkoutPayload,
      agentProfileUrl: profileUrl,
    });
  };
}

/**
 * Instruments `commerce.checkout` with Paybond middleware and guaranteed binding injection.
 *
 * Returns the standard {@link PaybondInstrumentRuntime} surface from `paybond.instrument()`.
 */
export async function instrumentShopifyCheckout(
  paybond: Paybond,
  input: InstrumentShopifyCheckoutInput,
) {
  const bindingRef = input.bindingRef ?? { tenantId: "", intentId: "" };
  const checkoutHandler = createGuardedShopifyCheckoutHandler({
    binding: () => bindingRef,
    executeCheckout: input.executeCheckout,
    agentProfileUrl: input.agentProfileUrl,
  });

  const { bindingRef: _ignored, executeCheckout: _execute, ...instrumentInput } = input;
  const instrumented = await paybond.instrument({
    ...instrumentInput,
    tools: {
      "commerce.checkout": checkoutHandler,
    },
  });

  return { ...instrumented, bindingRef };
}
