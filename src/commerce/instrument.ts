import type { Paybond } from "../index.js";
import type { PaybondPolicyLoadSource } from "../policy/load.js";
import type { PaybondInstrumentInput } from "../agent/instrument.js";
import {
  createCommerceCheckoutRouter,
  type CommerceCheckoutProviderMap,
  type CreateCommerceCheckoutRouterOptions,
} from "./router.js";
import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
  CommerceProviderId,
} from "./types.js";

export type CreateGuardedCommerceCheckoutHandlerOptions = CreateCommerceCheckoutRouterOptions;

export type InstrumentCommerceCheckoutInput = Omit<
  PaybondInstrumentInput<{
    "commerce.checkout": (
      args: CommerceCheckoutToolArgs,
    ) => Promise<CommerceCheckoutToolResult>;
  }>,
  "tools"
> & {
  policy: PaybondPolicyLoadSource;
  providers: CommerceCheckoutProviderMap;
  defaultProvider: CommerceProviderId;
  /**
   * Mutable binding populated after sandbox bind or production attach.
   * When omitted, a private ref is created for sandbox quickstarts.
   */
  bindingRef?: CommerceCheckoutSessionBinding;
};

/**
 * Wraps registered commerce providers so session binding is injected on every call.
 *
 * Equivalent to {@link createCommerceCheckoutRouter} — kept for symmetry with
 * {@link createGuardedShopifyCheckoutHandler}.
 */
export function createGuardedCommerceCheckoutHandler(
  options: CreateGuardedCommerceCheckoutHandlerOptions,
): (args: CommerceCheckoutToolArgs) => Promise<CommerceCheckoutToolResult> {
  return createCommerceCheckoutRouter(options);
}

/**
 * Instruments `commerce.checkout` with Paybond middleware and multi-provider routing.
 *
 * Prefer this over wiring Shopify-only {@link instrumentShopifyCheckout} when the
 * agent may check out via Shopify, Stripe, or Zinc under one tool name.
 *
 * Returns the standard instrument runtime surface plus `bindingRef` for session ids.
 *
 * @example
 * ```ts
 * const instrumented = await instrumentCommerceCheckout(paybond, {
 *   policy: "shopping",
 *   providers: { shopify, stripe, zinc },
 *   defaultProvider: "shopify",
 * });
 * instrumented.bindingRef.tenantId = tenantId;
 * instrumented.bindingRef.intentId = intentId;
 * await instrumented.bind({ intentId, capabilityToken });
 * ```
 */
export async function instrumentCommerceCheckout(
  paybond: Paybond,
  input: InstrumentCommerceCheckoutInput,
) {
  const bindingRef = input.bindingRef ?? { tenantId: "", intentId: "" };
  const checkoutHandler = createCommerceCheckoutRouter({
    providers: input.providers,
    defaultProvider: input.defaultProvider,
    binding: () => bindingRef,
  });

  const {
    bindingRef: _ignored,
    providers: _providers,
    defaultProvider: _default,
    ...instrumentInput
  } = input;

  const instrumented = await paybond.instrument({
    ...instrumentInput,
    tools: {
      "commerce.checkout": checkoutHandler,
    },
  });

  return { ...instrumented, bindingRef };
}
