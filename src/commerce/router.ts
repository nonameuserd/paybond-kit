import {
  requireCommerceSessionBinding,
  type CommerceCheckoutProvider,
} from "./provider.js";
import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
  CommerceProviderId,
} from "./types.js";

const KNOWN_PROVIDERS = new Set<CommerceProviderId>(["shopify", "stripe", "zinc"]);

export type CommerceCheckoutProviderMap = Partial<
  Record<CommerceProviderId, CommerceCheckoutProvider>
>;

export type CreateCommerceCheckoutRouterOptions = {
  /** Registered provider adapters (at least `defaultProvider` must be present). */
  providers: CommerceCheckoutProviderMap;
  /** Provider used when tool args omit `provider`. */
  defaultProvider: CommerceProviderId;
  /**
   * Session binding getter — must return authenticated Paybond tenant/intent ids.
   * Never source these from unauthenticated tool args.
   */
  binding: () => CommerceCheckoutSessionBinding;
};

/**
 * Resolves which provider id to use for a checkout call.
 *
 * @throws on unknown provider ids or missing adapters
 */
export function resolveCommerceCheckoutProvider(
  args: CommerceCheckoutToolArgs,
  options: {
    providers: CommerceCheckoutProviderMap;
    defaultProvider: CommerceProviderId;
  },
): { providerId: CommerceProviderId; provider: CommerceCheckoutProvider } {
  const rawProvider = args.provider;
  if (typeof rawProvider === "string" && rawProvider.trim() === "") {
    throw new Error(
      'commerce.checkout: unknown provider ""; expected shopify, stripe, or zinc',
    );
  }
  const providerId = rawProvider ?? options.defaultProvider;

  if (!KNOWN_PROVIDERS.has(providerId)) {
    throw new Error(
      `commerce.checkout: unknown provider ${JSON.stringify(providerId)}; expected shopify, stripe, or zinc`,
    );
  }

  const provider = options.providers[providerId];
  if (!provider) {
    throw new Error(
      `commerce.checkout: no adapter registered for provider ${JSON.stringify(providerId)}`,
    );
  }

  if (provider.id !== providerId) {
    throw new Error(
      `commerce.checkout: provider map key ${JSON.stringify(providerId)} does not match adapter id ${JSON.stringify(provider.id)}`,
    );
  }

  return { providerId, provider };
}

/**
 * Builds a thin multi-provider `commerce.checkout` tool handler.
 *
 * Routes by `args.provider` (or `defaultProvider`), injects session binding into
 * each adapter, and returns the canonical `{ status, cost_cents, order_id? }` envelope.
 *
 * This is a Kit product surface — not a Gateway HTTP buy-proxy.
 *
 * @example
 * ```ts
 * const checkout = createCommerceCheckoutRouter({
 *   providers: { shopify, stripe, zinc },
 *   defaultProvider: "shopify",
 *   binding: () => bindingRef,
 * });
 * await paybond.instrument({
 *   policy: "shopping",
 *   tools: { "commerce.checkout": checkout },
 * });
 * ```
 */
export function createCommerceCheckoutRouter(
  options: CreateCommerceCheckoutRouterOptions,
): (args: CommerceCheckoutToolArgs) => Promise<CommerceCheckoutToolResult> {
  if (!options.providers[options.defaultProvider]) {
    throw new Error(
      `createCommerceCheckoutRouter: defaultProvider ${JSON.stringify(options.defaultProvider)} has no registered adapter`,
    );
  }

  for (const [key, adapter] of Object.entries(options.providers)) {
    if (!adapter) {
      continue;
    }
    if (!KNOWN_PROVIDERS.has(key as CommerceProviderId)) {
      throw new Error(
        `createCommerceCheckoutRouter: unknown provider key ${JSON.stringify(key)}`,
      );
    }
    if (adapter.id !== key) {
      throw new Error(
        `createCommerceCheckoutRouter: providers.${key} adapter id is ${JSON.stringify(adapter.id)}`,
      );
    }
  }

  return async (args: CommerceCheckoutToolArgs): Promise<CommerceCheckoutToolResult> => {
    const session = requireCommerceSessionBinding(options.binding());
    const { provider } = resolveCommerceCheckoutProvider(args, options);
    return provider.checkout(args, session);
  };
}
