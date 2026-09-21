import { randomUUID } from "node:crypto";

import {
  requireAmountCents,
  requireCommerceSessionBinding,
  type CommerceCheckoutProvider,
} from "../provider.js";
import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
  CommerceZincCheckoutArgs,
  CommerceZincProductInput,
} from "../types.js";

/** Binding-injected Zinc order request used by sandbox and optional live clients. */
export type ZincCheckoutRequest = {
  tenantId: string;
  intentId: string;
  amountCents: number;
  retailer: string;
  products: CommerceZincCheckoutArgs["products"];
  shipping_address?: Record<string, string>;
  max_price_cents?: number;
};

/** Optional live Zinc HTTP client. Sandbox mode never calls this. */
export type ZincHttpClient = (request: ZincCheckoutRequest) => Promise<{
  status: CommerceCheckoutToolResult["status"];
  cost_cents: number;
  order_id?: string;
  zinc_request_id?: string;
}>;

export type CreateZincCommerceProviderOptions = {
  /**
   * `sandbox` (default) returns deterministic mock orders with no network I/O.
   * `live` requires {@link CreateZincCommerceProviderOptions.httpClient}.
   * Exact match after trim — `"Live"` / `"production"` are rejected.
   */
  mode?: "sandbox" | "live";
  /** Pluggable live Zinc HTTP client — unused in sandbox mode. */
  httpClient?: ZincHttpClient;
  /** Optional fixed order id prefix for sandbox determinism in tests. */
  sandboxOrderIdPrefix?: string;
};

function requireNonNegativeCents(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`commerce.checkout: ${label} must be a non-negative integer`);
  }
  return value;
}

/**
 * Sums unit `price_cents * quantity` across Zinc products.
 *
 * @throws when any product lacks a valid non-negative integer `price_cents`
 */
export function deriveZincProductsCostCents(
  products: readonly CommerceZincProductInput[],
): number {
  let total = 0;
  for (const product of products) {
    const unit = requireNonNegativeCents(
      product.price_cents,
      "zinc product price_cents",
    );
    if (!Number.isInteger(product.quantity) || product.quantity <= 0) {
      throw new Error("commerce.checkout: zinc product quantity must be a positive integer");
    }
    total += unit * product.quantity;
  }
  return total;
}

function requireZincArgs(args: CommerceCheckoutToolArgs): CommerceZincCheckoutArgs {
  const zinc = args.zinc;
  if (!zinc) {
    throw new Error('commerce.checkout: zinc payload is required when provider is "zinc"');
  }
  if (!zinc.retailer?.trim()) {
    throw new Error("commerce.checkout: zinc.retailer is required");
  }
  if (!Array.isArray(zinc.products) || zinc.products.length === 0) {
    throw new Error("commerce.checkout: zinc.products must include at least one item");
  }
  for (const product of zinc.products) {
    if (!product.product_id?.trim()) {
      throw new Error("commerce.checkout: zinc product_id is required");
    }
    if (!Number.isInteger(product.quantity) || product.quantity <= 0) {
      throw new Error("commerce.checkout: zinc product quantity must be a positive integer");
    }
  }
  if (zinc.max_price_cents !== undefined) {
    requireNonNegativeCents(zinc.max_price_cents, "zinc.max_price_cents");
  }
  return zinc;
}

function sandboxCheckout(
  request: ZincCheckoutRequest,
  orderIdPrefix: string,
): CommerceCheckoutToolResult {
  const derivedCostCents = deriveZincProductsCostCents(request.products);

  if (
    request.max_price_cents !== undefined &&
    derivedCostCents > request.max_price_cents
  ) {
    return {
      status: "failed",
      cost_cents: 0,
      provider: "zinc",
      zinc_request_id: `${orderIdPrefix}req_over_max`,
    };
  }

  if (request.amountCents !== derivedCostCents) {
    throw new Error(
      `commerce.checkout: zinc amountCents (${request.amountCents}) must equal ` +
        `product-derived cost_cents (${derivedCostCents})`,
    );
  }

  const requestId = `${orderIdPrefix}${randomUUID().replace(/-/g, "").slice(0, 12)}`;
  return {
    status: "completed",
    // Product-derived — never invent from agent amountCents alone.
    cost_cents: derivedCostCents,
    order_id: `${orderIdPrefix}ord_${request.retailer}_${request.products[0]?.product_id ?? "item"}`,
    provider: "zinc",
    zinc_request_id: requestId,
  };
}

/**
 * Creates a Zinc adapter for the multi-provider commerce checkout router.
 *
 * Default `sandbox` mode is fully offline for e2e / instrument smoke tests.
 * Live HTTP is optional via a pluggable {@link ZincHttpClient} — Kit does not
 * ship a hard-coded Zinc API dependency or Gateway buy-proxy.
 */
export function createZincCommerceProvider(
  options: CreateZincCommerceProviderOptions = {},
): CommerceCheckoutProvider {
  const mode = String(options.mode ?? "sandbox").trim();
  if (mode !== "sandbox" && mode !== "live") {
    throw new Error(
      'createZincCommerceProvider: mode must be "sandbox" or "live"',
    );
  }
  const orderIdPrefix = options.sandboxOrderIdPrefix ?? "zinc_sandbox_";

  if (mode === "live" && !options.httpClient) {
    throw new Error(
      'createZincCommerceProvider: httpClient is required when mode is "live"',
    );
  }

  return {
    id: "zinc",
    async checkout(
      args: CommerceCheckoutToolArgs,
      binding: CommerceCheckoutSessionBinding,
    ): Promise<CommerceCheckoutToolResult> {
      const session = requireCommerceSessionBinding(binding);
      const amountCents = requireAmountCents(args.amountCents);
      const zincArgs = requireZincArgs(args);

      const request: ZincCheckoutRequest = {
        tenantId: session.tenantId,
        intentId: session.intentId,
        amountCents,
        retailer: zincArgs.retailer.trim(),
        products: zincArgs.products,
        shipping_address: zincArgs.shipping_address,
        max_price_cents: zincArgs.max_price_cents,
      };

      if (mode === "sandbox") {
        return sandboxCheckout(request, orderIdPrefix);
      }

      const result = await options.httpClient!(request);
      if (
        typeof result.cost_cents !== "number" ||
        !Number.isInteger(result.cost_cents) ||
        result.cost_cents < 0
      ) {
        throw new Error(
          "commerce.checkout: zinc httpClient result cost_cents must be a non-negative integer",
        );
      }
      return {
        status: result.status,
        cost_cents: result.cost_cents,
        order_id: result.order_id,
        provider: "zinc",
        zinc_request_id: result.zinc_request_id,
      };
    },
  };
}
