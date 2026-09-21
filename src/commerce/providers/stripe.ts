import { encodeCommerceBindingToStripeMetadata } from "../../commerce-binding.js";
import { buildPaybondStripeMetadata } from "../../stripe-commerce/metadata.js";
import type { PaybondStripeSettlementRail } from "../../stripe-commerce/types.js";
import {
  requireAmountCents,
  requireCommerceSessionBinding,
  type CommerceCheckoutProvider,
} from "../provider.js";
import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
} from "../types.js";

/** Binding-injected input passed to a Stripe checkout executor. */
export type StripeCommerceCheckoutExecuteInput = {
  tenantId: string;
  intentId: string;
  amountCents: number;
  currency: string;
  description?: string;
  metadata: Record<string, string>;
  rail?: PaybondStripeSettlementRail;
  paymentIntentId?: string;
};

/**
 * Executes a Stripe PaymentIntent create/confirm after Paybond metadata binding.
 *
 * Must return the canonical `{ status, cost_cents, order_id? }` envelope.
 */
export type StripeCommerceCheckoutExecutor = (
  input: StripeCommerceCheckoutExecuteInput,
) => Promise<{
  status: CommerceCheckoutToolResult["status"];
  cost_cents: number;
  order_id?: string;
  payment_intent_id?: string;
}>;

export type CreateStripeCommerceProviderOptions = {
  executeCheckout: StripeCommerceCheckoutExecutor;
  /** Default ISO currency when tool args omit `stripe.currency` (default: usd). */
  defaultCurrency?: string;
};

/**
 * Creates a Stripe adapter for the multi-provider commerce checkout router.
 *
 * Stamps PaymentIntent metadata with session-sourced `tenant_id` / `paybond_intent_id`
 * via {@link encodeCommerceBindingToStripeMetadata} and optional rail via
 * {@link buildPaybondStripeMetadata}.
 */
export function createStripeCommerceProvider(
  options: CreateStripeCommerceProviderOptions,
): CommerceCheckoutProvider {
  const defaultCurrency = (options.defaultCurrency ?? "usd").trim().toLowerCase() || "usd";

  return {
    id: "stripe",
    async checkout(
      args: CommerceCheckoutToolArgs,
      binding: CommerceCheckoutSessionBinding,
    ): Promise<CommerceCheckoutToolResult> {
      const session = requireCommerceSessionBinding(binding);
      const amountCents = requireAmountCents(args.amountCents);
      const stripeArgs = args.stripe ?? {};

      const metadata = encodeCommerceBindingToStripeMetadata(
        { tenantId: session.tenantId, intentId: session.intentId },
        stripeArgs.existingMetadata,
      );

      if (stripeArgs.rail !== undefined) {
        const withRail = buildPaybondStripeMetadata({
          tenantId: session.tenantId,
          intentId: session.intentId,
          rail: stripeArgs.rail,
        });
        Object.assign(metadata, withRail);
      }

      const result = await options.executeCheckout({
        tenantId: session.tenantId,
        intentId: session.intentId,
        amountCents,
        currency: (stripeArgs.currency ?? defaultCurrency).trim().toLowerCase() || defaultCurrency,
        description: stripeArgs.description,
        metadata,
        rail: stripeArgs.rail,
        paymentIntentId: stripeArgs.paymentIntentId,
      });

      const costCents = result.cost_cents;
      if (
        typeof costCents !== "number" ||
        !Number.isInteger(costCents) ||
        costCents < 0
      ) {
        throw new Error(
          "commerce.checkout: stripe executor result cost_cents must be a non-negative integer",
        );
      }

      return {
        status: result.status,
        cost_cents: costCents,
        order_id: result.order_id ?? result.payment_intent_id,
        provider: "stripe",
        payment_intent_id: result.payment_intent_id,
      };
    },
  };
}
