import type {
  CommerceCheckoutSessionBinding,
  CommerceCheckoutToolArgs,
  CommerceCheckoutToolResult,
  CommerceProviderId,
} from "./types.js";

/**
 * Thin adapter contract for a commerce.checkout provider.
 *
 * Adapters receive session-sourced binding and tool args; they must never trust
 * client-supplied tenant or intent identifiers.
 */
export type CommerceCheckoutProvider = {
  readonly id: CommerceProviderId;
  checkout(
    args: CommerceCheckoutToolArgs,
    binding: CommerceCheckoutSessionBinding,
  ): Promise<CommerceCheckoutToolResult>;
};

/**
 * Validates and normalizes a Paybond session binding for commerce checkout.
 *
 * @throws when tenantId or intentId are missing/blank
 */
export function requireCommerceSessionBinding(
  binding: CommerceCheckoutSessionBinding,
): CommerceCheckoutSessionBinding {
  const tenantId = binding.tenantId.trim();
  const intentId = binding.intentId.trim();
  if (!tenantId || !intentId) {
    throw new Error("Paybond session binding is required before commerce.checkout");
  }
  return { tenantId, intentId };
}

/**
 * Asserts amountCents is a non-negative integer.
 */
export function requireAmountCents(amountCents: number): number {
  if (!Number.isInteger(amountCents) || amountCents < 0) {
    throw new Error("commerce.checkout: amountCents must be a non-negative integer");
  }
  return amountCents;
}
