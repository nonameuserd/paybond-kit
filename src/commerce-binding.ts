export const PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY = "tenant_id";
export const PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY = "paybond_intent_id";

export type CommerceBinding = {
  /**
   * Tenant realm identifier.
   *
   * Must be sourced from authenticated Paybond session context — never from
   * unauthenticated client input.
   */
  tenantId: string;
  /**
   * Harbor intent identifier (UUID).
   *
   * Must be sourced from authenticated Paybond session context — never from
   * unauthenticated client input.
   */
  intentId: string;
};

export type StripeMetadata = Record<string, string>;

export type ShopifyNoteAttribute = {
  name: string;
  value: string;
};

function requireNonEmptyTrimmed(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error(`commerce-binding: ${label} is required`);
  }
  return trimmed;
}

function assertNoCollision(
  existingValue: string | undefined,
  nextValue: string,
  label: string,
): void {
  if (existingValue === undefined) {
    return;
  }
  if (existingValue === nextValue) {
    return;
  }
  throw new Error(
    `commerce-binding: ${label} collision (${JSON.stringify(existingValue)} != ${JSON.stringify(nextValue)})`,
  );
}

/**
 * Validates and normalizes the canonical Paybond commerce binding.
 *
 * This helper is intentionally strict: the binding is used for tenant isolation
 * and provider webhook preflight matching.
 */
export function normalizeCommerceBinding(binding: CommerceBinding): CommerceBinding {
  return {
    tenantId: requireNonEmptyTrimmed(binding.tenantId, "tenantId"),
    intentId: requireNonEmptyTrimmed(binding.intentId, "intentId"),
  };
}

/**
 * Encodes a canonical Paybond commerce binding into Stripe `metadata`.
 *
 * - Preserves unknown metadata keys.
 * - Rejects collisions when an existing binding key disagrees.
 */
export function encodeCommerceBindingToStripeMetadata(
  binding: CommerceBinding,
  existingMetadata?: StripeMetadata,
): StripeMetadata {
  const normalized = normalizeCommerceBinding(binding);
  const merged: StripeMetadata = { ...(existingMetadata ?? {}) };

  assertNoCollision(
    merged[PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY],
    normalized.tenantId,
    PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY,
  );
  assertNoCollision(
    merged[PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY],
    normalized.intentId,
    PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY,
  );

  merged[PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY] = normalized.tenantId;
  merged[PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY] = normalized.intentId;
  return merged;
}

/**
 * Decodes a canonical Paybond commerce binding from Stripe `metadata`.
 *
 * Returns `null` when binding keys are absent. Throws on empty values.
 */
export function decodeCommerceBindingFromStripeMetadata(
  metadata: Record<string, unknown> | null | undefined,
): CommerceBinding | null {
  if (!metadata) {
    return null;
  }
  const rawTenantId = metadata[PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY];
  const rawIntentId = metadata[PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY];
  if (typeof rawTenantId !== "string" || typeof rawIntentId !== "string") {
    return null;
  }
  return normalizeCommerceBinding({ tenantId: rawTenantId, intentId: rawIntentId });
}

/**
 * Encodes a canonical Paybond commerce binding into Shopify `note_attributes`.
 *
 * - Preserves unknown attributes.
 * - Removes any existing occurrences of binding keys (after verifying they match).
 * - Appends canonical binding attributes in stable order.
 */
export function encodeCommerceBindingToShopifyNoteAttributes(
  binding: CommerceBinding,
  existingAttributes?: readonly ShopifyNoteAttribute[],
): ShopifyNoteAttribute[] {
  const normalized = normalizeCommerceBinding(binding);

  const attrs: ShopifyNoteAttribute[] = [];
  const input = existingAttributes ?? [];

  for (const attr of input) {
    if (!attr || typeof attr.name !== "string" || typeof attr.value !== "string") {
      continue;
    }
    if (attr.name === PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY) {
      assertNoCollision(attr.value, normalized.tenantId, attr.name);
      continue;
    }
    if (attr.name === PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY) {
      assertNoCollision(attr.value, normalized.intentId, attr.name);
      continue;
    }
    attrs.push({ name: attr.name, value: attr.value });
  }

  attrs.push(
    { name: PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY, value: normalized.tenantId },
    { name: PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY, value: normalized.intentId },
  );

  return attrs;
}

/**
 * Decodes a canonical Paybond commerce binding from Shopify `note_attributes`.
 *
 * Returns `null` when binding keys are absent. Throws on:
 * - empty binding values
 * - multiple conflicting values for the same key
 */
export function decodeCommerceBindingFromShopifyNoteAttributes(
  noteAttributes: unknown,
): CommerceBinding | null {
  if (!Array.isArray(noteAttributes)) {
    return null;
  }

  let tenantId: string | undefined;
  let intentId: string | undefined;

  for (const entry of noteAttributes) {
    if (!entry || typeof entry !== "object") {
      continue;
    }
    const name = (entry as { name?: unknown }).name;
    const value = (entry as { value?: unknown }).value;
    if (typeof name !== "string" || typeof value !== "string") {
      continue;
    }

    if (name === PAYBOND_COMMERCE_BINDING_TENANT_ID_KEY) {
      if (tenantId !== undefined && tenantId !== value) {
        throw new Error(
          `commerce-binding: ${name} collision (${JSON.stringify(tenantId)} != ${JSON.stringify(value)})`,
        );
      }
      tenantId = value;
    }

    if (name === PAYBOND_COMMERCE_BINDING_INTENT_ID_KEY) {
      if (intentId !== undefined && intentId !== value) {
        throw new Error(
          `commerce-binding: ${name} collision (${JSON.stringify(intentId)} != ${JSON.stringify(value)})`,
        );
      }
      intentId = value;
    }
  }

  if (tenantId === undefined || intentId === undefined) {
    return null;
  }
  return normalizeCommerceBinding({ tenantId, intentId });
}

