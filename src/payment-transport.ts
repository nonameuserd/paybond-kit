/**
 * Payment Auth transport headers for MPP funding through the Paybond Gateway.
 *
 * Kit callers send `x-paybond-payment-authorization: Payment <credential>` so
 * `Authorization: Bearer` remains available for Paybond tenant authentication.
 * The gateway translates this to `Authorization: Payment` when forwarding to Harbor.
 */

/** Gateway-facing Payment Auth credential header (avoids clashing with Bearer auth). */
export const PAYBOND_PAYMENT_AUTHORIZATION_HEADER = "x-paybond-payment-authorization";

/** Payment Auth response headers propagated by the gateway from Harbor. */
export const PAYMENT_TRANSPORT_RESPONSE_HEADERS = [
  "www-authenticate",
  "payment-receipt",
  "cache-control",
] as const;

/**
 * Normalizes a Payment Auth credential for HTTP headers.
 *
 * Accepts either a raw credential token or a value already prefixed with `Payment `.
 */
export function formatPaymentAuthorizationValue(credential: string): string {
  const trimmed = credential.trim();
  if (!trimmed) {
    throw new Error("payment authorization credential must be non-empty");
  }
  if (/^payment\s+/i.test(trimmed)) {
    return trimmed;
  }
  return `Payment ${trimmed}`;
}

/** Header entry for gateway Harbor fund/verify retries. */
export function paymentAuthorizationGatewayHeader(
  credential: string,
): Record<string, string> {
  return {
    [PAYBOND_PAYMENT_AUTHORIZATION_HEADER]: formatPaymentAuthorizationValue(credential),
  };
}

/**
 * Appends `Authorization: Payment …` for direct Harbor calls that already carry Bearer auth.
 */
export function appendDirectHarborPaymentAuthorization(
  headers: Headers,
  credential: string,
): void {
  headers.append("authorization", formatPaymentAuthorizationValue(credential));
}

export type FundPaymentTransportHeaders = {
  wwwAuthenticate?: string[];
  paymentReceipt?: string;
  cacheControl?: string;
};

/** Reads Payment Auth transport headers from a fund response. */
export function readFundPaymentTransportHeaders(headers: Headers): FundPaymentTransportHeaders {
  const wwwAuthenticate: string[] = [];
  headers.forEach((value, key) => {
    if (key.toLowerCase() === "www-authenticate") {
      wwwAuthenticate.push(value);
    }
  });
  return {
    wwwAuthenticate: wwwAuthenticate.length > 0 ? wwwAuthenticate : undefined,
    paymentReceipt: headers.get("payment-receipt") ?? undefined,
    cacheControl: headers.get("cache-control") ?? undefined,
  };
}
