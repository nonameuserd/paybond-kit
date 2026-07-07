import { describe, expect, it } from "vitest";
import {
  PAYBOND_PAYMENT_AUTHORIZATION_HEADER,
  formatPaymentAuthorizationValue,
  paymentAuthorizationGatewayHeader,
  readFundPaymentTransportHeaders,
} from "../src/payment-transport.js";

describe("payment-transport", () => {
  it("uses the gateway-facing payment authorization header name", () => {
    expect(PAYBOND_PAYMENT_AUTHORIZATION_HEADER).toBe("x-paybond-payment-authorization");
  });

  it("prefixes raw credentials with Payment scheme", () => {
    expect(formatPaymentAuthorizationValue("eyJ0ZXN0IjoidHJ1ZSJ9")).toBe(
      "Payment eyJ0ZXN0IjoidHJ1ZSJ9",
    );
  });

  it("preserves credentials already prefixed with Payment", () => {
    expect(formatPaymentAuthorizationValue("Payment eyJ0ZXN0IjoidHJ1ZSJ9")).toBe(
      "Payment eyJ0ZXN0IjoidHJ1ZSJ9",
    );
  });

  it("builds gateway header map for fund retries", () => {
    expect(paymentAuthorizationGatewayHeader("eyJ0ZXN0IjoidHJ1ZSJ9")).toEqual({
      "x-paybond-payment-authorization": "Payment eyJ0ZXN0IjoidHJ1ZSJ9",
    });
  });

  it("reads payment transport response headers from fund responses", () => {
    const headers = new Headers();
    headers.append(
      "www-authenticate",
      'Payment id="abc", realm="api.example.com", method="stripe", intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"',
    );
    headers.set("payment-receipt", "eyJyZWNlaXB0Ijp0cnVlfQ");
    headers.set("cache-control", "no-store");

    expect(readFundPaymentTransportHeaders(headers)).toEqual({
      wwwAuthenticate: [
        'Payment id="abc", realm="api.example.com", method="stripe", intent="charge", request="eyJ0ZXN0IjoidHJ1ZSJ9"',
      ],
      paymentReceipt: "eyJyZWNlaXB0Ijp0cnVlfQ",
      cacheControl: "no-store",
    });
  });
});
