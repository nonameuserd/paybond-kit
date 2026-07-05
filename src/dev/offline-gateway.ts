/**
 * In-process offline Gateway mock for `paybond dev --offline`.
 * Simulates sandbox capability bootstrap, verify, evidence, settlement completion,
 * and an optional x402 `/fund` state machine for Harbor intent funding smoke.
 */

import { X402FundStateMachine } from "./x402-fund-mock.js";

export const OFFLINE_DEV_INTENT_ID = "00000000-0000-4000-8000-000000000001";
export const OFFLINE_DEV_TENANT_ID = "tenant-dev-offline";

const HARBOR_FUND_PATH = /^\/harbor\/intents\/([^/]+)\/fund$/;

/** Synthetic sandbox API key shape accepted by offline mocks (never validated remotely). */
export const OFFLINE_SANDBOX_API_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_" +
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/** Visible prefix for production service-account API keys. */
export const LIVE_API_KEY_PREFIX = "paybond_sk_live_" as const;

/** Return true when `apiKey` is a production (`paybond_sk_live_…`) service-account key. */
export function isProductionApiKey(apiKey: string): boolean {
  return apiKey.startsWith(LIVE_API_KEY_PREFIX);
}

export const DEV_WIREMOCK_DEFAULT_PORT = 18089;
export const DEV_WIREMOCK_CONTAINER_NAME = "paybond-dev-wiremock";

export type OfflineGatewayMockOptions = {
  allowVerify?: boolean;
  denyMessage?: string;
};

function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...extraHeaders },
  });
}

function readRequestHeader(init: RequestInit | undefined, name: string): string | undefined {
  if (!init?.headers) {
    return undefined;
  }
  const headers = new Headers(init.headers);
  return headers.get(name) ?? undefined;
}

function parseHarborFundPath(url: string): string | null {
  try {
    const pathname = new URL(url).pathname;
    const match = pathname.match(HARBOR_FUND_PATH);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

/** Build a fetch implementation that stubs Gateway routes for local dev smoke. */
export function createOfflineDevGatewayFetch(
  options: OfflineGatewayMockOptions = {},
): typeof fetch {
  const allowVerify = options.allowVerify ?? true;
  const x402FundState = new X402FundStateMachine();
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    const method = (init?.method ?? "GET").toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    const harborFundIntentId =
      method === "POST" ? parseHarborFundPath(url) : null;
    if (harborFundIntentId) {
      const paymentSignature = readRequestHeader(init, "payment-signature");
      const mock = x402FundState.next(
        harborFundIntentId,
        OFFLINE_DEV_TENANT_ID,
        paymentSignature,
      );
      if (mock) {
        return jsonResponse(mock.body, mock.status, mock.headers);
      }
      return jsonResponse({}, 404);
    }
    if (url.endsWith("/v1/auth/principal")) {
      return jsonResponse({
        tenant_id: OFFLINE_DEV_TENANT_ID,
        tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
        environment: "sandbox",
        service_account_role: "operator",
      });
    }
    if (url.endsWith("/v1/sandbox/guardrails/bootstrap")) {
      return jsonResponse({
        tenant_id: OFFLINE_DEV_TENANT_ID,
        intent_id: OFFLINE_DEV_INTENT_ID,
        capability_token: "cap-dev-offline-1",
        operation: body.operation,
        requested_spend_cents: body.requested_spend_cents,
        sandbox_lifecycle_status: "funded",
      });
    }
    if (url.endsWith("/verify")) {
      if (!allowVerify) {
        return jsonResponse({
          allow: false,
          tenant: OFFLINE_DEV_TENANT_ID,
          intent_id: OFFLINE_DEV_INTENT_ID,
          audit_id: "audit-deny",
          decision_id: "decision-deny",
          message: options.denyMessage ?? "spend denied",
        });
      }
      return jsonResponse({
        allow: true,
        tenant: OFFLINE_DEV_TENANT_ID,
        intent_id: OFFLINE_DEV_INTENT_ID,
        audit_id: "00000000-0000-4000-8000-000000000002",
        decision_id: "00000000-0000-4000-8000-000000000003",
      });
    }
    if (url.endsWith(`/v1/sandbox/guardrails/${OFFLINE_DEV_INTENT_ID}/evidence`)) {
      return jsonResponse({
        tenant_id: OFFLINE_DEV_TENANT_ID,
        intent_id: OFFLINE_DEV_INTENT_ID,
        operation: body.operation ?? "paid-tool",
        requested_spend_cents: body.requested_spend_cents ?? 100,
        sandbox_lifecycle_status: "released",
        predicate_passed: true,
        settlement_mode: "simulated",
      });
    }
    if (url.includes("/v1/spend/decisions/") && url.endsWith("/complete")) {
      return jsonResponse({ settlement_mode: "simulated" });
    }
    return jsonResponse({}, 404);
  }) as typeof fetch;
}

declare const process: { env: Record<string, string | undefined> };

/** Apply offline dev credentials and fetch mock; returns a restore function. */
export function activateOfflineDevMode(): { restore: () => void } {
  const previousApiKey = process.env.PAYBOND_API_KEY;
  const trimmedPrevious = previousApiKey?.trim();
  if (trimmedPrevious && isProductionApiKey(trimmedPrevious)) {
    throw new Error(
      "offline dev mode cannot be used with production API keys (paybond_sk_live_...); unset PAYBOND_API_KEY or use a sandbox key",
    );
  }
  process.env.PAYBOND_API_KEY = OFFLINE_SANDBOX_API_KEY;
  return {
    restore() {
      if (previousApiKey === undefined) {
        delete process.env.PAYBOND_API_KEY;
      } else {
        process.env.PAYBOND_API_KEY = previousApiKey;
      }
    },
  };
}
