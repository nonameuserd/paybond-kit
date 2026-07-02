import { vi } from "vitest";

export const AGENT_SMOKE_INTENT = "00000000-0000-4000-8000-000000000001";
export const ATTACH_INTENT_ID = "550e8400-e29b-41d4-a716-446655440000";

export const PRODUCTION_ATTACH_SEEDS = {
  payeeDid: "did:web:vendor.example",
  payeeSigningSeedHex: "01".repeat(32),
  agentRecognitionKeyId: "kid-1",
  agentRecognitionSigningSeedHex: "02".repeat(32),
} as const;

export function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export type AgentGatewayMockOptions = {
  allowVerify?: boolean;
  denyMessage?: string;
  environment?: "sandbox" | "live";
};

/** Mock Gateway routes used by agent bind, execute, and doctor --agent smoke checks. */
export function createAgentGatewayFetch(options: AgentGatewayMockOptions = {}) {
  const allowVerify = options.allowVerify ?? true;
  const environment = options.environment ?? "sandbox";
  const tenantId = environment === "live" ? "tenant-live" : "tenant-sandbox";
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = input.toString();
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (url.endsWith("/v1/auth/principal")) {
      return jsonResponse({
        tenant_id: tenantId,
        tenant_uuid: "550e8400-e29b-41d4-a716-446655440000",
        environment,
        service_account_role: "operator",
      });
    }
    if (url.includes(`/harbor/operator/v1/intents/${ATTACH_INTENT_ID}`)) {
      return jsonResponse({
        tenant_id: tenantId,
        intent_id: ATTACH_INTENT_ID,
        allowed_tools: ["paid-tool"],
      });
    }
    if (url.endsWith("/v1/sandbox/guardrails/bootstrap")) {
      return jsonResponse({
        tenant_id: "tenant-sandbox",
        intent_id: AGENT_SMOKE_INTENT,
        capability_token: "cap-smoke-1",
        operation: body.operation,
        requested_spend_cents: body.requested_spend_cents,
        sandbox_lifecycle_status: "funded",
      });
    }
    if (url.endsWith("/verify")) {
      if (!allowVerify) {
        return jsonResponse({
          allow: false,
          tenant: "tenant-sandbox",
          intent_id: AGENT_SMOKE_INTENT,
          audit_id: "audit-deny",
          decision_id: "decision-deny",
          message: options.denyMessage ?? "spend denied",
        });
      }
      return jsonResponse({
        allow: true,
        tenant: "tenant-sandbox",
        intent_id: AGENT_SMOKE_INTENT,
        audit_id: "audit-1",
        decision_id: "decision-1",
      });
    }
    if (url.endsWith(`/v1/sandbox/guardrails/${AGENT_SMOKE_INTENT}/evidence`)) {
      return jsonResponse({
        tenant_id: "tenant-sandbox",
        intent_id: AGENT_SMOKE_INTENT,
        operation: body.operation ?? "paid-tool",
        requested_spend_cents: body.requested_spend_cents ?? 100,
        sandbox_lifecycle_status: "released",
        predicate_passed: true,
      });
    }
    if (url.includes("/v1/spend/decisions/") && url.endsWith("/complete")) {
      return jsonResponse({});
    }
    return jsonResponse({}, 404);
  });
}

export const SANDBOX_RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

export const LIVE_RAW_KEY =
  "paybond_sk_live_fixture_not_a_real_secret_for_tests_only";
