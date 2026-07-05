import { createPaybondToolRegistry } from "../agent/registry.js";
import type { Paybond } from "../index.js";
import { PaybondMCPServer } from "../mcp-server.js";

export type RunMcpSandboxDemoInput = {
  paybond: Paybond;
  apiKey: string;
  gatewayBaseUrl: string;
  operation?: string;
  requestedSpendCents?: number;
  evidencePreset?: string;
};

export type RunMcpSandboxDemoResult = {
  bind: {
    run_id: string;
    tenant_id: string;
    intent_id: string;
    capability_token: string;
    operation: string;
    sandbox_lifecycle_status?: string;
  };
  authorization: {
    allow: boolean;
    audit_id?: string;
    decision_id?: string;
  };
  tool_result: {
    status: string;
    cost_cents: number;
  };
  evidence: {
    submitted: boolean;
    sandbox_lifecycle_status?: string;
    predicate_passed?: boolean | null;
  };
};

function readStructuredContent(
  result: Awaited<ReturnType<PaybondMCPServer["callTool"]>>,
): Record<string, unknown> | undefined {
  const structured = result.structuredContent;
  return typeof structured === "object" && structured !== null
    ? (structured as Record<string, unknown>)
    : undefined;
}

/**
 * No-LLM MCP sandbox demo: agent-run bind + in-process `PaybondMCPServer.callTool`
 * for authorize and evidence (no stdio subprocess).
 */
export async function runMcpSandboxDemo(
  input: RunMcpSandboxDemoInput,
): Promise<RunMcpSandboxDemoResult> {
  const operation = (input.operation ?? "paid-tool").trim();
  const requestedSpendCents = input.requestedSpendCents ?? 100;
  const evidencePreset = (input.evidencePreset ?? "cost_and_completion").trim();

  const registry = createPaybondToolRegistry({
    defaultDeny: true,
    sideEffecting: {
      [operation]: {
        operation,
        evidencePreset,
        spendCents: requestedSpendCents,
      },
    },
  });

  const run = await input.paybond.agentRun.bind({
    bootstrap: {
      kind: "sandbox",
      operation,
      requestedSpendCents,
      completionPreset: evidencePreset,
    },
    registry,
  });

  const server = new PaybondMCPServer({
    gatewayBaseUrl: input.gatewayBaseUrl,
    apiKey: input.apiKey,
  });

  const authorizeResult = await server.callTool("paybond_authorize_agent_spend", {
    intent_id: run.intentId,
    token: run.capabilityToken,
    operation,
    requested_spend_cents: requestedSpendCents,
  });
  if (authorizeResult.isError) {
    const message =
      authorizeResult.content[0]?.type === "text"
        ? authorizeResult.content[0].text
        : "paybond_authorize_agent_spend failed";
    throw new Error(message);
  }

  const authorizationBody = readStructuredContent(authorizeResult) ?? {};
  const toolResult = {
    status: "completed",
    cost_cents: requestedSpendCents,
  };

  const validationResult = await server.callTool("paybond_validate_completion_evidence", {
    preset_id: evidencePreset,
    vendor_payload: toolResult,
    canonical_payload: toolResult,
  });
  if (validationResult.isError) {
    const message =
      validationResult.content[0]?.type === "text"
        ? validationResult.content[0].text
        : "paybond_validate_completion_evidence failed";
    throw new Error(message);
  }
  const validationBody = readStructuredContent(validationResult) ?? {};
  if (validationBody.ok !== true) {
    throw new Error("paybond_validate_completion_evidence did not pass");
  }

  const evidenceResult = await server.callTool("paybond_submit_sandbox_guardrail_evidence", {
    intent_id: run.intentId,
    payload: toolResult,
    operation,
    requested_spend_cents: requestedSpendCents,
    completion_preset_id: evidencePreset,
  });
  if (evidenceResult.isError) {
    const message =
      evidenceResult.content[0]?.type === "text"
        ? evidenceResult.content[0].text
        : "paybond_submit_sandbox_guardrail_evidence failed";
    throw new Error(message);
  }

  const evidenceBody = readStructuredContent(evidenceResult) ?? {};
  const sandboxStatus =
    typeof evidenceBody.sandbox_lifecycle_status === "string"
      ? evidenceBody.sandbox_lifecycle_status
      : run.binding.sandbox?.sandboxLifecycleStatus;

  return {
    bind: {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation,
      sandbox_lifecycle_status: sandboxStatus,
    },
    authorization: {
      allow: authorizationBody.allow === true,
      audit_id:
        typeof authorizationBody.audit_id === "string" ? authorizationBody.audit_id : undefined,
      decision_id:
        typeof authorizationBody.decision_id === "string"
          ? authorizationBody.decision_id
          : undefined,
    },
    tool_result: toolResult,
    evidence: {
      submitted: true,
      sandbox_lifecycle_status: sandboxStatus,
      predicate_passed:
        typeof evidenceBody.predicate_passed === "boolean" ? evidenceBody.predicate_passed : true,
    },
  };
}
