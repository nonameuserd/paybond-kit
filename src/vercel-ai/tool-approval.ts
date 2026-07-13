import type { GenericToolApprovalFunction, ToolApprovalStatus, ToolSet } from "ai";
import { createToolInputGuardAdapter } from "../agent/adapter.js";
import type { PaybondAgentRun } from "../agent/run.js";
import type { PaybondToolInputGuardDecision } from "../agent/types.js";
import {
  isProviderExecutedVercelTool,
  paybondProviderExecutedToolDenialReason,
  resolveVercelToolFromSet,
} from "./provider-executed.js";

/** Map a framework-neutral Paybond decision to Vercel AI SDK tool approval status. */
export function mapPaybondDecisionToVercelToolApproval(
  decision: PaybondToolInputGuardDecision,
): ToolApprovalStatus {
  if (decision.kind === "allow") {
    return "approved";
  }

  if (decision.kind === "approval_required") {
    return "user-approval";
  }

  return { type: "denied", reason: decision.message };
}

export type PaybondVercelToolApprovalOptions = {
  /** Override Paybond → Vercel approval status mapping (for example custom HITL labels). */
  mapDecision?: (decision: PaybondToolInputGuardDecision) => ToolApprovalStatus;
  /**
   * Fail closed on provider-executed tools (`isProviderExecuted: true`).
   * When enabled, those tool calls are denied at approval time.
   */
  denyProviderExecutedTools?: boolean;
};

/**
 * Centralized `toolApproval` bridge for Vercel AI SDK `generateText` / `streamText`.
 *
 * Non-side-effecting tools are auto-approved without Harbor verify. Side-effecting
 * registered tools run the Paybond interceptor pre-check; denials propagate as tool errors.
 */
export function paybondVercelToolApproval<TOOLS extends ToolSet = ToolSet>(
  run: PaybondAgentRun,
  options?: PaybondVercelToolApprovalOptions,
): GenericToolApprovalFunction<TOOLS, never, never> {
  const guard = createToolInputGuardAdapter(run);
  const mapDecision = options?.mapDecision ?? mapPaybondDecisionToVercelToolApproval;

  const approve = async ({
    toolCall,
    tools,
  }: {
    toolCall: { toolName: string; toolCallId: string; input: unknown };
    tools?: TOOLS;
  }): Promise<ToolApprovalStatus> => {
    const toolName = toolCall.toolName;
    const toolCallId = toolCall.toolCallId;

    if (options?.denyProviderExecutedTools === true) {
      const toolDef = resolveVercelToolFromSet(tools, toolName);
      if (toolDef !== undefined && isProviderExecutedVercelTool(toolDef)) {
        return { type: "denied", reason: paybondProviderExecutedToolDenialReason() };
      }
    }

    if (!run.registry.isSideEffecting(toolName)) {
      const resolution = run.registry.resolveTool(toolName, {
        allowedTools: run.allowedTools,
      });
      if (resolution.kind === "passthrough") {
        return "approved";
      }
    }

    const decision = await guard.evaluate({
      toolName,
      toolCallId,
      arguments: toolCall.input,
      approvalToken: run.getApprovalToken(toolCallId),
    });

    return mapDecision(decision);
  };

  return approve as GenericToolApprovalFunction<TOOLS, never, never>;
}
