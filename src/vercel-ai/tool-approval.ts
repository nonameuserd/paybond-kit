import type { GenericToolApprovalFunction, ToolApprovalStatus, ToolSet } from "ai";
import { createToolInputGuardAdapter } from "../agent/adapter.js";
import type { PaybondAgentRun } from "../agent/run.js";
import type { PaybondToolInputGuardDecision } from "../agent/types.js";

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
  }: {
    toolCall: { toolName: string; toolCallId: string; input: unknown };
  }): Promise<ToolApprovalStatus> => {
    const toolName = toolCall.toolName;
    const toolCallId = toolCall.toolCallId;

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
