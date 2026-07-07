import {
  verifyAgentReceiptV1,
  type AgentReceiptV1,
} from "../agent-receipt.js";
import type { PaybondAgentInput, PaybondAgentResult } from "./facade.js";

export type VerifyAgentReceiptV1Result = {
  valid: boolean;
  kind: string;
  receipt_id: string;
  tenant_id: string;
  receipt: AgentReceiptV1;
};

type AgentReceiptProtocolClient = {
  getAgentReceiptV1ByID(receiptId: string): Promise<AgentReceiptV1>;
  getAgentReceiptV1ByIntentToolCall(init: {
    intentId: string;
    toolCallId: string;
  }): Promise<AgentReceiptV1>;
  verifyAgentReceiptV1(receipt: AgentReceiptV1 | Record<string, unknown>): Promise<VerifyAgentReceiptV1Result>;
};

export type GetAgentReceiptInput =
  | { receiptId: string; intentId?: never; toolCallId?: never }
  | { intentId: string; toolCallId: string; receiptId?: never };

export type PaybondAgentCallable = ((
  input: PaybondAgentInput,
) => Promise<PaybondAgentResult>) & {
  getReceipt(input: GetAgentReceiptInput): Promise<AgentReceiptV1>;
  verifyReceipt(
    receipt: AgentReceiptV1,
    options?: { offline?: boolean },
  ): Promise<VerifyAgentReceiptV1Result | AgentReceiptV1>;
};

/** Tenant-bound agent quickstart plus receipt fetch/verify helpers. */
export class PaybondAgentFacade {
  constructor(
    private readonly protocol: AgentReceiptProtocolClient,
    private readonly invokeAgent?: (input: PaybondAgentInput) => Promise<PaybondAgentResult>,
  ) {}

  /** Fetch a signed `paybond.agent_receipt_v1` by receipt id or intent/tool-call lookup. */
  async getReceipt(input: GetAgentReceiptInput): Promise<AgentReceiptV1> {
    if ("receiptId" in input && input.receiptId?.trim()) {
      return this.protocol.getAgentReceiptV1ByID(input.receiptId.trim());
    }
    if (input.intentId?.trim() && input.toolCallId?.trim()) {
      return this.protocol.getAgentReceiptV1ByIntentToolCall({
        intentId: input.intentId.trim(),
        toolCallId: input.toolCallId.trim(),
      });
    }
    throw new Error("getReceipt requires receiptId or intentId + toolCallId");
  }

  /** Verify a signed agent receipt via Gateway or locally with {@link verifyAgentReceiptV1}. */
  async verifyReceipt(
    receipt: AgentReceiptV1,
    options?: { offline?: boolean },
  ): Promise<VerifyAgentReceiptV1Result | AgentReceiptV1> {
    if (options?.offline) {
      return verifyAgentReceiptV1(receipt);
    }
    return this.protocol.verifyAgentReceiptV1(receipt);
  }

  /** Opinionated quickstart: resolve policy presets and wire framework tools. */
  async call(input: PaybondAgentInput): Promise<PaybondAgentResult> {
    if (!this.invokeAgent) {
      throw new Error("paybond.agent() requires a hosted Paybond session");
    }
    return this.invokeAgent(input);
  }
}

/** Callable `paybond.agent({...})` surface with receipt helpers attached. */
export function createPaybondAgentCallable(
  protocol: AgentReceiptProtocolClient,
  invokeAgent: (input: PaybondAgentInput) => Promise<PaybondAgentResult>,
): PaybondAgentCallable {
  const facade = new PaybondAgentFacade(protocol, invokeAgent);
  const callable = ((input: PaybondAgentInput) => facade.call(input)) as PaybondAgentCallable;
  callable.getReceipt = facade.getReceipt.bind(facade);
  callable.verifyReceipt = facade.verifyReceipt.bind(facade);
  return callable;
}
