import type { PaybondTraceEvent } from "../agent/types.js";

export type AgentRunUpsertInput = Readonly<{
  intentId: string;
  operation?: string;
  sandbox?: boolean;
  allowedTools?: readonly string[];
  completionPreset?: string;
}>;

type GatewayJsonWriter = (
  method: "PUT" | "POST",
  path: string,
  body: Record<string, unknown>,
) => Promise<unknown>;

/**
 * Fire-and-forget Gateway trace reporter for console observability.
 * Failures are swallowed so middleware execution is never blocked on telemetry.
 */
export class GatewayAgentRunTraceReporter {
  private readonly pending: Promise<void>[] = [];
  private registered = false;

  constructor(
    private readonly writeJSON: GatewayJsonWriter,
    private readonly runId: string,
  ) {}

  /** Register run metadata once per bind (idempotent server-side upsert). */
  registerRun(input: AgentRunUpsertInput): void {
    if (this.registered) {
      return;
    }
    this.registered = true;
    const body = {
      intent_id: input.intentId,
      operation: input.operation ?? "",
      sandbox: input.sandbox ?? false,
      allowed_tools: [...(input.allowedTools ?? [])],
      completion_preset: input.completionPreset ?? "",
    };
    this.pending.push(
      this.writeJSON("PUT", `/v1/agent-runs/${encodeURIComponent(this.runId)}`, body)
        .then(() => undefined)
        .catch(() => undefined),
    );
  }

  /** Append one middleware trace event to the Gateway run timeline. */
  reportEvent(event: PaybondTraceEvent): void {
    this.pending.push(
      this.writeJSON("POST", `/v1/agent-runs/${encodeURIComponent(this.runId)}/trace-events`, {
        events: [event],
      })
        .then(() => undefined)
        .catch(() => undefined),
    );
  }

  createSink(input: AgentRunUpsertInput): (event: PaybondTraceEvent) => void {
    this.registerRun(input);
    return (event) => {
      this.reportEvent(event);
    };
  }

  /** Await in-flight Gateway writes (CLI shutdown hooks). */
  async flush(): Promise<void> {
    await Promise.all(this.pending.splice(0));
  }
}
