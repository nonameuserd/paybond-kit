import { apiKeyEnvironment } from "./agent/paybond.js";
import { handleAgentSandboxSmoke } from "./commands/agent.js";
import type { CliContext } from "./context.js";
import type { DoctorCheck } from "./doctor-agent.js";
import { CliError } from "./types.js";

export const AGENT_MIDDLEWARE_SMOKE_NEXT =
  "paybond agent sandbox smoke --operation paid-tool --requested-spend-cents 100 --evidence-preset cost_and_completion --result-body '{\"status\":\"ok\",\"cost_cents\":100}' --format json";

/** Run sandbox middleware smoke as a doctor --agent check (uses ctx.fetch / project cwd). */
export async function runAgentMiddlewareDoctorCheck(
  ctx: CliContext,
  apiKey: string,
): Promise<DoctorCheck> {
  if (!apiKey) {
    return {
      name: "agent_middleware_smoke",
      ok: false,
      message: "skipped (missing API key)",
      details: { next_command: AGENT_MIDDLEWARE_SMOKE_NEXT },
    };
  }
  if (apiKeyEnvironment(apiKey) === "live") {
    return {
      name: "agent_middleware_smoke",
      ok: true,
      message: "skipped (live API key; smoke uses sandbox guardrails bootstrap)",
      details: { next_command: AGENT_MIDDLEWARE_SMOKE_NEXT },
    };
  }

  try {
    await handleAgentSandboxSmoke(ctx, [
      "--operation",
      "paid-tool",
      "--requested-spend-cents",
      "100",
      "--evidence-preset",
      "cost_and_completion",
      "--result-body",
      '{"status":"ok","cost_cents":100}',
    ]);
    return {
      name: "agent_middleware_smoke",
      ok: true,
      message: "bind, authorize, execute, and auto-evidence succeeded",
    };
  } catch (err) {
    const message = err instanceof CliError ? err.message : err instanceof Error ? err.message : String(err);
    return {
      name: "agent_middleware_smoke",
      ok: false,
      message,
      details: { next_command: AGENT_MIDDLEWARE_SMOKE_NEXT },
    };
  }
}
