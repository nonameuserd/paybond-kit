import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  DEV_DEFAULT_POLICY_FILE,
  DEV_TRACE_DEFAULT_PORT,
  devTraceUrl,
} from "../../dev/trace-buffer.js";
import { type CliContext, type GatewayClient, type GatewayJson, withGateway } from "../context.js";
import { CliError } from "../types.js";

export type ControlPanel = "intents" | "receipts" | "policy" | "spend" | "denials";

export const CONTROL_PANELS: readonly ControlPanel[] = [
  "intents",
  "receipts",
  "policy",
  "spend",
  "denials",
] as const;

export type ControlPlaneSnapshot = {
  tenant_id: string | null;
  environment: string | null;
  gateway: string;
  trace_url: string;
  panels: {
    intents: Array<Record<string, unknown>>;
    receipts: Array<Record<string, unknown>>;
    policy: Record<string, unknown>;
    spend: Record<string, unknown>;
    denials: Array<Record<string, unknown>>;
  };
  generated_at: string;
  limitations: string[];
};

function asObjectRows(body: GatewayJson, keys: string[]): Array<Record<string, unknown>> {
  for (const key of keys) {
    const value = body[key];
    if (Array.isArray(value)) {
      return value.filter((row): row is Record<string, unknown> => !!row && typeof row === "object");
    }
  }
  return [];
}

function isDenialOutcome(outcome: unknown): boolean {
  if (typeof outcome !== "string") {
    return false;
  }
  const normalized = outcome.trim().toLowerCase();
  return (
    normalized === "deny" ||
    normalized === "denied" ||
    normalized === "reject" ||
    normalized === "rejected" ||
    normalized.includes("deny")
  );
}

function mapDecisionRow(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id ?? null,
    intent_id: row.intent_id ?? null,
    operation: row.operation ?? null,
    amount_cents: row.amount_cents ?? null,
    currency: row.currency ?? null,
    outcome: row.outcome ?? null,
    remaining_cents: row.remaining_cents ?? null,
    reason_codes: row.reason_codes ?? [],
    tool_name: row.tool_name ?? null,
    created_at: row.created_at ?? null,
  };
}

function readLocalPolicyPanel(policyPath: string): Record<string, unknown> {
  const policy: Record<string, unknown> = {
    path: policyPath,
    present: existsSync(policyPath),
    source: "local_file",
  };
  if (existsSync(policyPath)) {
    try {
      const body = readFileSync(policyPath, "utf8");
      policy.bytes = body.length;
      const nameMatch = body.match(/^\s*name:\s*["']?([^"'\n]+)/m);
      const opMatch = body.match(/^\s*operation:\s*["']?([^"'\n]+)/m);
      if (nameMatch?.[1]) {
        policy.name = nameMatch[1].trim();
      }
      if (opMatch?.[1]) {
        policy.operation = opMatch[1].trim();
      }
    } catch {
      // keep present=true with no parse fields
    }
  }
  return policy;
}

async function loadIntents(
  gateway: GatewayClient,
  limit: number,
  limitations: string[],
): Promise<Array<Record<string, unknown>>> {
  try {
    const body = await gateway.getJson(`/harbor/operator/v1/intents?limit=${limit}`);
    return asObjectRows(body, ["intents", "items", "data"])
      .slice(0, limit)
      .map((row) => ({
        intent_id: row.intent_id ?? row.id ?? null,
        status: row.status ?? null,
        amount_cents: row.amount_cents ?? row.amount ?? null,
        created_at: row.created_at ?? null,
      }));
  } catch {
    limitations.push("intents list unavailable (gateway path or RBAC) — need harbor.read / operator");
    return [];
  }
}

async function loadReceipts(
  gateway: GatewayClient,
  limit: number,
  limitations: string[],
): Promise<Array<Record<string, unknown>>> {
  try {
    const body = await gateway.getJson(`/protocol/v2/agent-receipts?limit=${limit}`);
    const rows = asObjectRows(body, ["items", "receipts", "data"]);
    if (rows.length === 0) {
      limitations.push("no agent receipts yet for this tenant");
    }
    return rows.slice(0, limit).map((row) => ({
      receipt_id: row.receipt_id ?? row.id ?? null,
      scope: row.scope ?? null,
      intent_id: row.intent_id ?? null,
      tool_call_id: row.tool_call_id ?? null,
      message_digest_sha256_hex: row.message_digest_sha256_hex ?? null,
      created_at: row.created_at ?? null,
      source: "gateway",
    }));
  } catch {
    limitations.push(
      "receipts list unavailable — need GET /protocol/v2/agent-receipts (harbor.read or harbor.write)",
    );
    return [];
  }
}

async function loadSpendAndDenials(
  gateway: GatewayClient,
  limit: number,
  limitations: string[],
): Promise<{
  spend: Record<string, unknown>;
  denials: Array<Record<string, unknown>>;
}> {
  let decisions: Array<Record<string, unknown>> = [];
  let policy: Record<string, unknown> | null = null;
  let reservations: Array<Record<string, unknown>> = [];
  let decisionsLoaded = false;

  try {
    const body = await gateway.getJson(`/v1/admin/spend-controls/decisions?limit=${limit}`);
    decisions = asObjectRows(body, ["items", "data"]).slice(0, limit).map(mapDecisionRow);
    decisionsLoaded = true;
  } catch {
    limitations.push(
      "spend decisions unavailable — need GET /v1/admin/spend-controls/decisions (harbor.read)",
    );
  }

  try {
    const body = await gateway.getJson("/v1/admin/spend-controls/policy");
    policy = {
      source: body.source ?? "gateway",
      configured: body.configured ?? false,
      mode: body.mode ?? null,
      policy_version: body.policy_version ?? null,
      updated_at: body.updated_at ?? null,
    };
  } catch {
    limitations.push("spend policy unavailable (optional panel enrichment)");
  }

  try {
    const body = await gateway.getJson(
      `/v1/admin/spend-controls/reservations?status=active&limit=${limit}`,
    );
    reservations = asObjectRows(body, ["items", "data"])
      .slice(0, limit)
      .map((row) => ({
        id: row.id ?? null,
        intent_id: row.intent_id ?? null,
        amount_cents: row.amount_cents ?? null,
        currency: row.currency ?? null,
        status: row.status ?? null,
        expires_at: row.expires_at ?? null,
      }));
  } catch {
    // reservations are enrichment only
  }

  const denials = decisions.filter((row) => isDenialOutcome(row.outcome));
  if (decisionsLoaded && decisions.length === 0) {
    limitations.push("no spend authorization decisions yet for this tenant");
  }
  if (denials.length === 0 && decisions.length > 0) {
    limitations.push("no denied spend decisions in the latest page");
  }

  const latestRemaining = decisions.find((row) => typeof row.remaining_cents === "number");
  if (!decisionsLoaded) {
    return {
      spend: {
        ...unavailableSpendPanel("paybond login"),
        next: "paybond doctor --agent",
        policy,
      },
      denials,
    };
  }
  const spend: Record<string, unknown> = {
    source: "gateway",
    decisions,
    active_reservations: reservations,
    policy,
    latest_remaining_cents: latestRemaining?.remaining_cents ?? null,
    note:
      "Budget remaining for a specific intent: paybond spend budget-remaining --intent-id <id> --operation <op> --requested-spend-cents <n>",
  };
  return { spend, denials };
}

function unavailableSpendPanel(next: string): Record<string, unknown> {
  return {
    source: "unavailable",
    decisions: [],
    active_reservations: [],
    policy: null,
    latest_remaining_cents: null,
    next,
  };
}

/**
 * Gather a read-mostly, tenant-scoped control-plane snapshot from live Gateway APIs.
 * Tenant scope comes only from authenticated credentials — never from client-supplied tenant IDs.
 * Unauthenticated / offline sessions return empty panels with an explicit next command.
 */
export async function gatherControlPlaneSnapshot(
  ctx: CliContext,
  options: { policyFile?: string; limit?: number } = {},
): Promise<ControlPlaneSnapshot> {
  const limit = Math.max(1, Math.min(options.limit ?? 10, 50));
  const policyPath = resolve(ctx.cwd, options.policyFile?.trim() || DEV_DEFAULT_POLICY_FILE);
  const limitations: string[] = [];
  const policy = readLocalPolicyPanel(policyPath);

  let tenantId: string | null = null;
  let environment: string | null = null;
  let intents: Array<Record<string, unknown>> = [];
  let receipts: Array<Record<string, unknown>> = [];
  let spend: Record<string, unknown> = unavailableSpendPanel("paybond login");
  let denials: Array<Record<string, unknown>> = [];

  try {
    await withGateway(ctx, async (gateway) => {
      try {
        const principal = await gateway.getJson("/v1/auth/principal");
        tenantId = typeof principal.tenant_id === "string" ? principal.tenant_id : null;
        environment = typeof principal.environment === "string" ? principal.environment : null;
      } catch {
        limitations.push("principal lookup failed; other panels may still work");
      }

      intents = await loadIntents(gateway, limit, limitations);
      receipts = await loadReceipts(gateway, limit, limitations);
      const spendPanels = await loadSpendAndDenials(gateway, limit, limitations);
      spend = spendPanels.spend;
      denials = spendPanels.denials;
      return { data: {} };
    });
  } catch (err) {
    if (err instanceof CliError && err.category === "auth") {
      limitations.push("not authenticated — run paybond login");
      spend = unavailableSpendPanel("paybond login");
    } else {
      limitations.push(
        `gateway panels unavailable: ${err instanceof Error ? err.message : String(err)}`,
      );
      spend = unavailableSpendPanel("paybond doctor");
    }
  }

  return {
    tenant_id: tenantId,
    environment,
    gateway: ctx.globals.gateway,
    trace_url: devTraceUrl(DEV_TRACE_DEFAULT_PORT),
    panels: {
      intents,
      receipts,
      policy,
      spend,
      denials,
    },
    generated_at: new Date().toISOString(),
    limitations,
  };
}
