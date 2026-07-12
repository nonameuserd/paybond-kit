import { resolveJsonBody } from "../body.js";
import {
  buildListQueryParams,
  extractNextCursor,
  partialResultsWarning,
} from "../automation.js";
import {
  signHarborCreateRecognitionProof,
  signHarborEvidenceSubmitRecognitionProof,
  signHarborFundRecognitionProof,
  signHarborSettlementConfirmRecognitionProof,
} from "../../agent-recognition.js";
import {
  DEPRECATED_INTENTS_FUND_BODY_WARNING,
  fundBodyShimUsed,
  parseHarborMutationFlags,
  resolveFundPaymentSignatureFromBody,
  resolveHarborRecognition,
} from "../intents-harbor-mutation.js";
import { commandPath, requireConfirmation, type CliContext, withGateway } from "../context.js";
import { withPaybondCli } from "../paybond.js";
import { consumeFlag, parseOptionalNonNegativeInt, parseRequiredNonNegativeInt } from "../globals.js";
import { maskApiKey, redactSensitiveFields } from "../redact.js";
import { CliError, type CommandResult } from "../types.js";

export async function handleKeys(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    if (subcommand === "list") {
      const limitFlag = consumeFlag(argv, "--limit");
      const cursorFlag = consumeFlag(argv, "--cursor");
      const params = buildListQueryParams(limitFlag.value, cursorFlag.value, { limit: "50" });
      const body = await gateway.getJson(`/v1/admin/api-keys?${params.toString()}`);
      const items = Array.isArray(body.items) ? body.items : [];
      const keys = items.map((item) => {
        const row = item as Record<string, unknown>;
        return {
          key_id: String(row.key_id ?? row.id ?? ""),
          key_masked: maskApiKey(`paybond_sk_${String(row.environment ?? "sandbox")}_${String(row.key_id ?? "redacted")}_redacted`),
          role: String(row.service_account_role ?? ""),
          created_at: String(row.created_at ?? ""),
          expires_at: row.expires_at ? String(row.expires_at) : null,
          status: row.revoked_at ? "revoked" : "active",
        };
      });
      const nextCursor = extractNextCursor(body);
      const warnings = partialResultsWarning(nextCursor) ? [partialResultsWarning(nextCursor)!] : undefined;
      const data: Record<string, unknown> = { keys };
      if (nextCursor) {
        data.next_cursor = nextCursor;
      }
      return { data, warnings };
    }
    if (subcommand === "create") {
      const nameFlag = consumeFlag(argv, "--name");
      const roleFlag = consumeFlag(argv, "--role");
      const labelFlag = consumeFlag(argv, "--label");
      if (!nameFlag.value || !roleFlag.value) {
        throw new CliError("keys create requires --name and --role", { category: "usage", code: "cli.usage.missing_args" });
      }
      const body = await gateway.postJson("/v1/admin/api-keys", {
        service_account_name: nameFlag.value,
        service_account_role: roleFlag.value,
        label: labelFlag.value ?? "",
      });
      const item = (body.item ?? {}) as Record<string, unknown>;
      const rawApiKey = typeof body.api_key === "string" ? body.api_key : "";
      const data: Record<string, unknown> = {
        key_id: String(item.key_id ?? item.id ?? ""),
        key_masked: rawApiKey ? maskApiKey(rawApiKey) : maskApiKey(""),
        role: String(item.service_account_role ?? roleFlag.value),
        created_at: String(item.created_at ?? ""),
        status: "active",
      };
      if (rawApiKey) {
        data.api_key = rawApiKey;
      }
      return { data };
    }
    const keyId = argv[0];
    if (!keyId) {
      throw new CliError(`keys ${subcommand} requires <key_id>`, { category: "usage", code: "cli.usage.missing_key_id" });
    }
    if (subcommand === "rotate") {
      requireConfirmation(ctx.globals, "rotate API key");
      const body = await gateway.postJson(`/v1/admin/api-keys/${encodeURIComponent(keyId)}/rotate`);
      const item = (body.item ?? {}) as Record<string, unknown>;
      const rawApiKey = typeof body.api_key === "string" ? body.api_key : "";
      const data: Record<string, unknown> = {
        key_id: String(item.key_id ?? keyId),
        key_masked: rawApiKey ? maskApiKey(rawApiKey) : maskApiKey(""),
        rotated: true,
      };
      if (rawApiKey) {
        data.api_key = rawApiKey;
      }
      return { data };
    }
    if (subcommand === "revoke") {
      requireConfirmation(ctx.globals, "revoke API key");
      await gateway.deleteJson(`/v1/admin/api-keys/${encodeURIComponent(keyId)}`);
      return { data: { key_id: keyId, revoked: true } };
    }
    throw new CliError(`unknown keys subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export async function handleIntents(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  if (subcommand === "create") {
    return handleIntentsCreate(ctx, argv);
  }
  return withGateway(ctx, async (gateway) => {
    if (subcommand === "list") {
      const statusFlag = consumeFlag(argv, "--status");
      const limitFlag = consumeFlag(argv, "--limit");
      const cursorFlag = consumeFlag(argv, "--cursor");
      const params = buildListQueryParams(limitFlag.value, cursorFlag.value);
      if (statusFlag.value) {
        params.set("status", statusFlag.value);
      }
      const body = await gateway.getJson(`/harbor/operator/v1/intents?${params.toString()}`);
      const redacted = redactSensitiveFields(body) as Record<string, unknown>;
      const nextCursor = extractNextCursor(redacted);
      const warnings = partialResultsWarning(nextCursor) ? [partialResultsWarning(nextCursor)!] : undefined;
      if (nextCursor && !redacted.next_cursor) {
        redacted.next_cursor = nextCursor;
      }
      return { data: redacted, warnings };
    }
    const intentId = argv[0];
    if (subcommand === "get") {
      if (!intentId) {
        throw new CliError("intents get requires <intent_id>", { category: "usage", code: "cli.usage.missing_intent_id" });
      }
      const body = await gateway.getJson(`/harbor/operator/v1/intents/${encodeURIComponent(intentId)}`);
      return { data: redactSensitiveFields(body) as Record<string, unknown> };
    }
    if (!intentId) {
      throw new CliError(`intents ${subcommand} requires <intent_id>`, { category: "usage", code: "cli.usage.missing_intent_id" });
    }
    if (subcommand === "fund") {
      return handleIntentsFund(ctx, intentId, argv.slice(1));
    }
    if (subcommand === "evidence") {
      return handleIntentsEvidence(ctx, intentId, argv.slice(1));
    }
    if (subcommand === "settlement-confirm") {
      return handleIntentsSettlementConfirm(ctx, intentId, argv);
    }
    throw new CliError(`unknown intents subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

async function handleIntentsCreate(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const flags = parseHarborMutationFlags(argv);
  const { payload } = await resolveJsonBody(flags.restArgv, {
    missingMessage: "intents create requires --body <json-file> or --stdin",
  });
  const body = payload ?? {};

  return withPaybondCli(ctx, async (session) => {
    const recognition = await resolveHarborRecognition(ctx, flags);
    const recognitionProof = signHarborCreateRecognitionProof({
      tenantId: session.paybond.harbor.tenantId,
      intentBody: body,
      keyId: recognition.agentRecognitionKeyId,
      signingSeed: recognition.agentRecognitionSigningSeed,
    });
    const result = await session.paybond.harbor.createIntent(body, {
      recognitionProof,
      idempotencyKey: flags.idempotencyKey?.trim(),
    });
    return {
      data: redactSensitiveFields(result) as Record<string, unknown>,
      warnings: session.warnings.length ? session.warnings : undefined,
    };
  });
}

async function handleIntentsEvidence(
  ctx: CliContext,
  intentId: string,
  argv: string[],
): Promise<CommandResult> {
  const flags = parseHarborMutationFlags(argv);
  const { payload } = await resolveJsonBody(flags.restArgv, {
    missingMessage: "intents evidence requires --body <json-file> or --stdin",
  });
  const body = payload ?? {};

  return withPaybondCli(ctx, async (session) => {
    const recognition = await resolveHarborRecognition(ctx, flags);
    const recognitionProof = signHarborEvidenceSubmitRecognitionProof({
      tenantId: session.paybond.harbor.tenantId,
      intentId,
      evidenceBody: body,
      keyId: recognition.agentRecognitionKeyId,
      signingSeed: recognition.agentRecognitionSigningSeed,
    });
    const result = await session.paybond.harbor.submitEvidence(intentId, body, {
      recognitionProof,
      idempotencyKey: flags.idempotencyKey?.trim(),
    });
    return {
      data: redactSensitiveFields(result) as Record<string, unknown>,
      warnings: session.warnings.length ? session.warnings : undefined,
    };
  });
}

async function handleIntentsFund(
  ctx: CliContext,
  intentId: string,
  argv: string[],
): Promise<CommandResult> {
  const flags = parseHarborMutationFlags(argv);
  const paymentSignatureFlag = consumeFlag(flags.restArgv, "--payment-signature");
  let paymentSignature = paymentSignatureFlag.value?.trim() || undefined;
  const deprecationWarnings: string[] = [];
  const bodyShimUsed = fundBodyShimUsed(paymentSignatureFlag.rest);

  const { payload } = await resolveJsonBody(paymentSignatureFlag.rest, { required: false });
  if (bodyShimUsed) {
    deprecationWarnings.push(DEPRECATED_INTENTS_FUND_BODY_WARNING);
    if (!paymentSignature) {
      paymentSignature = resolveFundPaymentSignatureFromBody(payload);
    }
  }

  return withPaybondCli(ctx, async (session) => {
    const recognition = await resolveHarborRecognition(ctx, flags);
    const recognitionProof = signHarborFundRecognitionProof({
      tenantId: session.paybond.harbor.tenantId,
      intentId,
      keyId: recognition.agentRecognitionKeyId,
      signingSeed: recognition.agentRecognitionSigningSeed,
    });
    const result = await session.paybond.harbor.fundIntent(intentId, {
      recognitionProof,
      paymentSignature,
      idempotencyKey: flags.idempotencyKey?.trim(),
    });
    const warnings = [...session.warnings, ...deprecationWarnings];
    return {
      data: redactSensitiveFields(result) as Record<string, unknown>,
      warnings: warnings.length ? warnings : undefined,
    };
  });
}

async function handleIntentsSettlementConfirm(
  ctx: CliContext,
  intentId: string,
  argv: string[],
): Promise<CommandResult> {
  const flags = parseHarborMutationFlags(argv);
  const { payload } = await resolveJsonBody(flags.restArgv, { required: false });

  return withPaybondCli(ctx, async (session) => {
    const recognition = await resolveHarborRecognition(ctx, flags);
    const body = payload ?? {};
    const recognitionProof = signHarborSettlementConfirmRecognitionProof({
      tenantId: session.paybond.harbor.tenantId,
      intentId,
      body,
      keyId: recognition.agentRecognitionKeyId,
      signingSeed: recognition.agentRecognitionSigningSeed,
    });
    const result = await session.paybond.intents.confirmSettlement({
      intentId,
      body,
      recognitionProof,
      idempotencyKey: flags.idempotencyKey?.trim(),
    });
    return {
      data: redactSensitiveFields(result) as Record<string, unknown>,
      warnings: session.warnings.length ? session.warnings : undefined,
    };
  });
}

export async function handleGuardrails(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    if (subcommand === "bootstrap") {
      const operationFlag = consumeFlag(argv, "--operation");
      const spendFlag = consumeFlag(argv, "--requested-spend-cents");
      const presetFlag = consumeFlag(argv, "--completion-preset");
      if (!operationFlag.value || !spendFlag.value) {
        throw new CliError(
          "guardrails bootstrap requires --operation and --requested-spend-cents",
          { category: "usage", code: "cli.usage.missing_args" },
        );
      }
      const spendCents = parseRequiredNonNegativeInt(spendFlag.value, "--requested-spend-cents");
      const bodyPayload: Record<string, unknown> = {
        operation: operationFlag.value,
        requested_spend_cents: spendCents,
      };
      if (presetFlag.value) {
        bodyPayload.completion_preset = presetFlag.value;
      }
      const body = await gateway.postJson("/v1/sandbox/guardrails/bootstrap", bodyPayload);
      return {
        data: redactSensitiveFields({
          tenant_id: String(body.tenant_id ?? ""),
          intent_id: String(body.intent_id ?? ""),
          capability_token: String(body.capability_token ?? ""),
          operation: String(body.operation ?? operationFlag.value),
          requested_spend_cents: Number(body.requested_spend_cents ?? spendCents),
          sandbox_lifecycle_status: String(body.sandbox_lifecycle_status ?? ""),
        }) as Record<string, unknown>,
      };
    }
    if (subcommand === "evidence") {
      const intentFlag = consumeFlag(argv, "--intent-id");
      if (!intentFlag.value) {
        throw new CliError(
          "guardrails evidence requires --intent-id and --body <json-file>",
          { category: "usage", code: "cli.usage.missing_args" },
        );
      }
      const { payload } = await resolveJsonBody(argv, {
        missingMessage: "guardrails evidence requires --intent-id and --body <json-file> or --stdin",
      });
      const body = await gateway.postJson(`/v1/sandbox/guardrails/${encodeURIComponent(intentFlag.value)}/evidence`, payload);
      return { data: body };
    }
    throw new CliError(`unknown guardrails subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export async function handleSpendAuthorize(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    const intentFlag = consumeFlag(argv, "--intent-id");
    const tokenFlag = consumeFlag(argv, "--token");
    const operationFlag = consumeFlag(argv, "--operation");
    const spendFlag = consumeFlag(argv, "--requested-spend-cents");
    if (!intentFlag.value || !tokenFlag.value || !operationFlag.value) {
      throw new CliError(
        "spend authorize requires --intent-id, --token, and --operation",
        { category: "usage", code: "cli.usage.missing_args" },
      );
    }
    const spendCents = parseOptionalNonNegativeInt(spendFlag.value, "--requested-spend-cents");
    const body = await gateway.postJson("/verify", {
      intent_id: intentFlag.value,
      token: tokenFlag.value,
      operation: operationFlag.value,
      requested_spend_cents: spendCents,
    });
    return {
      data: {
        authorized: Boolean(body.allow),
        intent_id: String(body.intent_id ?? intentFlag.value),
        operation: operationFlag.value,
        requested_spend_cents: spendCents,
        deny_reason: body.allow ? undefined : String(body.message ?? body.code ?? "denied"),
      },
    };
  });
}

function parseSpendPreflightCliArgs(argv: string[]): {
  intentId: string;
  operation: string;
  requestedSpendCents: number;
  payload: Record<string, unknown>;
  rest: string[];
} {
  const intentFlag = consumeFlag(argv, "--intent-id");
  const operationFlag = consumeFlag(intentFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const vendorFlag = consumeFlag(spendFlag.rest, "--vendor-id");
  const toolFlag = consumeFlag(vendorFlag.rest, "--tool-name");
  const taskFlag = consumeFlag(toolFlag.rest, "--task-id");
  const workflowFlag = consumeFlag(taskFlag.rest, "--workflow-id");
  const toolCallFlag = consumeFlag(workflowFlag.rest, "--tool-call-id");
  const currencyFlag = consumeFlag(toolCallFlag.rest, "--currency");
  const agentFlag = consumeFlag(currencyFlag.rest, "--agent-subject");
  const approvalFlag = consumeFlag(agentFlag.rest, "--approval-token");
  if (!intentFlag.value) {
    throw new CliError("spend preflight requires --intent-id", {
      category: "usage",
      code: "cli.usage.missing_args",
    });
  }
  const operation = operationFlag.value?.trim() || "*";
  const spendCents = parseOptionalNonNegativeInt(spendFlag.value, "--requested-spend-cents");
  const payload: Record<string, unknown> = {
    intent_id: intentFlag.value,
    operation,
    requested_spend_cents: spendCents,
  };
  if (vendorFlag.value) {
    payload.vendor_id = vendorFlag.value;
  }
  if (toolFlag.value) {
    payload.tool_name = toolFlag.value;
  }
  if (taskFlag.value) {
    payload.task_id = taskFlag.value;
  }
  if (workflowFlag.value) {
    payload.workflow_id = workflowFlag.value;
  }
  if (toolCallFlag.value) {
    payload.tool_call_id = toolCallFlag.value;
  }
  if (currencyFlag.value) {
    payload.currency = currencyFlag.value;
  }
  if (agentFlag.value) {
    payload.agent_subject = agentFlag.value;
  }
  if (approvalFlag.value) {
    payload.approval_token = approvalFlag.value;
  }
  return {
    intentId: intentFlag.value,
    operation,
    requestedSpendCents: spendCents,
    payload,
    rest: approvalFlag.rest,
  };
}

function normalizeExplainPolicyOutcome(
  outcome: string,
  classification: string,
): "allow" | "approval_required" | "deny" {
  const normalized = outcome.trim().toLowerCase();
  if (normalized === "allow" || normalized === "anomaly_observe") {
    return "allow";
  }
  if (normalized === "approval_required" || normalized === "anomaly_escalate") {
    return "approval_required";
  }
  if (normalized === "deny") {
    return "deny";
  }
  const classNorm = classification.trim().toLowerCase();
  if (classNorm === "allow") {
    return "allow";
  }
  if (classNorm === "hold") {
    return "approval_required";
  }
  return "deny";
}

export async function handleSpendBudgetRemaining(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    const parsed = parseSpendPreflightCliArgs(argv);
    const body = await gateway.postJson("/v1/spend/preflight", parsed.payload);
    return {
      data: {
        remaining_cents: body.remaining_cents ?? null,
        spend_scope: body.spend_scope ?? null,
        policy_version: body.policy_version ?? null,
        intent_id: parsed.intentId,
        operation: parsed.operation,
        requested_spend_cents: parsed.requestedSpendCents,
      },
    };
  });
}

export async function handleSpendExplainPolicy(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    const parsed = parseSpendPreflightCliArgs(argv);
    const body = await gateway.postJson("/v1/spend/preflight", parsed.payload);
    const reasonCodes = Array.isArray(body.reason_codes)
      ? body.reason_codes.map((code: unknown) => String(code))
      : [];
    const outcome = normalizeExplainPolicyOutcome(
      String(body.outcome ?? ""),
      String(body.classification ?? ""),
    );
    return {
      data: {
        outcome,
        reason_codes: reasonCodes,
        explanation: String(body.explanation ?? ""),
        remaining_cents: body.remaining_cents ?? null,
        approval_threshold_exceeded:
          reasonCodes.includes("approval_threshold_exceeded") || outcome === "approval_required"
            ? reasonCodes.includes("approval_threshold_exceeded")
            : undefined,
        intent_id: parsed.intentId,
        operation: parsed.operation,
        requested_spend_cents: parsed.requestedSpendCents,
      },
    };
  });
}

export { commandPath };
