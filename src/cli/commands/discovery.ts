import { resolveJsonBody } from "../body.js";
import { verifyAuditBundleLocal } from "../../audit/verify.js";
import { PaybondAuditExports } from "../../audit/exports.js";
import type { AuditExportCreateFilter } from "../../audit/wire.js";
import {
  buildListQueryParams,
  extractNextCursor,
  partialResultsWarning,
  writeAtomicFileAsync,
} from "../automation.js";
import { commandPath, gatewayUrl, requireConfirmation, type CliContext, withGateway } from "../context.js";
import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import { withNextActions } from "../next-actions.js";
import { CliError, type CommandResult } from "../types.js";

const TERMINAL_EXPORT_STATUSES = new Set(["ready", "failed", "expired", "deleted"]);

async function pollAuditExportJob(
  ctx: CliContext,
  exportsClient: PaybondAuditExports,
  jobId: string,
  options: { timeoutMs: number; intervalMs: number; humanProgress: boolean },
): Promise<Record<string, unknown>> {
  const sleep = ctx.deps.sleep ?? ((ms: number) => new Promise((resolve) => setTimeout(resolve, ms)));
  const now = ctx.deps.now ?? Date.now;
  const deadline = now() + options.timeoutMs;
  let lastStatus = "";
  while (now() < deadline) {
    const body = await exportsClient.get(jobId);
    const status = String(body.job.status ?? "");
    if (options.humanProgress && status !== lastStatus) {
      ctx.stderr.write(`audit export ${jobId}: ${status}\n`);
      lastStatus = status;
    }
    if (TERMINAL_EXPORT_STATUSES.has(status)) {
      return body as unknown as Record<string, unknown>;
    }
    await sleep(options.intervalMs);
  }
  throw new CliError(`audit export ${jobId} did not become ready before timeout`, {
    category: "gateway",
    code: "cli.audit.export_timeout",
    exitCode: 5,
    details: withNextActions(
      { job_id: jobId },
      {
        what: "export still processing",
        why: "gateway job did not reach a terminal status in time",
        next: `paybond audit exports get ${jobId} --format json`,
      },
    ),
  });
}

export async function handleSignal(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    if (subcommand === "portfolio") {
      const body = await gateway.getJson("/signal/v1/portfolio/summary");
      return { data: body };
    }
    const didFlag = consumeFlag(argv, "--did");
    if (!didFlag.value) {
      throw new CliError(`signal ${subcommand} requires --did`, { category: "usage", code: "cli.usage.missing_did" });
    }
    if (subcommand === "reputation") {
      const body = await gateway.getJson(`/reputation/${encodeURIComponent(didFlag.value)}`);
      return { data: body };
    }
    if (subcommand === "fraud") {
      const body = await gateway.getJson(
        `/signal/v1/operators/${encodeURIComponent(didFlag.value)}/review-status`,
      );
      return { data: body };
    }
    throw new CliError(`unknown signal subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export async function handleReceipts(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    // <receipt_id> is a positional SHA-256 digest the caller must already have. Most callers only
    // know the intent_id and (for action receipts) tool_call_id from their own request, so agent
    // receipts also resolve by --intent-id [--tool-call-id] without forcing callers to derive the
    // digest themselves (Gateway's GET /protocol/v2/agent-receipts query endpoint).
    const hasReceiptId = argv.length > 0 && !argv[0].startsWith("-");
    const receiptId = hasReceiptId ? argv[0] : undefined;
    const flagArgv = hasReceiptId ? argv.slice(1) : argv;
    const kindFlag = consumeFlag(flagArgv, "--kind");
    const kind = (kindFlag.value ?? "protocol").trim().toLowerCase();
    const intentIdFlag = consumeFlag(kindFlag.rest, "--intent-id");
    const toolCallIdFlag = consumeFlag(intentIdFlag.rest, "--tool-call-id");
    const intentId = intentIdFlag.value;
    const toolCallId = toolCallIdFlag.value;

    if (toolCallId && !intentId) {
      throw new CliError(`receipts ${subcommand} --tool-call-id requires --intent-id`, {
        category: "usage",
        code: "cli.usage.tool_call_id_requires_intent_id",
      });
    }
    if (!receiptId && !intentId) {
      throw new CliError(`receipts ${subcommand} requires <receipt_id> or --intent-id <id>`, {
        category: "usage",
        code: "cli.usage.missing_receipt_id",
      });
    }
    if (intentId && kind !== "agent") {
      throw new CliError(`receipts ${subcommand} --intent-id is only supported with --kind agent`, {
        category: "usage",
        code: "cli.usage.intent_id_requires_agent_kind",
      });
    }

    if (kind === "agent") {
      let path: string;
      if (receiptId) {
        path = `/protocol/v2/agent-receipts/${encodeURIComponent(receiptId)}`;
      } else {
        path = `/protocol/v2/agent-receipts?intent_id=${encodeURIComponent(intentId as string)}`;
        if (toolCallId) {
          path += `&tool_call_id=${encodeURIComponent(toolCallId)}`;
        }
      }
      if (subcommand === "get") {
        const body = await gateway.getJson(path);
        return { data: body };
      }
      if (subcommand === "verify") {
        const fetched = await gateway.getJson(path);
        const body = await gateway.postJson("/protocol/v2/agent-receipts/verify", fetched);
        return { data: body };
      }
    }
    if (subcommand === "get") {
      const body = await gateway.getJson(`/protocol/v2/receipts/${encodeURIComponent(receiptId as string)}`);
      return { data: body };
    }
    if (subcommand === "verify") {
      const body = await gateway.postJson("/protocol/v2/receipts/verify", { receipt_id: receiptId });
      return { data: body };
    }
    throw new CliError(`unknown receipts subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export async function handleMandates(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    const { payload } = await resolveJsonBody(argv, {
      missingMessage: `mandates ${subcommand} requires --body <json-file> or --stdin`,
    });
    if (subcommand === "verify") {
      const body = await gateway.postJson("/protocol/v2/mandates/verify", payload);
      return { data: body };
    }
    if (subcommand === "import") {
      const body = await gateway.postJson("/protocol/v2/mandates", payload);
      return { data: body };
    }
    throw new CliError(`unknown mandates subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export async function handleA2a(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  return withGateway(ctx, async (gateway) => {
    if (subcommand === "card") {
      const body = await gateway.getJson("/.well-known/agent-card.json");
      return { data: body };
    }
    if (subcommand === "contracts") {
      const contractFlag = consumeFlag(argv, "--contract-id");
      if (contractFlag.value) {
        const body = await gateway.getJson(`/protocol/v2/a2a/task-contracts/${encodeURIComponent(contractFlag.value)}`);
        return { data: body };
      }
      const limitFlag = consumeFlag(argv, "--limit");
      const cursorFlag = consumeFlag(argv, "--cursor");
      const params = buildListQueryParams(limitFlag.value, cursorFlag.value);
      const body = await gateway.getJson(`/protocol/v2/a2a/task-contracts?${params.toString()}`);
      const nextCursor = extractNextCursor(body);
      const warnings = partialResultsWarning(nextCursor) ? [partialResultsWarning(nextCursor)!] : undefined;
      if (nextCursor && !body.next_cursor) {
        body.next_cursor = nextCursor;
      }
      return { data: body, warnings };
    }
    throw new CliError(`unknown a2a subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

async function downloadAuditExportBundle(
  ctx: CliContext,
  gateway: { /* marker */ },
  jobId: string,
  token: string,
  outputPath: string,
): Promise<{ job_id: string; output: string; bytes_written: number }> {
  void gateway;
  const bundleUrl = gatewayUrl(
    ctx.globals.gateway,
    `/v1/compliance/audit-exports/${encodeURIComponent(jobId)}/bundle`,
  );
  const response = await ctx.fetch(bundleUrl, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "x-request-id": ctx.globals.requestId,
    },
  });
  if (!response.ok) {
    throw new CliError(`failed to download audit export bundle (${response.status})`, {
      category: "gateway",
      code: "cli.audit.bundle_download_failed",
      exitCode: 5,
      details: withNextActions(
        { job_id: jobId, gateway_status: response.status },
        {
          what: "bundle download failed",
          why: `gateway returned HTTP ${response.status}`,
          next: `paybond audit exports get ${jobId} --issue-download --format json`,
        },
      ),
    });
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  await writeAtomicFileAsync(outputPath, bytes, 0o600);
  return { job_id: jobId, output: outputPath, bytes_written: bytes.byteLength };
}

export async function handleAuditExports(ctx: CliContext, subcommand: string, argv: string[]): Promise<CommandResult> {
  if (subcommand === "verify") {
    const path = argv[0];
    if (!path) {
      throw new CliError("audit exports verify requires <path>", { category: "usage", code: "cli.usage.missing_path" });
    }
    try {
      const data = await verifyAuditBundleLocal(path, ctx.cwd);
      return { data };
    } catch (err) {
      if (err instanceof CliError) {
        throw err;
      }
      throw new CliError(err instanceof Error ? err.message : String(err), {
        category: "validation",
        code: "cli.audit.verify_failed",
      });
    }
  }
  return withGateway(ctx, async (gateway) => {
    const exportsClient = PaybondAuditExports.fromGateway(gateway);
    if (subcommand === "list") {
      const limitFlag = consumeFlag(argv, "--limit");
      const cursorFlag = consumeFlag(argv, "--cursor");
      const page = await exportsClient.list({
        limit: limitFlag.value ? Number.parseInt(limitFlag.value, 10) : undefined,
        cursor: cursorFlag.value,
      });
      const warnings = partialResultsWarning(page.next_cursor)
        ? [partialResultsWarning(page.next_cursor)!]
        : undefined;
      const data: Record<string, unknown> = {
        exports: page.jobs.map((item) => ({
          job_id: item.id,
          status: item.status,
          created_at: item.created_at,
          expires_at: item.expires_at,
        })),
      };
      if (page.next_cursor) {
        data.next_cursor = page.next_cursor;
      }
      return { data, warnings };
    }
    if (subcommand === "create") {
      const timeStart = consumeFlag(argv, "--time-start");
      const timeEnd = consumeFlag(timeStart.rest, "--time-end");
      const intentId = consumeFlag(timeEnd.rest, "--intent-id");
      const caseId = consumeFlag(intentId.rest, "--case-id");
      const operatorDid = consumeFlag(caseId.rest, "--operator-did");
      const includesFlag = consumeFlag(operatorDid.rest, "--includes");
      const disclosureTier = consumeFlag(includesFlag.rest, "--disclosure-tier");
      const retentionHours = consumeFlag(disclosureTier.rest, "--retention-hours");
      const waitFlag = consumeBooleanFlag(retentionHours.rest, "--wait");
      const outputFlag = consumeFlag(waitFlag.rest, "--output");
      const timeoutFlag = consumeFlag(outputFlag.rest, "--timeout-seconds");
      if (timeoutFlag.rest.length > 0) {
        throw new CliError(`unexpected arguments: ${timeoutFlag.rest.join(" ")}`, {
          category: "usage",
          code: "cli.usage.unexpected_args",
        });
      }

      const filter: AuditExportCreateFilter = {
        ...(timeStart.value ? { time_start: timeStart.value } : {}),
        ...(timeEnd.value ? { time_end: timeEnd.value } : {}),
        ...(intentId.value ? { intent_id: intentId.value } : {}),
        ...(caseId.value ? { case_id: caseId.value } : {}),
        ...(operatorDid.value ? { operator_did: operatorDid.value } : {}),
        ...(includesFlag.value
          ? {
              includes: includesFlag.value
                .split(",")
                .map((part) => part.trim())
                .filter((part) => part.length > 0),
            }
          : {}),
      };

      const tierRaw = (disclosureTier.value ?? "standard").trim().toLowerCase();
      if (tierRaw !== "standard" && tierRaw !== "extended") {
        throw new CliError("audit exports create --disclosure-tier must be standard|extended", {
          category: "usage",
          code: "cli.usage.invalid_disclosure_tier",
        });
      }

      let retention: number | undefined;
      if (retentionHours.value) {
        retention = Number.parseInt(retentionHours.value, 10);
        if (!Number.isFinite(retention) || retention < 1) {
          throw new CliError("audit exports create --retention-hours must be a positive integer", {
            category: "usage",
            code: "cli.usage.invalid_retention_hours",
          });
        }
      }

      const humanProgress = ctx.globals.format !== "json";
      if (humanProgress) {
        ctx.stderr.write("Creating compliance audit export (tenant-scoped from credentials)...\n");
      }
      const created = await exportsClient.create({
        filter,
        disclosureTier: tierRaw,
        retentionHours: retention,
      });
      let jobBody = created as unknown as Record<string, unknown>;
      const jobId = String(created.job.id);
      if (waitFlag.present || outputFlag.value) {
        const timeoutSeconds = timeoutFlag.value ? Number.parseInt(timeoutFlag.value, 10) : 120;
        if (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 1) {
          throw new CliError("audit exports create --timeout-seconds must be a positive integer", {
            category: "usage",
            code: "cli.usage.invalid_timeout",
          });
        }
        jobBody = await pollAuditExportJob(ctx, exportsClient, jobId, {
          timeoutMs: timeoutSeconds * 1000,
          intervalMs: 2000,
          humanProgress,
        });
      }

      if (outputFlag.value) {
        const ready = await exportsClient.get(jobId, { issueDownload: true });
        const token = String(ready.job.download_token ?? "");
        if (!token) {
          throw new CliError("audit exports create --output requires a ready export download token", {
            category: "validation",
            code: "cli.audit.missing_download_token",
            details: withNextActions(
              { job_id: jobId },
              {
                what: "export not downloadable",
                why: "job is not ready or download token was not issued",
                next: `paybond audit exports get ${jobId} --issue-download --output ./bundle.zip`,
              },
            ),
          });
        }
        if (humanProgress) {
          ctx.stderr.write(`Downloading bundle to ${outputFlag.value}...\n`);
        }
        const downloaded = await downloadAuditExportBundle(ctx, gateway, jobId, token, outputFlag.value);
        return {
          data: {
            ...(ready as unknown as Record<string, unknown>),
            ...downloaded,
            waited: waitFlag.present || Boolean(outputFlag.value),
          },
        };
      }

      return {
        data: {
          ...jobBody,
          waited: waitFlag.present,
          next_commands: [
            `paybond audit exports get ${jobId} --format json`,
            `paybond audit exports get ${jobId} --issue-download --output ./paybond-audit-bundle.zip`,
            `paybond audit exports verify ./paybond-audit-bundle.zip`,
          ],
        },
      };
    }

    const jobId = argv[0];
    if (!jobId) {
      throw new CliError(`audit exports ${subcommand} requires <job_id>`, { category: "usage", code: "cli.usage.missing_job_id" });
    }
    if (subcommand === "get") {
      const issueDownload = consumeBooleanFlag(argv.slice(1), "--issue-download").present;
      const outputFlag = consumeFlag(argv.slice(1), "--output");
      const body = await exportsClient.get(jobId, { issueDownload });
      if (outputFlag.value) {
        const token = String(body.job.download_token ?? "");
        if (!token) {
          throw new CliError("audit exports get --output requires a ready export with --issue-download", {
            category: "validation",
            code: "cli.audit.missing_download_token",
          });
        }
        const downloaded = await downloadAuditExportBundle(ctx, gateway, jobId, token, outputFlag.value);
        return { data: downloaded };
      }
      return { data: body as unknown as Record<string, unknown> };
    }
    if (subcommand === "delete") {
      requireConfirmation(ctx.globals, "delete audit export job");
      const data = await exportsClient.delete(jobId);
      return { data };
    }
    throw new CliError(`unknown audit exports subcommand: ${subcommand}`, { category: "usage", code: "cli.usage.unknown_command" });
  });
}

export { commandPath };
