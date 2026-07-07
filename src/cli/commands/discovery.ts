import { resolveJsonBody } from "../body.js";
import { verifyAuditBundleLocal } from "../../audit/verify.js";
import { PaybondAuditExports } from "../../audit/exports.js";
import {
  buildListQueryParams,
  extractNextCursor,
  partialResultsWarning,
  writeAtomicFileAsync,
} from "../automation.js";
import { commandPath, gatewayUrl, requireConfirmation, type CliContext, withGateway } from "../context.js";
import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import { CliError, type CommandResult } from "../types.js";

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
    const kindFlag = consumeFlag(argv, "--kind");
    const kind = (kindFlag.value ?? "protocol").trim().toLowerCase();
    const receiptId = argv[0];
    if (!receiptId) {
      throw new CliError(`receipts ${subcommand} requires <receipt_id>`, { category: "usage", code: "cli.usage.missing_receipt_id" });
    }
    if (kind === "agent") {
      if (subcommand === "get") {
        const body = await gateway.getJson(`/protocol/v2/agent-receipts/${encodeURIComponent(receiptId)}`);
        return { data: body };
      }
      if (subcommand === "verify") {
        const fetched = await gateway.getJson(`/protocol/v2/agent-receipts/${encodeURIComponent(receiptId)}`);
        const body = await gateway.postJson("/protocol/v2/agent-receipts/verify", fetched);
        return { data: body };
      }
    }
    if (subcommand === "get") {
      const body = await gateway.getJson(`/protocol/v2/receipts/${encodeURIComponent(receiptId)}`);
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
          });
        }
        const bytes = new Uint8Array(await response.arrayBuffer());
        await writeAtomicFileAsync(outputFlag.value, bytes, 0o600);
        return {
          data: {
            job_id: jobId,
            output: outputFlag.value,
            bytes_written: bytes.byteLength,
          },
        };
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
