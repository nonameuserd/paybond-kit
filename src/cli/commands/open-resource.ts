import { DEV_TRACE_DEFAULT_PORT, devTraceUrl } from "../../dev/trace-buffer.js";
import type { CliContext } from "../context.js";
import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import { withNextActions } from "../next-actions.js";
import { CliError, type CommandResult } from "../types.js";

const DEFAULT_CONSOLE_ORIGIN = "http://127.0.0.1:3000";

type OpenResourceKind =
  | "console"
  | "billing"
  | "sso"
  | "scim"
  | "intent"
  | "export"
  | "trace"
  | "compliance-exports"
  | "docs";

type ResolvedOpenTarget = {
  kind: OpenResourceKind;
  url: string;
  purpose: string;
};

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, "");
}

function resolveConsoleOrigin(): string {
  const configured =
    process.env.PAYBOND_CONSOLE_BASE_URL?.trim() ||
    process.env.PAYBOND_PUBLIC_BASE_URL?.trim();
  return stripTrailingSlashes(configured && configured.length > 0 ? configured : DEFAULT_CONSOLE_ORIGIN);
}

function resolveDocsOrigin(): string {
  const configured = process.env.PAYBOND_DOCS_BASE_URL?.trim();
  return stripTrailingSlashes(configured && configured.length > 0 ? configured : "https://paybond.ai/docs");
}

/**
 * Resolve a rare admin deep-link escape hatch. Kit day-to-day work stays in the CLI.
 */
export function resolveOpenTarget(resource: string, id?: string, port?: number): ResolvedOpenTarget {
  const kind = resource.trim().toLowerCase() as OpenResourceKind;
  const consoleOrigin = resolveConsoleOrigin();
  const docsOrigin = resolveDocsOrigin();

  switch (kind) {
    case "console":
      return {
        kind,
        url: `${consoleOrigin}/console`,
        purpose: "Tenant admin console home (billing, SSO/SCIM, operators)",
      };
    case "billing":
      return {
        kind,
        url: `${consoleOrigin}/console/configuration/billing`,
        purpose: "Billing and plan management (console-only)",
      };
    case "sso":
      return {
        kind,
        url: `${consoleOrigin}/console/configuration/identity/sso`,
        purpose: "SSO federation configuration (console-only)",
      };
    case "scim":
      return {
        kind,
        url: `${consoleOrigin}/console/configuration/identity/scim`,
        purpose: "SCIM provisioning configuration (console-only)",
      };
    case "compliance-exports":
      return {
        kind,
        url: `${consoleOrigin}/console/investigations/compliance-exports`,
        purpose: "Compliance export investigation workspace (console)",
      };
    case "docs":
      return {
        kind,
        url: `${docsOrigin}/kit`,
        purpose: "Kit documentation",
      };
    case "trace": {
      const runId = id?.trim();
      return {
        kind,
        url: devTraceUrl(port ?? DEV_TRACE_DEFAULT_PORT, runId || undefined),
        purpose: "Local terminal-native trace dashboard",
      };
    }
    case "intent": {
      const intentId = id?.trim();
      if (!intentId) {
        throw new CliError("open intent requires <intent_id>", {
          category: "usage",
          code: "cli.usage.missing_intent_id",
          details: withNextActions(undefined, {
            what: "missing intent id",
            why: "console intent deep links need a Harbor intent UUID",
            next: "paybond open intent <intent_id>",
          }),
        });
      }
      return {
        kind,
        url: `${consoleOrigin}/console/operations/intents/${encodeURIComponent(intentId)}`,
        purpose: "Intent dossier in console (admin investigation)",
      };
    }
    case "export": {
      const jobId = id?.trim();
      if (!jobId) {
        throw new CliError("open export requires <job_id>", {
          category: "usage",
          code: "cli.usage.missing_job_id",
          details: withNextActions(undefined, {
            what: "missing export job id",
            why: "compliance export deep links need a job id from audit exports list",
            next: "paybond audit exports list --format json",
          }),
        });
      }
      return {
        kind,
        url: `${consoleOrigin}/console/investigations/compliance-exports?job=${encodeURIComponent(jobId)}`,
        purpose: "Compliance export job in console",
      };
    }
    default:
      throw new CliError(
        `unknown open resource: ${resource} (expected console|billing|sso|scim|intent|export|trace|compliance-exports|docs)`,
        {
          category: "usage",
          code: "cli.usage.invalid_open_resource",
          details: withNextActions(undefined, {
            what: "unknown resource",
            why: `${resource} is not a supported deep-link target`,
            next: "paybond open --help",
          }),
        },
      );
  }
}

async function defaultOpenBrowser(url: string): Promise<boolean> {
  const { spawn } = await import("node:child_process");
  const platform = process.platform;
  const command = platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  return await new Promise((resolvePromise) => {
    const child = spawn(command, args, { stdio: "ignore", detached: true });
    child.unref();
    child.on("error", () => resolvePromise(false));
    child.on("exit", (code) => resolvePromise(code === 0));
  });
}

/**
 * Open (or print) a console/admin deep link. Prefer CLI for Kit builder workflows.
 */
export async function handleOpen(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h" || argv.length === 0) {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }

  const portFlag = consumeFlag(argv, "--port");
  const noOpenFlag = consumeBooleanFlag(portFlag.rest, "--no-open");
  const positionals = noOpenFlag.rest.filter((part) => !part.startsWith("-"));
  const unknownFlags = noOpenFlag.rest.filter((part) => part.startsWith("-"));
  if (unknownFlags.length > 0) {
    throw new CliError(`unexpected flag: ${unknownFlags[0]}`, {
      category: "usage",
      code: "cli.usage.unknown_flag",
    });
  }

  const resource = positionals[0];
  const id = positionals[1];
  if (positionals.length > 2) {
    throw new CliError(`unexpected arguments: ${positionals.slice(2).join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }
  if (!resource) {
    throw new CliError("open requires <resource>", {
      category: "usage",
      code: "cli.usage.missing_open_resource",
      details: withNextActions(undefined, {
        what: "missing resource",
        why: "open needs an explicit deep-link target",
        next: "paybond open console",
      }),
    });
  }

  let port: number | undefined;
  if (portFlag.value) {
    port = Number.parseInt(portFlag.value, 10);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      throw new CliError("open --port must be a valid TCP port", {
        category: "usage",
        code: "cli.usage.invalid_port",
      });
    }
  }

  const target = resolveOpenTarget(resource, id, port);
  const warnings: string[] = [];
  const shouldOpen = !ctx.globals.noOpen && !noOpenFlag.present;
  let opened = false;
  if (shouldOpen) {
    const openBrowser = ctx.deps.openBrowser ?? defaultOpenBrowser;
    opened = await openBrowser(target.url);
    if (!opened) {
      warnings.push("browser open failed; copy the URL manually");
    }
  } else {
    warnings.push("browser open skipped (--no-open)");
  }

  return {
    data: {
      resource: target.kind,
      url: target.url,
      purpose: target.purpose,
      opened,
      note: "Console deep links are for rare admin tasks (billing, SSO/SCIM). Prefer paybond status / control / shell for Kit work.",
    },
    warnings: warnings.length ? warnings : undefined,
  };
}

declare const process: {
  env: Record<string, string | undefined>;
  platform: string;
};
