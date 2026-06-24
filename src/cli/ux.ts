import { access } from "node:fs/promises";
import path from "node:path";

import { COMMAND_EXAMPLES, COMPLETION_SCRIPTS, WORKFLOWS } from "./command-spec.js";
import type { CliContext } from "./context.js";
import { resolvedDefaultsForDoctor } from "./credentials.js";
import { helpForCommand } from "./help.js";
import { consumeFlag } from "./globals.js";
import { planMcpInstall, parseMcpInstallFormat, parseMcpInstallHost, parseMcpInstallScope } from "./mcp-install.js";
import { CliError, type CommandResult } from "./types.js";
import { handleDoctor } from "./commands/setup.js";

export function resolveHelpPath(argv: string[]): string {
  return argv.filter((part) => part !== "--help" && part !== "-h").join(" ");
}

export function renderHelpText(path: string): string {
  return helpForCommand(path);
}

export function handleHelpCommand(argv: string[]): CommandResult {
  const helpPath = resolveHelpPath(argv);
  return { data: { text: renderHelpText(helpPath), path: helpPath || "paybond" } };
}

export function handleExamplesCommand(argv: string[]): CommandResult {
  const filterPath = argv.filter((part) => part !== "--help" && part !== "-h").join(" ");
  const lines: string[] = [];
  if (!filterPath) {
    lines.push("Workflows:");
    for (const workflow of WORKFLOWS) {
      lines.push("", workflow.title);
      if (workflow.description) {
        lines.push(workflow.description);
      }
      for (const example of workflow.examples) {
        lines.push(`  $ ${example}`);
      }
      if (workflow.next) {
        lines.push(`  Next: ${workflow.next}`);
      }
    }
    lines.push("", "Commands:");
  }

  const entries = filterPath
    ? Object.entries(COMMAND_EXAMPLES).filter(([commandPath]) => commandPath === filterPath || commandPath.startsWith(`${filterPath} `))
    : Object.entries(COMMAND_EXAMPLES);

  if (filterPath && entries.length === 0) {
    throw new CliError(`no examples found for: ${filterPath}`, {
      category: "usage",
      code: "cli.usage.unknown_command",
    });
  }

  for (const [commandPath, examples] of entries) {
    lines.push("", `paybond ${commandPath}`);
    for (const example of examples) {
      lines.push(`  $ ${example}`);
    }
  }

  return { data: { text: lines.join("\n").trim(), filter: filterPath || null, count: entries.length } };
}

export function handleCompletionCommand(argv: string[]): CommandResult {
  const shell = argv[0];
  if (!shell || shell === "--help" || shell === "-h") {
    throw new CliError("completion requires bash|zsh|fish", {
      category: "usage",
      code: "cli.usage.missing_completion_shell",
    });
  }
  const script = COMPLETION_SCRIPTS[shell as keyof typeof COMPLETION_SCRIPTS];
  if (!script) {
    throw new CliError(`unsupported completion shell: ${shell} (expected bash|zsh|fish)`, {
      category: "usage",
      code: "cli.usage.invalid_completion_shell",
    });
  }
  return { data: { shell, script } };
}

export async function handleOnboarding(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const hostFlag = consumeFlag(argv, "--host");
  let installHost: ReturnType<typeof parseMcpInstallHost> = "generic";
  try {
    if (hostFlag.present) {
      installHost = parseMcpInstallHost(hostFlag.value);
    }
  } catch (err) {
    throw new CliError(err instanceof Error ? err.message : String(err), {
      category: "usage",
      code: "cli.usage.invalid_mcp_install",
    });
  }

  const steps: Array<{ name: string; ok: boolean; message: string; command?: string }> = [];
  steps.push({
    name: "runtime",
    ok: true,
    message: `node ${process.version}`,
  });

  const defaults = resolvedDefaultsForDoctor(ctx.globals);
  const envPath = path.isAbsolute(defaults.envFile)
    ? path.resolve(defaults.envFile)
    : path.resolve(ctx.cwd, defaults.envFile);
  let loggedIn = false;
  try {
    const { resolveApiKey } = await import("./credentials.js");
    const apiKey = await resolveApiKey(ctx.globals, ctx.cwd);
    loggedIn = true;
    const { maskApiKey } = await import("./redact.js");
    steps.push({
      name: "login",
      ok: true,
      message: `credentials found (${maskApiKey(apiKey)})`,
    });
  } catch (err) {
    steps.push({
      name: "login",
      ok: false,
      message: err instanceof Error ? err.message : String(err),
      command: "paybond login",
    });
  }

  const guardrailPath = path.resolve(ctx.cwd, "paybond-paid-tool-guard.ts");
  let guardrailExists = false;
  try {
    await access(guardrailPath);
    guardrailExists = true;
  } catch {
    guardrailExists = false;
  }
  steps.push({
    name: "guardrail",
    ok: guardrailExists,
    message: guardrailExists ? `found ${guardrailPath}` : `guardrail file not found (${guardrailPath})`,
    command: guardrailExists ? undefined : "paybond init guardrail",
  });

  const plan = planMcpInstall({
    host: installHost,
    scope: parseMcpInstallScope("local"),
    format: parseMcpInstallFormat(undefined, installHost),
    envFile: defaults.envFile,
    cwd: ctx.cwd,
    home: process.env.HOME ?? process.env.USERPROFILE ?? ctx.cwd,
  });
  steps.push({
    name: "mcp_config",
    ok: true,
    message: `preview ready for host=${plan.host} (non-destructive --scope local)`,
    command: `paybond mcp install --host ${plan.host} --scope local`,
  });

  const doctor = await handleDoctor(ctx, loggedIn ? ["--agent"] : []);
  const doctorOk = String(doctor.data.summary) === "pass";
  steps.push({
    name: "doctor",
    ok: doctorOk,
    message: `doctor ${doctor.data.summary}`,
    command: doctorOk ? undefined : "paybond doctor --agent",
  });

  const summary = steps.every((step) => step.ok) ? "pass" : "fail";
  return {
    data: {
      steps,
      summary,
      env_file: envPath,
      mcp_preview: plan.printed ? plan.payload : undefined,
      doctor_checks: doctor.data.checks,
    },
  };
}

declare const process: { version: string; env: Record<string, string | undefined> };
