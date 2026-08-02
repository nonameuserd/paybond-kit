import { createInterface } from "node:readline/promises";

import type { CliContext } from "../context.js";
import { consumeFlag } from "../globals.js";
import { withNextActions } from "../next-actions.js";
import { mustBeNonInteractive } from "../tty.js";
import {
  CliError,
  EXIT_SUCCESS,
  type CliDependencies,
  type CommandResult,
  type GlobalOptions,
} from "../types.js";

/** Subcommands that must not nest another interactive shell/TUI inside the REPL. */
const SHELL_BLOCKED_HEADS = new Set(["shell", "control"]);

export type ShellStickyContext = {
  gateway: string;
  envFile: string;
  profile?: string;
  requestIdPrefix: string;
};

function parseLine(line: string): string[] {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) {
    return [];
  }
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < trimmed.length; i += 1) {
    const ch = trimmed[i]!;
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += ch;
  }
  if (quote) {
    throw new CliError("unclosed quote in shell input", {
      category: "usage",
      code: "cli.shell.unclosed_quote",
    });
  }
  if (current) {
    tokens.push(current);
  }
  return tokens;
}

function stickyGlobalFlags(sticky: ShellStickyContext): string[] {
  const flags = ["--gateway", sticky.gateway, "--env-file", sticky.envFile];
  if (sticky.profile) {
    flags.push("--profile", sticky.profile);
  }
  return flags;
}

function buildShellPrompt(sticky: ShellStickyContext): string {
  const profile = sticky.profile ? ` profile=${sticky.profile}` : "";
  return `paybond${profile}> `;
}

/**
 * Run a single sticky-context command line through the CLI router.
 * Exported for tests.
 */
export async function runShellLine(
  line: string,
  sticky: ShellStickyContext,
  deps: CliDependencies,
  runCli: (argv: string[], deps?: CliDependencies) => Promise<number>,
): Promise<{ exitCode: number; tokens: string[] }> {
  const tokens = parseLine(line);
  if (tokens.length === 0) {
    return { exitCode: EXIT_SUCCESS, tokens };
  }
  if (tokens[0] === "exit" || tokens[0] === "quit") {
    return { exitCode: EXIT_SUCCESS, tokens: ["exit"] };
  }
  if (tokens[0] === "help" && tokens.length === 1) {
    const code = await runCli([...stickyGlobalFlags(sticky), "help"], deps);
    return { exitCode: code, tokens };
  }
  if (SHELL_BLOCKED_HEADS.has(tokens[0]!)) {
    throw new CliError(`refusing to nest '${tokens[0]}' inside paybond shell`, {
      category: "usage",
      code: "cli.shell.nested_forbidden",
      details: withNextActions(undefined, {
        what: "nested interactive command",
        why: "shell already provides sticky context for subcommands",
        next: "type status, whoami, or help <command>",
      }),
    });
  }
  const argv = [...stickyGlobalFlags(sticky), ...tokens];
  const code = await runCli(argv, deps);
  return { exitCode: code, tokens };
}

/**
 * Interactive REPL with sticky gateway/env/profile context (Heroku-style).
 * Non-TTY / CI / `--format json` must not hang: use `--exec` for one-shot.
 */
export async function handleShell(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }

  const execFlag = consumeFlag(argv, "--exec");
  if (execFlag.rest.length > 0) {
    throw new CliError(`unexpected arguments: ${execFlag.rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
      details: withNextActions(undefined, {
        what: "unexpected shell args",
        why: "interactive shell takes no positional args; use --exec for one-shot",
        next: 'paybond shell --exec "status"',
      }),
    });
  }

  const sticky: ShellStickyContext = {
    gateway: ctx.globals.gateway,
    envFile: ctx.globals.envFile,
    profile: ctx.globals.profile,
    requestIdPrefix: ctx.globals.requestId,
  };

  const { runCli } = await import("../router.js");
  const deps: CliDependencies = {
    ...ctx.deps,
    cwd: ctx.cwd,
    fetch: ctx.fetch,
    stdout: ctx.stdout,
    stderr: ctx.stderr,
    openBrowser: ctx.deps.openBrowser,
    sleep: ctx.deps.sleep,
    now: ctx.deps.now,
  };

  if (execFlag.value !== undefined) {
    const { exitCode, tokens } = await runShellLine(execFlag.value, sticky, deps, runCli);
    if (tokens[0] === "exit") {
      return { data: { mode: "exec", exited: true, exit_code: EXIT_SUCCESS } };
    }
    return {
      data: {
        mode: "exec",
        command: execFlag.value,
        exit_code: exitCode,
        sticky: {
          gateway: sticky.gateway,
          env_file: sticky.envFile,
          profile: sticky.profile ?? null,
        },
      },
    };
  }

  if (mustBeNonInteractive(ctx.globals)) {
    throw new CliError(
      "paybond shell requires an interactive TTY; use --exec \"<command>\" in CI/non-TTY",
      {
        category: "usage",
        code: "cli.shell.non_interactive",
        details: withNextActions(undefined, {
          what: "non-interactive shell",
          why: "REPL would hang without a TTY (or --format json / CI)",
          next: 'paybond shell --exec "status --format json"',
        }),
      },
    );
  }

  const stdin = (globalThis as { process?: { stdin?: NodeJS.ReadableStream } }).process?.stdin;
  const stdout = (globalThis as { process?: { stdout?: NodeJS.WritableStream } }).process?.stdout;
  if (!stdin || !stdout) {
    throw new CliError("paybond shell requires process stdin/stdout", {
      category: "environment",
      code: "cli.shell.missing_stdio",
    });
  }

  const rl = createInterface({ input: stdin, output: stdout, terminal: true });
  let commandsRun = 0;
  try {
    if (ctx.globals.format !== "json") {
      ctx.stdout.write(
        `Paybond shell (sticky gateway=${sticky.gateway} env-file=${sticky.envFile}). Type help, status, or exit.\n`,
      );
    }
    for (;;) {
      const line = await rl.question(buildShellPrompt(sticky));
      try {
        const { exitCode, tokens } = await runShellLine(line, sticky, deps, runCli);
        if (tokens[0] === "exit") {
          break;
        }
        if (tokens.length > 0) {
          commandsRun += 1;
          if (exitCode !== EXIT_SUCCESS && ctx.globals.format !== "json") {
            ctx.stderr.write(`[exit ${exitCode}]\n`);
          }
        }
      } catch (err) {
        if (err instanceof CliError) {
          ctx.stderr.write(`${err.message}\n`);
          continue;
        }
        throw err;
      }
    }
  } finally {
    rl.close();
  }

  return {
    data: {
      mode: "repl",
      commands_run: commandsRun,
      sticky: {
        gateway: sticky.gateway,
        env_file: sticky.envFile,
        profile: sticky.profile ?? null,
      },
    },
  };
}

/** Preserve sticky globals when nesting runCli from shell (exported for tests). */
export function mergeStickyGlobals(base: GlobalOptions, sticky: ShellStickyContext): GlobalOptions {
  return {
    ...base,
    gateway: sticky.gateway,
    envFile: sticky.envFile,
    profile: sticky.profile,
  };
}
