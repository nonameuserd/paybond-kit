import { consumeBooleanFlag, consumeFlag } from "../globals.js";
import { withNextActions } from "../next-actions.js";
import { mustBeNonInteractive } from "../tty.js";
import { CliError, type CommandResult } from "../types.js";
import type { CliContext } from "../context.js";
import { gatherControlPlaneSnapshot } from "./control-snapshot.js";

/**
 * Live read-mostly control-plane command. Interactive TTY uses Ink; `--once` / JSON stay snapshot-only.
 */
export async function handleControl(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  if (argv[0] === "--help" || argv[0] === "-h") {
    throw new CliError("help", { category: "usage", code: "cli.help" });
  }

  const policyFlag = consumeFlag(argv, "--policy-file");
  const limitFlag = consumeFlag(policyFlag.rest, "--limit");
  const onceFlag = consumeBooleanFlag(limitFlag.rest, "--once");
  if (onceFlag.rest.length > 0) {
    throw new CliError(`unexpected arguments: ${onceFlag.rest.join(" ")}`, {
      category: "usage",
      code: "cli.usage.unexpected_args",
    });
  }

  let limit = 10;
  if (limitFlag.value) {
    limit = Number.parseInt(limitFlag.value, 10);
    if (!Number.isFinite(limit) || limit < 1) {
      throw new CliError("control --limit must be a positive integer", {
        category: "usage",
        code: "cli.usage.invalid_limit",
      });
    }
  }

  const snapshot = await gatherControlPlaneSnapshot(ctx, {
    policyFile: policyFlag.value,
    limit,
  });

  const nonInteractive =
    mustBeNonInteractive(ctx.globals) || onceFlag.present || ctx.globals.format === "json";
  if (nonInteractive) {
    return {
      data: {
        mode: "snapshot",
        ...snapshot,
        active_panel: "intents",
        next_commands: [
          "paybond status",
          'paybond shell --exec "intents list"',
          "paybond open billing",
        ],
      },
    };
  }

  const stdin = (globalThis as { process?: { stdin?: NodeJS.ReadableStream } }).process?.stdin;
  const stdout = (globalThis as { process?: { stdout?: NodeJS.WritableStream } }).process?.stdout;
  if (!stdin || !stdout) {
    throw new CliError("paybond control requires process stdin/stdout", {
      category: "environment",
      code: "cli.control.missing_stdio",
      details: withNextActions(undefined, {
        what: "missing stdio",
        why: "TUI needs an interactive terminal",
        next: "paybond control --once --format json",
      }),
    });
  }

  const [{ default: React }, { render }, { ControlTuiApp }] = await Promise.all([
    import("react"),
    import("ink"),
    import("./control-tui.js"),
  ]);

  let lastSnapshot = snapshot;
  const instance = render(
    React.createElement(ControlTuiApp, {
      initialSnapshot: snapshot,
      globals: ctx.globals,
      refresh: async () => {
        lastSnapshot = await gatherControlPlaneSnapshot(ctx, {
          policyFile: policyFlag.value,
          limit,
        });
        return lastSnapshot;
      },
    }),
    { stdin: stdin as NodeJS.ReadStream, stdout: stdout as NodeJS.WriteStream },
  );

  await instance.waitUntilExit();

  return {
    data: {
      mode: "tui",
      active_panel: "intents",
      ...lastSnapshot,
    },
  };
}

export type { ControlPanel, ControlPlaneSnapshot } from "./control-snapshot.js";
export { gatherControlPlaneSnapshot, CONTROL_PANELS } from "./control-snapshot.js";
