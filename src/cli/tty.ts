import type { GlobalOptions } from "./types.js";

declare const process: {
  stdin: { isTTY?: boolean };
  stdout: { isTTY?: boolean };
};

/**
 * True when stdin and stdout are interactive TTYs (prompts / REPL / TUI allowed).
 */
export function isInteractiveTty(
  stdinIsTty: boolean = process.stdin.isTTY === true,
  stdoutIsTty: boolean = process.stdout.isTTY === true,
): boolean {
  return stdinIsTty && stdoutIsTty;
}

/**
 * True when the CLI must avoid prompts and interactive loops.
 * JSON format, missing TTY, or CI-like environments force non-interactive mode.
 */
export function mustBeNonInteractive(
  globals: GlobalOptions,
  options: { stdinIsTty?: boolean; stdoutIsTty?: boolean } = {},
): boolean {
  if (globals.format === "json") {
    return true;
  }
  if (!isInteractiveTty(options.stdinIsTty, options.stdoutIsTty)) {
    return true;
  }
  const ci = processEnvTruthy("CI") || processEnvTruthy("PAYBOND_CLI_NONINTERACTIVE");
  return ci;
}

function processEnvTruthy(name: string): boolean {
  const value = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process
    ?.env?.[name];
  if (!value) {
    return false;
  }
  const normalized = value.trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}
