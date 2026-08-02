import type { CliErrorDetails, CliErrorShape } from "./types.js";

/**
 * Structured recovery guidance attached to CLI errors (`details.what|why|next`).
 * Human table mode prints these on stderr; JSON mode nests them under `error.details`.
 */
export type CliNextActions = {
  /** What failed (short noun phrase). */
  what: string;
  /** Why it failed (safe, loggable reason). */
  why: string;
  /** Exact next command or action the operator should run. */
  next: string;
};

export type CliErrorDetailsWithNext = CliErrorDetails & Partial<CliNextActions>;

/**
 * Merge what/why/next recovery fields into CliError details without dropping context.
 */
export function withNextActions(
  details: CliErrorDetails | undefined,
  actions: CliNextActions,
): CliErrorDetailsWithNext {
  return {
    ...(details ?? {}),
    what: actions.what,
    why: actions.why,
    next: actions.next,
  };
}

/**
 * Extract structured next-actions from an error shape when present.
 */
export function readNextActions(details: CliErrorDetails | undefined): CliNextActions | undefined {
  if (!details) {
    return undefined;
  }
  const what = typeof details.what === "string" ? details.what.trim() : "";
  const why = typeof details.why === "string" ? details.why.trim() : "";
  const next = typeof details.next === "string" ? details.next.trim() : "";
  if (!what && !why && !next) {
    return undefined;
  }
  return {
    what: what || "command failed",
    why: why || "see message",
    next: next || "paybond doctor",
  };
}

/**
 * Format a human-readable error block for stderr (never colored; caller decides).
 */
export function formatHumanErrorLines(shape: CliErrorShape): string[] {
  const lines = [shape.message];
  const actions = readNextActions(shape.details);
  if (!actions) {
    return lines;
  }
  lines.push(`what: ${actions.what}`);
  lines.push(`why: ${actions.why}`);
  lines.push(`next: ${actions.next}`);
  return lines;
}

/** Canonical post-login next commands for Kit builder loop. */
export const LOGIN_NEXT_COMMANDS: readonly string[] = [
  "paybond init",
  "paybond doctor",
  "paybond status",
] as const;

/** Example-led happy path shown in help/examples workflows. */
export const KIT_HAPPY_PATH_COMMANDS: readonly string[] = [
  "paybond login",
  "paybond init",
  "paybond agent sandbox smoke --offline --operation paid-tool --requested-spend-cents 100 --evidence-preset cost_and_completion --result-body '{\"status\":\"ok\",\"cost_cents\":100}'",
  "paybond dev loop --offline",
  "paybond dev trace",
] as const;
