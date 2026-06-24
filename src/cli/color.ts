import type { ColorMode, GlobalOptions } from "./types.js";

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
} as const;

export type AnsiStyle = keyof typeof ANSI;

export function resolveColorModeFromEnv(env: NodeJS.ProcessEnv = process.env): ColorMode {
  if (env.NO_COLOR !== undefined && env.NO_COLOR.trim() !== "") {
    return "never";
  }
  return "auto";
}

export function parseColorMode(raw: string): ColorMode {
  const value = raw.trim().toLowerCase();
  if (value === "auto" || value === "always" || value === "never") {
    return value;
  }
  throw new Error("invalid --color (expected auto|always|never)");
}

export function shouldUseColor(globals: GlobalOptions, isTTY = process.stdout.isTTY === true): boolean {
  if (globals.format === "json") {
    return false;
  }
  if (globals.color === "never") {
    return false;
  }
  if (globals.color === "always") {
    return true;
  }
  return isTTY;
}

export function colorize(text: string, style: AnsiStyle, enabled: boolean): string {
  if (!enabled) {
    return text;
  }
  return `${ANSI[style]}${text}${ANSI.reset}`;
}
