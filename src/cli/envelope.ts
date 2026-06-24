import { applyAutomationTransforms } from "./automation.js";
import type { CliEnvelope, CliErrorShape, CommandResult, GlobalOptions, Writable } from "./types.js";

export function mergeWarnings(result: CommandResult, extra: string[] = []): string[] {
  const merged = [...(result.warnings ?? []), ...extra];
  return [...new Set(merged)];
}

export function prepareCommandOutput(
  command: string,
  globals: GlobalOptions,
  result: CommandResult,
): { data: unknown; warnings: string[]; automationPlain: boolean } {
  const warnings = mergeWarnings(result);
  const automationRequested = Boolean(globals.jsonFields || globals.jqExpr);
  const data = applyAutomationTransforms(command, result.data, {
    jsonFields: globals.jsonFields,
    jqExpr: globals.jqExpr,
  }) as Record<string, unknown>;
  return {
    data,
    warnings,
    automationPlain: automationRequested && globals.format !== "json",
  };
}

export function successEnvelope<T>(
  command: string,
  globals: GlobalOptions,
  result: CommandResult<T> | { data: T; warnings?: string[] },
): CliEnvelope<T> {
  return {
    ok: true,
    command,
    data: result.data,
    warnings: result.warnings ?? [],
    request_id: globals.requestId,
    error: null,
  };
}

export function failureEnvelope(command: string, globals: GlobalOptions, error: CliErrorShape): CliEnvelope<null> {
  return {
    ok: false,
    command,
    data: null,
    warnings: [],
    request_id: globals.requestId,
    error,
  };
}

export function writeEnvelope<T>(stdout: Writable, envelope: CliEnvelope<T>): void {
  stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
}

export function writeTableLines(stdout: Writable, lines: string[]): void {
  for (const line of lines) {
    stdout.write(`${line}\n`);
  }
}
