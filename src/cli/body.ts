import { consumeBooleanFlag, consumeFlag } from "./globals.js";
import { readJsonBody } from "./automation.js";
import { CliError } from "./types.js";

declare const process: { stdin: NodeJS.ReadableStream };

export async function resolveJsonBody(
  argv: string[],
  options?: { required?: boolean; missingMessage?: string },
): Promise<{ payload: Record<string, unknown>; rest: string[] }> {
  const required = options?.required ?? true;
  const missingMessage =
    options?.missingMessage ?? "missing JSON body; pass --body <json-file> or --stdin";
  const stdinFlag = consumeBooleanFlag(argv, "--stdin");
  if (stdinFlag.present) {
    return { payload: await readJsonBody("-", process.stdin), rest: stdinFlag.rest };
  }
  const bodyFlag = consumeFlag(stdinFlag.rest, "--body");
  if (!bodyFlag.value) {
    if (!required) {
      return { payload: {}, rest: bodyFlag.rest };
    }
    throw new CliError(missingMessage, {
      category: "usage",
      code: "cli.usage.missing_body",
    });
  }
  return { payload: await readJsonBody(bodyFlag.value, process.stdin), rest: bodyFlag.rest };
}
