import { PaybondPolicyValidationError } from "./schema.js";

/** Read a dot-separated JSON path from tool call arguments. */
export function resolveJsonPath(args: unknown, path: string): unknown {
  let current: unknown = args;
  for (const segment of path.split(".")) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

/** Resolve non-negative integer spend cents from a JSON path at intercept time. */
export function resolveSpendCentsFromJsonPath(
  args: unknown,
  path: string,
  toolName: string,
): number | undefined {
  const value = resolveJsonPath(args, path);
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new PaybondPolicyValidationError(
      `tool "${toolName}" spend_from_args path "${path}" must resolve to a non-negative integer`,
    );
  }
  return value;
}
