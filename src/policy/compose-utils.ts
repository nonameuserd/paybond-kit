import type { PaybondPolicyToolEntry } from "./schema.js";

/** Clone a tool registry entry for compose merges. */
export function cloneToolEntry(entry: PaybondPolicyToolEntry): PaybondPolicyToolEntry {
  return { ...entry };
}
