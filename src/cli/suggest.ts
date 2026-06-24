import { COMMAND_PATHS, GLOBAL_FLAG_NAMES } from "./command-spec.js";

function levenshtein(a: string, b: string): number {
  const rows = a.length + 1;
  const cols = b.length + 1;
  const matrix = Array.from({ length: rows }, () => Array<number>(cols).fill(0));
  for (let i = 0; i < rows; i += 1) {
    matrix[i]![0] = i;
  }
  for (let j = 0; j < cols; j += 1) {
    matrix[0]![j] = j;
  }
  for (let i = 1; i < rows; i += 1) {
    for (let j = 1; j < cols; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i]![j] = Math.min(
        matrix[i - 1]![j]! + 1,
        matrix[i]![j - 1]! + 1,
        matrix[i - 1]![j - 1]! + cost,
      );
    }
  }
  return matrix[a.length]![b.length]!;
}

function bestSuggestion(input: string, candidates: string[]): string | undefined {
  const needle = input.trim().toLowerCase();
  if (!needle) {
    return undefined;
  }
  let best: { value: string; distance: number } | undefined;
  for (const candidate of candidates) {
    const distance = levenshtein(needle, candidate.toLowerCase());
    const threshold = Math.max(2, Math.floor(candidate.length / 3));
    if (distance > threshold) {
      continue;
    }
    if (!best || distance < best.distance) {
      best = { value: candidate, distance };
    }
  }
  return best?.value;
}

export function suggestCommandPath(input: string): string | undefined {
  return bestSuggestion(input, COMMAND_PATHS);
}

export function suggestGlobalFlag(input: string): string | undefined {
  const normalized = input.split("=")[0] ?? input;
  return bestSuggestion(normalized, GLOBAL_FLAG_NAMES);
}

export function formatUnknownCommandMessage(input: string): string {
  const suggestion = suggestCommandPath(input);
  if (suggestion) {
    return `unknown command: ${input} (did you mean "${suggestion}"?)`;
  }
  return `unknown command: ${input}`;
}

export function formatUnknownGlobalFlagMessage(flag: string): string {
  const suggestion = suggestGlobalFlag(flag);
  if (suggestion) {
    return `unknown global flag: ${flag} (did you mean ${suggestion}?)`;
  }
  return `unknown global flag: ${flag}`;
}
