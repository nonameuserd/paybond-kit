import { PaybondPolicyValidationError } from "./schema.js";

type YamlLine = {
  indent: number;
  trimmed: string;
  raw: string;
};

function tokenizeYamlLines(text: string): YamlLine[] {
  const lines: YamlLine[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const indent = raw.search(/\S/);
    if (indent < 0) {
      continue;
    }
    lines.push({ indent, trimmed, raw });
  }
  return lines;
}

function parseYamlScalar(value: string): unknown {
  if (!value) {
    return "";
  }
  if (value === "true") {
    return true;
  }
  if (value === "false") {
    return false;
  }
  if (/^-?\d+$/.test(value)) {
    return Number.parseInt(value, 10);
  }
  if (/^-?\d+\.\d+$/.test(value)) {
    return Number.parseFloat(value);
  }
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function parseYamlBlock(
  lines: YamlLine[],
  start: number,
  indent: number,
  sourceLabel: string,
): [unknown, number] {
  if (start >= lines.length || lines[start]!.indent < indent) {
    return [{}, start];
  }

  if (lines[start]!.trimmed.startsWith("- ")) {
    const items: unknown[] = [];
    let index = start;
    while (
      index < lines.length &&
      lines[index]!.indent === indent &&
      lines[index]!.trimmed.startsWith("- ")
    ) {
      const afterDash = lines[index]!.trimmed.slice(2).trim();
      if (!afterDash) {
        const [child, next] = parseYamlBlock(lines, index + 1, indent + 2, sourceLabel);
        items.push(child);
        index = next;
        continue;
      }
      const inlineMap = /^([^:]+?):\s*(.*)$/.exec(afterDash);
      if (inlineMap && !inlineMap[2]) {
        const key = inlineMap[1]!.trim();
        const [child, next] = parseYamlBlock(lines, index + 1, indent + 2, sourceLabel);
        items.push({ [key]: child });
        index = next;
        continue;
      }
      if (inlineMap) {
        items.push({
          [inlineMap[1]!.trim()]: parseYamlScalar(inlineMap[2]!.trim()),
        });
        index += 1;
        continue;
      }
      items.push(parseYamlScalar(afterDash));
      index += 1;
    }
    return [items, index];
  }

  const objectValue: Record<string, unknown> = {};
  let index = start;
  while (index < lines.length && lines[index]!.indent === indent) {
    const match = /^([^:]+?):\s*(.*)$/.exec(lines[index]!.trimmed);
    if (!match) {
      throw new PaybondPolicyValidationError(
        `${sourceLabel} has invalid YAML line: ${lines[index]!.raw}`,
      );
    }
    const key = match[1]!.trim();
    const rest = match[2]!.trim();
    if (rest) {
      objectValue[key] = parseYamlScalar(rest);
      index += 1;
      continue;
    }
    const [child, next] = parseYamlBlock(lines, index + 1, indent + 2, sourceLabel);
    objectValue[key] = child;
    index = next;
  }
  return [objectValue, index];
}

function parseIndentedYaml(text: string, sourceLabel: string): Record<string, unknown> {
  const lines = tokenizeYamlLines(text);
  if (lines.length === 0) {
    throw new PaybondPolicyValidationError(`${sourceLabel} is empty`);
  }
  const [value] = parseYamlBlock(lines, 0, lines[0]!.indent, sourceLabel);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PaybondPolicyValidationError(`${sourceLabel} must be a YAML object`);
  }
  return value as Record<string, unknown>;
}

/** Parse policy file text (JSON or YAML) into a raw document object. */
export function parsePolicyDocumentText(
  text: string,
  sourceLabel = "policy file",
): Record<string, unknown> {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new PaybondPolicyValidationError(`${sourceLabel} is empty`);
  }
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new PaybondPolicyValidationError(`${sourceLabel} must be a JSON object`);
    }
    return parsed as Record<string, unknown>;
  } catch (err) {
    if (err instanceof PaybondPolicyValidationError) {
      throw err;
    }
    return parseIndentedYaml(trimmed, sourceLabel);
  }
}
