import { Ajv2020 } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { AgentReceiptV1 } from "./agent-receipt.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const AGENT_RECEIPT_DIR = join(MODULE_DIR, "../../agent-receipt");

/** Privacy-sensitive keys that MUST NOT appear anywhere in agent receipt JSON. */
export const FORBIDDEN_AGENT_RECEIPT_FIELDS = [
  "user_prompt",
  "system_prompt",
  "tool_arguments",
  "tool_results",
  "evidence_payload",
  "payee_signature",
] as const;

let schemaValidator: ReturnType<Ajv2020["compile"]> | undefined;

function schemaValidate(): ReturnType<Ajv2020["compile"]> {
  if (!schemaValidator) {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(readFileSync(join(AGENT_RECEIPT_DIR, "schema.json"), "utf8"));
    schemaValidator = ajv.compile(schema);
  }
  return schemaValidator;
}

function rejectForbiddenAgentReceiptFields(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) {
      rejectForbiddenAgentReceiptFields(item);
    }
    return;
  }
  if (!value || typeof value !== "object") {
    return;
  }
  const record = value as Record<string, unknown>;
  for (const [key, child] of Object.entries(record)) {
    if ((FORBIDDEN_AGENT_RECEIPT_FIELDS as readonly string[]).includes(key)) {
      throw new Error(`agent receipt: forbidden field ${JSON.stringify(key)}`);
    }
    rejectForbiddenAgentReceiptFields(child);
  }
}

/** Reject forbidden privacy fields and validate against the published Draft 2020-12 schema. */
export function validateAgentReceiptJSON(value: unknown): AgentReceiptV1 {
  rejectForbiddenAgentReceiptFields(value);
  const validate = schemaValidate();
  if (!validate(value)) {
    throw new Error(
      `agent receipt: schema validation failed: ${JSON.stringify(validate.errors ?? [])}`,
    );
  }
  return value as AgentReceiptV1;
}

/** Parse and validate untrusted agent receipt JSON before signature verification. */
export function parseAgentReceiptJSON(raw: string | Uint8Array): AgentReceiptV1 {
  const text = typeof raw === "string" ? raw : new TextDecoder().decode(raw);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error("agent receipt: invalid JSON");
  }
  return validateAgentReceiptJSON(parsed);
}
