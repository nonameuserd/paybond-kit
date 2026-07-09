import { Ajv2020 } from "ajv/dist/2020.js";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const AGENT_RECEIPT_DIR = join(MODULE_DIR, "../../agent-receipt");

describe("agent receipt schema", () => {
  it("validates signed conformance vector against schema.json", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(readFileSync(join(AGENT_RECEIPT_DIR, "schema.json"), "utf8"));
    const receipt = JSON.parse(
      readFileSync(join(AGENT_RECEIPT_DIR, "conformance/signed-action-receipt-v1.json"), "utf8"),
    );
    const validate = ajv.compile(schema);
    const valid = validate(receipt);
    expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });

  it("validates signed intent_terminal conformance vector against schema.json", () => {
    const ajv = new Ajv2020({ allErrors: true, strict: false });
    const schema = JSON.parse(readFileSync(join(AGENT_RECEIPT_DIR, "schema.json"), "utf8"));
    const receipt = JSON.parse(
      readFileSync(
        join(AGENT_RECEIPT_DIR, "conformance/signed-intent-terminal-receipt-v1.json"),
        "utf8",
      ),
    );
    const validate = ajv.compile(schema);
    const valid = validate(receipt);
    expect(valid, JSON.stringify(validate.errors, null, 2)).toBe(true);
  });
});
