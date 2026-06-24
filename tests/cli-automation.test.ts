import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  applyJqFilter,
  applyJsonFieldSelection,
  formatWarning,
  parseJsonFields,
  selectJsonFields,
  writeAtomicFile,
} from "../src/cli/automation.js";

describe("cli automation", () => {
  it("parses json field selectors", () => {
    expect(parseJsonFields("key_id,role")).toEqual(["key_id", "role"]);
  });

  it("selects fields from list rows", () => {
    const rows = [{ key_id: "k1", role: "operator", secret: "x" }];
    expect(selectJsonFields(rows, ["key_id", "role"])).toEqual([{ key_id: "k1", role: "operator" }]);
  });

  it("applies json field selection for list commands", () => {
    const data = { keys: [{ key_id: "k1", role: "operator" }] };
    expect(applyJsonFieldSelection("keys list", data, ["key_id"])).toEqual([{ key_id: "k1" }]);
  });

  it("applies simple jq paths", () => {
    const data = { keys: [{ key_id: "k1" }] };
    expect(applyJqFilter(data, ".keys")).toEqual([{ key_id: "k1" }]);
    expect(applyJqFilter(data, ".keys[].key_id")).toEqual(["k1"]);
  });

  it("formats stable warnings", () => {
    expect(formatWarning("cli.warn.partial_results", "more items available")).toBe(
      "cli.warn.partial_results: more items available",
    );
  });

  it("writes sensitive artifacts atomically with 0600 permissions", () => {
    const dir = mkdtempSync(join(tmpdir(), "paybond-automation-"));
    const target = join(dir, "secret.json");
    writeAtomicFile(target, '{"ok":true}', 0o600);
    const mode = statSync(target).mode & 0o777;
    expect(mode).toBe(0o600);
    rmSync(dir, { recursive: true, force: true });
  });
});
