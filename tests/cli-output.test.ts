import { describe, expect, it } from "vitest";

import { prepareCommandOutput } from "../src/cli/envelope.js";
import { defaultGlobalOptions } from "../src/cli/globals.js";
import type { CommandResult } from "../src/cli/types.js";

describe("cli automation output routing", () => {
  it("keeps envelope mode when --format json is set", () => {
    const globals = { ...defaultGlobalOptions(), format: "json" as const, jsonFields: "key_id" };
    const result: CommandResult = { data: { keys: [{ key_id: "k1", role: "operator" }] } };
    const output = prepareCommandOutput("keys list", globals, result);
    expect(output.automationPlain).toBe(false);
    expect(output.data).toEqual([{ key_id: "k1" }]);
  });

  it("emits plain JSON when --json is set without envelope", () => {
    const globals = { ...defaultGlobalOptions(), jsonFields: "key_id" };
    const result: CommandResult = { data: { keys: [{ key_id: "k1", role: "operator" }] } };
    const output = prepareCommandOutput("keys list", globals, result);
    expect(output.automationPlain).toBe(true);
    expect(output.data).toEqual([{ key_id: "k1" }]);
  });
});
