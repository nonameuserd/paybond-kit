import { describe, expect, it } from "vitest";

import {
  agentReceiptResourceTemplateDefinition,
  agentReceiptResourceUri,
  parseAgentReceiptResourceUri,
} from "../src/mcp-receipt-resource.js";

describe("mcp receipt resource URIs", () => {
  it("parses sha256 receipt ids", () => {
    const receiptId = "0ab0f1c2b58543f4753b23fec340f16c931e43d102898606a08acbee37a1e484";
    expect(parseAgentReceiptResourceUri(`paybond://receipt/${receiptId}`)).toBe(receiptId);
    expect(agentReceiptResourceUri(receiptId)).toBe(`paybond://receipt/${receiptId}`);
  });

  it("exposes the MCP resource template metadata", () => {
    expect(agentReceiptResourceTemplateDefinition()).toMatchObject({
      uriTemplate: "paybond://receipt/{receipt_id}",
      mimeType: "application/json",
    });
  });
});
