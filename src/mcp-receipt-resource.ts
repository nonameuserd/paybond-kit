/** MCP resource URI helpers for tenant-bound agent receipt handoff. */

export const MCP_AGENT_RECEIPT_RESOURCE_SCHEME = "paybond";
export const MCP_AGENT_RECEIPT_RESOURCE_HOST = "receipt";
export const MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE = "paybond://receipt/{receipt_id}";
export const MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE = "application/json";

const RECEIPT_URI_RE =
  /^paybond:\/\/receipt\/([0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

/** Parse `paybond://receipt/{receipt_id}` into a canonical receipt id. */
export function parseAgentReceiptResourceUri(uri: string): string {
  const trimmed = uri.trim();
  const match = RECEIPT_URI_RE.exec(trimmed);
  if (!match) {
    throw new Error(
      `unsupported resource URI ${trimmed}; expected ${MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE}`,
    );
  }
  return match[1]!.toLowerCase();
}

/** Build the MCP resource URI for one signed agent receipt id. */
export function agentReceiptResourceUri(receiptId: string): string {
  const normalized = receiptId.trim().toLowerCase();
  if (!RECEIPT_URI_RE.test(`paybond://receipt/${normalized}`)) {
    throw new Error("receipt_id must be a lowercase SHA-256 hex digest or canonical UUID");
  }
  return `paybond://receipt/${normalized}`;
}

export function agentReceiptResourceTemplateDefinition(): Record<string, unknown> {
  return {
    uriTemplate: MCP_AGENT_RECEIPT_RESOURCE_URI_TEMPLATE,
    name: "paybond_agent_receipt",
    title: "Paybond Agent Receipt",
    description:
      "Signed paybond.agent_receipt_v1 JSON fetched tenant-bound from Gateway GET /protocol/v2/agent-receipts/{receipt_id}.",
    mimeType: MCP_AGENT_RECEIPT_RESOURCE_MIME_TYPE,
  };
}
