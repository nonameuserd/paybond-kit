import { describe, expect, it, vi } from "vitest";

import { runCli } from "../src/cli/router.js";

const RAW_KEY =
  "paybond_sk_sandbox_0123456789abcdef0123456789abcdef_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const INTENT_ID = "550e8400-e29b-41d4-a716-446655440000";
const TOOL_CALL_ID = "call_1";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function collectingStdout() {
  return {
    chunks: [] as string[],
    write(chunk: string): boolean {
      this.chunks.push(chunk);
      return true;
    },
  };
}

describe("receipts CLI resolve-by-intent parity", () => {
  it("resolves the action receipt by --intent-id and --tool-call-id", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn(async () => jsonResponse({ scope: "action", receipt_id: "digest-1" }));
    const stdout = collectingStdout();
    const code = await runCli(
      ["--format", "json", "receipts", "get", "--kind", "agent", "--intent-id", INTENT_ID, "--tool-call-id", TOOL_CALL_ID],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const [input] = fetchMock.mock.calls[0]!;
    expect(String(input)).toContain(
      `/protocol/v2/agent-receipts?intent_id=${INTENT_ID}&tool_call_id=${TOOL_CALL_ID}`,
    );
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.scope).toBe("action");
  });

  it("resolves the intent-terminal receipt by --intent-id alone (no --tool-call-id)", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn(async () => jsonResponse({ scope: "intent_terminal", receipt_id: INTENT_ID }));
    const stdout = collectingStdout();
    const code = await runCli(
      ["--format", "json", "receipts", "get", "--kind", "agent", "--intent-id", INTENT_ID],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const [input] = fetchMock.mock.calls[0]!;
    expect(String(input)).toContain(`/protocol/v2/agent-receipts?intent_id=${INTENT_ID}`);
    expect(String(input)).not.toContain("tool_call_id");
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.scope).toBe("intent_terminal");
  });

  it("verify fetches the resolved receipt by intent then verifies it", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetched = { scope: "action", receipt_id: "digest-1" };
    const fetchMock = vi.fn(async (input: unknown, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/agent-receipts/verify")) {
        expect(init?.method).toBe("POST");
        expect(JSON.parse(String(init?.body))).toEqual(fetched);
        return jsonResponse({ valid: true });
      }
      expect(url).toContain(`/protocol/v2/agent-receipts?intent_id=${INTENT_ID}&tool_call_id=${TOOL_CALL_ID}`);
      return jsonResponse(fetched);
    });
    const stdout = collectingStdout();
    const code = await runCli(
      [
        "--format",
        "json",
        "receipts",
        "verify",
        "--kind",
        "agent",
        "--intent-id",
        INTENT_ID,
        "--tool-call-id",
        TOOL_CALL_ID,
      ],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.data.valid).toBe(true);
  });

  it("still resolves by explicit <receipt_id> unchanged", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn(async () => jsonResponse({ scope: "action" }));
    const stdout = collectingStdout();
    const code = await runCli(["--format", "json", "receipts", "get", "digest-abc", "--kind", "agent"], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const [input] = fetchMock.mock.calls[0]!;
    expect(String(input)).toContain("/protocol/v2/agent-receipts/digest-abc");
  });

  it("prefers an explicit <receipt_id> over --intent-id when both are given", async () => {
    vi.stubEnv("PAYBOND_API_KEY", RAW_KEY);
    const fetchMock = vi.fn(async () => jsonResponse({ scope: "action" }));
    const stdout = collectingStdout();
    const code = await runCli(
      ["--format", "json", "receipts", "get", "digest-abc", "--kind", "agent", "--intent-id", INTENT_ID],
      { fetch: fetchMock, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const [input] = fetchMock.mock.calls[0]!;
    expect(String(input)).toContain("/protocol/v2/agent-receipts/digest-abc");
  });
});
