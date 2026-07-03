import { describe, expect, it, vi } from "vitest";
import {
  fetchWithGatewayRetries,
  gatewayRetryDelayMs,
  isCloudflareEdgeErrorBody,
  parseRetryAfterSeconds,
  shouldRetryGatewayHttpStatus,
} from "../../src/gateway-retry.js";

describe("gateway-retry", () => {
  it("detects Cloudflare edge error bodies", () => {
    expect(
      isCloudflareEdgeErrorBody(
        JSON.stringify({ cloudflare_error: true, title: "Error 502: Bad gateway" }),
      ),
    ).toBe(true);
    expect(isCloudflareEdgeErrorBody(JSON.stringify({ error: { code: "validation_error" } }))).toBe(
      false,
    );
  });

  it("skips retry for Cloudflare edge 502 bodies", () => {
    const body = JSON.stringify({ cloudflare_error: true, title: "Error 502: Bad gateway" });
    expect(shouldRetryGatewayHttpStatus(502, body)).toBe(false);
    expect(shouldRetryGatewayHttpStatus(502, JSON.stringify({ error: { message: "nope" } }))).toBe(
      true,
    );
  });

  it("prefers Retry-After over backoff", () => {
    expect(gatewayRetryDelayMs(0, "2")).toBe(2000);
    expect(parseRetryAfterSeconds("120")).toBe(30);
    expect(gatewayRetryDelayMs(3, null)).toBeGreaterThan(0);
  });

  it("returns the response when retries eventually succeed", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: { message: "busy" } }), { status: 503 }),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ok: true }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetchMock);

    const res = await fetchWithGatewayRetries("https://api.paybond.ai/health", {}, 2);
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not retry Cloudflare edge 502 bodies", async () => {
    const body = JSON.stringify({ cloudflare_error: true, title: "Error 502: Bad gateway" });
    const fetchMock = vi.fn().mockResolvedValue(new Response(body, { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);

    const res = await fetchWithGatewayRetries(
      "https://api.paybond.ai/v1/sandbox/guardrails/bootstrap",
      {},
      3,
    );
    expect(res.status).toBe(502);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("throws the last network error when fetch never succeeds", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("connection reset"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchWithGatewayRetries("https://api.paybond.ai/health", {}, 2),
    ).rejects.toThrow("connection reset");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
