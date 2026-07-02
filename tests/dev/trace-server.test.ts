import { get } from "node:http";
import type { IncomingMessage } from "node:http";
import { describe, expect, it } from "vitest";

import { recordSmokeTraceEvent } from "../../src/dev/trace-buffer.js";
import { DEV_TRACE_SECURITY_HEADERS } from "../../src/dev/trace-security-headers.js";
import { loadDevTraceDashboardHtml } from "../../src/dev/trace-ui.js";
import { startDevTraceServer } from "../../src/dev/trace-server.js";

function expectDevTraceSecurityHeaders(headers: IncomingMessage["headers"]): void {
  expect(headers["x-content-type-options"]).toBe(DEV_TRACE_SECURITY_HEADERS["x-content-type-options"]);
  expect(headers["x-frame-options"]).toBe(DEV_TRACE_SECURITY_HEADERS["x-frame-options"]);
  expect(headers["cache-control"]).toBe(DEV_TRACE_SECURITY_HEADERS["cache-control"]);
  expect(headers["content-security-policy"]).toBe(DEV_TRACE_SECURITY_HEADERS["content-security-policy"]);
}

describe("dev trace dashboard", () => {
  it("loads bundled dashboard HTML with vertical timeline shell", () => {
    const html = loadDevTraceDashboardHtml();
    expect(html).toContain("Paybond dev trace");
    expect(html).toContain('class="v-timeline"');
    expect(html).toContain("v-timeline-step");
    expect(html).toContain("/api/events");
  });

  it("serves dashboard HTML and events API from the trace server", async () => {
    recordSmokeTraceEvent({
      preset: "travel",
      bind: {
        run_id: "run-dashboard-test",
        operation: "travel.book_hotel",
        requested_spend_cents: 18_700,
      },
      execute: { evidence_submitted: true, sandbox_lifecycle_status: "released" },
      resultBody: { status: "completed", cost_cents: 18_700 },
    });

    const server = await startDevTraceServer({ port: 0 });
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("expected bound TCP port");
    }
    const baseUrl = `http://127.0.0.1:${address.port}`;

    const html = await new Promise<string>((resolve, reject) => {
      get(`${baseUrl}/runs/run-dashboard-test`, (response) => {
        expectDevTraceSecurityHeaders(response.headers);
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      }).on("error", reject);
    });
    expect(html).toContain("v-timeline");
    expect(html).toContain("Recent runs");

    const eventsPayload = await new Promise<string>((resolve, reject) => {
      get(`${baseUrl}/api/events`, (response) => {
        expectDevTraceSecurityHeaders(response.headers);
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        response.on("error", reject);
      }).on("error", reject);
    });
    const parsed = JSON.parse(eventsPayload) as {
      events: Array<{ operation: string; steps?: Array<{ phase: string }> }>;
      has_credentials: boolean;
    };
    expect(parsed.events.length).toBeGreaterThan(0);
    expect(parsed.events.at(-1)?.operation).toBe("travel.book_hotel");
    expect(parsed.events.at(-1)?.steps?.map((step) => step.phase)).toEqual(
      expect.arrayContaining(["tool", "authorize"]),
    );
    expect(typeof parsed.has_credentials).toBe("boolean");

    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
});
