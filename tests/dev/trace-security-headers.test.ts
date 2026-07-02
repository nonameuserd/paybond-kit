import { describe, expect, it } from "vitest";

import {
  DEV_TRACE_SECURITY_HEADERS,
  devTraceResponseHeaders,
} from "../../src/dev/trace-security-headers.js";

describe("dev trace security headers", () => {
  it("includes baseline hardening headers", () => {
    expect(DEV_TRACE_SECURITY_HEADERS["x-content-type-options"]).toBe("nosniff");
    expect(DEV_TRACE_SECURITY_HEADERS["x-frame-options"]).toBe("DENY");
    expect(DEV_TRACE_SECURITY_HEADERS["cache-control"]).toBe("no-store");
    expect(DEV_TRACE_SECURITY_HEADERS["content-security-policy"]).toContain("frame-ancestors 'none'");
    expect(DEV_TRACE_SECURITY_HEADERS["content-security-policy"]).toContain("connect-src 'self'");
  });

  it("merges content type for responses", () => {
    expect(devTraceResponseHeaders("application/json; charset=utf-8")).toMatchObject({
      ...DEV_TRACE_SECURITY_HEADERS,
      "content-type": "application/json; charset=utf-8",
    });
  });
});
