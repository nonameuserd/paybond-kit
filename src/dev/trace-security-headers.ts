/** Security headers applied to every dev trace dashboard HTTP response. */
export const DEV_TRACE_SECURITY_HEADERS = {
  "cache-control": "no-store",
  "content-security-policy":
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
} as const satisfies Readonly<Record<string, string>>;

/** Merge dev trace security headers with a response content type. */
export function devTraceResponseHeaders(contentType: string): Record<string, string> {
  return {
    ...DEV_TRACE_SECURITY_HEADERS,
    "content-type": contentType,
  };
}
