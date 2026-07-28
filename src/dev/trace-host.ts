/**
 * Allowed Host headers for the local-only `paybond dev trace` dashboard.
 * Rejects DNS-rebinding hosts that resolve to loopback.
 */
export function isAllowedDevTraceHost(hostHeader: string | undefined, port: number): boolean {
  if (typeof hostHeader !== "string") {
    return false;
  }
  const host = hostHeader.trim().toLowerCase();
  if (!host) {
    return false;
  }
  const allowed = new Set([
    "127.0.0.1",
    `127.0.0.1:${port}`,
    "localhost",
    `localhost:${port}`,
    "[::1]",
    `[::1]:${port}`,
  ]);
  return allowed.has(host);
}
