export const LOCAL_GATEWAY_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

export class InsecureGatewayURLError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InsecureGatewayURLError";
  }
}

function parseIPv4Octets(ip: string): ReadonlyArray<number> | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) {
    return null;
  }
  const octets = parts.map((part) => Number.parseInt(part, 10));
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return null;
  }
  return octets;
}

/** True for loopback hostnames and RFC1918 private IPv4 addresses. */
function isRfc1918IPv4(hostname: string): boolean {
  const octets = parseIPv4Octets(hostname);
  if (!octets) {
    return false;
  }
  const [first, second] = octets;
  if (first === 10) {
    return true;
  }
  if (first === 192 && second === 168) {
    return true;
  }
  return first === 172 && second >= 16 && second <= 31;
}

export function isLocalGatewayHost(hostname: string): boolean {
  const lowered = hostname.trim().toLowerCase();
  if (LOCAL_GATEWAY_HOSTS.has(lowered)) {
    return true;
  }
  if (isRfc1918IPv4(lowered)) {
    return true;
  }
  if (lowered.startsWith("127.")) {
    return true;
  }
  return false;
}

/** Return a normalized gateway base URL or throw when TLS requirements are not met. */
export function requireSecureGatewayUrl(url: string): string {
  const trimmed = url.trim();
  if (!trimmed) {
    throw new InsecureGatewayURLError("gateway URL is required");
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new InsecureGatewayURLError("gateway URL must be an absolute URL");
  }
  const scheme = parsed.protocol.replace(":", "").toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  if (scheme === "https") {
    return trimmed.replace(/\/+$/, "");
  }
  if (scheme === "http" && isLocalGatewayHost(hostname)) {
    return trimmed.replace(/\/+$/, "");
  }
  throw new InsecureGatewayURLError(
    "gateway URL must use https:// (http:// is allowed only for loopback and private networks)",
  );
}
