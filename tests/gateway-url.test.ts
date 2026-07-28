import { describe, expect, it } from "vitest";

import {
  InsecureGatewayURLError,
  isLocalGatewayHost,
  isLoopbackGatewayHost,
  requireSecureGatewayUrl,
} from "../src/gateway-url.js";

describe("requireSecureGatewayUrl", () => {
  it("accepts https gateway URLs", () => {
    expect(requireSecureGatewayUrl("https://api.paybond.ai")).toBe("https://api.paybond.ai");
    expect(requireSecureGatewayUrl("https://api.paybond.ai/")).toBe("https://api.paybond.ai");
  });

  it("allows http only for loopback by default", () => {
    expect(requireSecureGatewayUrl("http://127.0.0.1:18089")).toBe("http://127.0.0.1:18089");
    expect(requireSecureGatewayUrl("http://localhost:18089")).toBe("http://localhost:18089");
    expect(() => requireSecureGatewayUrl("http://192.168.1.5:18089")).toThrow(InsecureGatewayURLError);
  });

  it("allows private-network cleartext with explicit opt-in", () => {
    expect(
      requireSecureGatewayUrl("http://192.168.1.5:18089", {
        allowInsecurePrivateNetwork: true,
      }),
    ).toBe("http://192.168.1.5:18089");
  });

  it("rejects insecure remote gateway URLs", () => {
    expect(() => requireSecureGatewayUrl("http://api.paybond.ai")).toThrow(InsecureGatewayURLError);
    expect(() => requireSecureGatewayUrl("http://evil.example")).toThrow(InsecureGatewayURLError);
  });

  it("identifies loopback and local gateway hosts", () => {
    expect(isLoopbackGatewayHost("localhost")).toBe(true);
    expect(isLoopbackGatewayHost("127.0.0.1")).toBe(true);
    expect(isLoopbackGatewayHost("10.0.0.5")).toBe(false);
    expect(isLocalGatewayHost("localhost")).toBe(true);
    expect(isLocalGatewayHost("127.0.0.1")).toBe(true);
    expect(isLocalGatewayHost("10.0.0.5")).toBe(true);
    expect(isLocalGatewayHost("172.16.1.1")).toBe(true);
    expect(isLocalGatewayHost("192.168.0.42")).toBe(true);
    expect(isLocalGatewayHost("api.paybond.ai")).toBe(false);
    expect(isLocalGatewayHost("172.15.0.1")).toBe(false);
  });
});
