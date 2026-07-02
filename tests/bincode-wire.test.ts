import { describe, expect, it } from "vitest";
import {
  encodeBincodeString,
  encodeBincodeUuid,
  encodeVarintI64,
  encodeVarintU32,
  encodeVarintU64,
} from "../src/bincode-wire.js";

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("bincode-wire", () => {
  it("matches paybond-evidence primitive encodings", () => {
    expect(hex(encodeVarintU64(6n))).toBe("06");
    expect(hex(encodeBincodeString("tenant-golden"))).toBe("0d74656e616e742d676f6c64656e");
    expect(hex(encodeBincodeUuid("7f2a9b1e-2f66-4f4f-9c6e-8f4b8e85c401"))).toBe(
      "107f2a9b1e2f664f4f9c6e8f4b8e85c401",
    );
    expect(hex(encodeVarintI64(100))).toBe("c8");
    expect(hex(encodeVarintI64(1000))).toBe("fbd007");
    expect(hex(encodeVarintI64(-1))).toBe("01");
    expect(hex(encodeVarintU32(3))).toBe("03");
    expect(hex(encodeVarintU32(300))).toBe("fb2c01");
  });
});
