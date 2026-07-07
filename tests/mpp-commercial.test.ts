import { describe, expect, it } from "vitest";
import {
  USDC_BASE_UNITS_PER_USD_CENT,
  usdCentsToUsdcBaseUnits,
  validateUsdDenominatedSettlement,
} from "../src/mpp-commercial.js";

describe("mpp-commercial", () => {
  it("converts USD cents to USDC base units with 10_000 multiplier", () => {
    expect(USDC_BASE_UNITS_PER_USD_CENT).toBe(10_000);
    expect(usdCentsToUsdcBaseUnits(0)).toBe(0n);
    expect(usdCentsToUsdcBaseUnits(1)).toBe(10_000n);
    expect(usdCentsToUsdcBaseUnits(100)).toBe(1_000_000n);
    expect(usdCentsToUsdcBaseUnits(12_345)).toBe(123_450_000n);
  });

  it("rejects non-USD currency for stripe_mpp", () => {
    expect(() => validateUsdDenominatedSettlement("stripe_mpp", "eur")).toThrow(
      /currency must be usd when settlementRail is stripe_mpp/,
    );
  });

  it("accepts USD for stripe_mpp", () => {
    expect(() => validateUsdDenominatedSettlement("stripe_mpp", "USD")).not.toThrow();
  });
});
