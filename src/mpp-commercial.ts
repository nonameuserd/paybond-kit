/**
 * MPP commercial denomination helpers for Paybond MVP.
 *
 * Paybond intent commercial fields remain USD-denominated (`amount_cents`, `currency`).
 * Tempo session deposits use USDC base units (6 decimals): `amount_cents * 10_000`.
 */

import type { SettlementRail } from "./principal-intent.js";

/** USDC uses 6 decimal places; one USD cent maps to 10_000 base units. */
export const USDC_BASE_UNITS_PER_USD_CENT = 10_000;

/** Rails that require USD-denominated commercial intent fields for MVP. */
export const USD_DENOMINATED_SETTLEMENT_RAILS = new Set<SettlementRail>([
  "x402_usdc_base",
  "stripe_ach_debit",
  "stripe_mpp",
]);

/**
 * Rejects non-USD intents on rails that remain USD-denominated for MVP.
 */
export function validateUsdDenominatedSettlement(
  settlementRail: SettlementRail,
  currency: string,
): void {
  if (!USD_DENOMINATED_SETTLEMENT_RAILS.has(settlementRail)) {
    return;
  }
  if (currency.trim().toLowerCase() !== "usd") {
    throw new Error(
      `currency must be usd when settlementRail is ${settlementRail} until multi-currency policy is defined`,
    );
  }
}

/**
 * Converts Paybond USD cents to Tempo USDC base units.
 */
export function usdCentsToUsdcBaseUnits(amountCents: number): bigint {
  if (!Number.isInteger(amountCents) || amountCents < 0) {
    throw new Error("amountCents must be a non-negative integer");
  }
  return BigInt(amountCents) * BigInt(USDC_BASE_UNITS_PER_USD_CENT);
}
