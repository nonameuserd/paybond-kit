import { describe, expect, it } from "vitest";

import {
  ADYEN_ARGV_BLOCKED_FLAGS,
  assertNoAdyenSensitiveArgv,
  buildAdyenDoctorChecks,
  buildAdyenReadyChecks,
  formatAdyenDoctorChecklist,
  rejectsAdyenSensitiveArgvFlag,
  resolveAdyenWebhookAddress,
  type AdyenSettlementConfigSnapshot,
} from "../../src/cli/commands/adyen.js";
import { CliError } from "../../src/cli/types.js";

const READY_FIXTURE: AdyenSettlementConfigSnapshot = {
  allowed_rails: ["adyen_manual_capture", "stripe_connect"],
  plan_id: "growth",
  adyen_destination_configured: true,
  adyen_merchant_account_masked: "Payb***Demo",
  adyen_environment: "test",
  adyen_live_prefix_configured: false,
  adyen_api_key_configured: true,
  adyen_hmac_secret_configured: true,
  adyen_stored_payment_method_configured: true,
  rail_readiness: [
    {
      rail: "adyen_manual_capture",
      ready: true,
      enabled: true,
      status: "ready",
      message: "Adyen Checkout destination credentials are active for manual-capture settlement.",
    },
  ],
};

const INCOMPLETE_FIXTURE: AdyenSettlementConfigSnapshot = {
  allowed_rails: [],
  adyen_destination_configured: false,
  adyen_api_key_configured: false,
  adyen_hmac_secret_configured: false,
  adyen_stored_payment_method_configured: false,
  adyen_live_prefix_configured: false,
  rail_readiness: [
    {
      rail: "adyen_manual_capture",
      ready: false,
      enabled: false,
      status: "not_configured",
      reason_code: "adyen_destination_missing",
      message: "Save Adyen Checkout merchant credentials before enabling manual-capture settlement.",
    },
  ],
};

const LIVE_UNPAID_FIXTURE: AdyenSettlementConfigSnapshot = {
  allowed_rails: ["adyen_manual_capture"],
  plan_id: "free",
  adyen_destination_configured: true,
  adyen_merchant_account_masked: "Live***Acct",
  adyen_environment: "live",
  adyen_live_prefix_configured: true,
  adyen_api_key_configured: true,
  adyen_hmac_secret_configured: true,
  adyen_stored_payment_method_configured: true,
  rail_readiness: [
    {
      rail: "adyen_manual_capture",
      ready: false,
      enabled: true,
      status: "plan_upgrade_needed",
      reason_code: "adyen_paid_plan_required",
      message: "Live Adyen settlement destinations are only available on paid self-serve plans.",
    },
  ],
};

describe("adyen CLI ready/doctor", () => {
  it("resolves live and sandbox webhook addresses", () => {
    expect(resolveAdyenWebhookAddress("https://api.paybond.ai", "sandbox")).toBe(
      "https://api.paybond.ai/webhooks/sandbox/adyen",
    );
    expect(resolveAdyenWebhookAddress("https://api.paybond.ai/", "live")).toBe(
      "https://api.paybond.ai/webhooks/live/adyen",
    );
  });

  it("ready passes against a complete fixture config", () => {
    const checks = buildAdyenReadyChecks(READY_FIXTURE);
    expect(checks.every((check) => check.ok)).toBe(true);
    expect(checks.map((check) => check.name)).toEqual([
      "rail_enabled",
      "destination_configured",
      "api_key",
      "hmac",
      "stored_payment_method",
      "live_prefix",
      "paid_plan",
      "rail_readiness",
    ]);
  });

  it("ready fails when destination and secrets are missing", () => {
    const checks = buildAdyenReadyChecks(INCOMPLETE_FIXTURE);
    expect(checks.find((check) => check.name === "rail_enabled")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "destination_configured")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "api_key")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "hmac")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "rail_readiness")?.ok).toBe(false);
    expect(checks.every((check) => check.ok)).toBe(false);
  });

  it("ready surfaces paid-plan block for live destinations", () => {
    const checks = buildAdyenReadyChecks(LIVE_UNPAID_FIXTURE);
    const paidPlan = checks.find((check) => check.name === "paid_plan");
    expect(paidPlan?.ok).toBe(false);
    expect(paidPlan?.message).toContain("paid self-serve");
    expect(checks.find((check) => check.name === "live_prefix")?.ok).toBe(true);
  });

  it("ready fails live destinations without live prefix", () => {
    const checks = buildAdyenReadyChecks({
      ...LIVE_UNPAID_FIXTURE,
      adyen_live_prefix_configured: false,
      rail_readiness: [
        {
          rail: "adyen_manual_capture",
          ready: false,
          reason_code: "adyen_destination_incomplete",
          message: "live URL prefix missing",
        },
      ],
    });
    expect(checks.find((check) => check.name === "live_prefix")?.ok).toBe(false);
  });

  it("doctor expands ready with webhook, environment, and console pointer", () => {
    const checks = buildAdyenDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    expect(checks.find((check) => check.name === "webhook_endpoint")?.message).toContain(
      "/webhooks/sandbox/adyen",
    );
    expect(checks.find((check) => check.name === "environment_match")?.ok).toBe(true);
    expect(checks.find((check) => check.name === "console_destination")?.ok).toBe(true);
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it("doctor flags sandbox tenant with live Adyen destination", () => {
    const checks = buildAdyenDoctorChecks(LIVE_UNPAID_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const env = checks.find((check) => check.name === "environment_match");
    expect(env?.ok).toBe(false);
    expect(env?.message).toContain("tenant environment=sandbox");
  });

  it("formats checklist summary lines", () => {
    const checks = buildAdyenReadyChecks(INCOMPLETE_FIXTURE);
    const lines = formatAdyenDoctorChecklist(checks, false, "adyen ready");
    expect(lines.at(-1)).toBe("adyen ready: fail");
    expect(lines.some((line) => line.includes("rail_enabled"))).toBe(true);
  });

  it("rejects Adyen destination material on argv (SEC-011)", () => {
    for (const flag of ADYEN_ARGV_BLOCKED_FLAGS) {
      expect(rejectsAdyenSensitiveArgvFlag(flag)).toBe(true);
      expect(rejectsAdyenSensitiveArgvFlag(`${flag}=value`)).toBe(true);
      expect(() => assertNoAdyenSensitiveArgv([flag, "x"])).toThrow(CliError);
      try {
        assertNoAdyenSensitiveArgv([`${flag}=secret`]);
        expect.unreachable("expected argv rejection");
      } catch (err) {
        expect(err).toBeInstanceOf(CliError);
        const cliErr = err as CliError;
        expect(cliErr.code).toBe("cli.adyen.argv_secret_forbidden");
        expect(cliErr.message).toContain(flag);
        expect(cliErr.message).toContain("write-only");
      }
    }
    expect(rejectsAdyenSensitiveArgvFlag("--format")).toBe(false);
    expect(() => assertNoAdyenSensitiveArgv([])).not.toThrow();
  });

  it("doctor console pointer lists argv-blocked flags including live-prefix", () => {
    const checks = buildAdyenDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const consoleCheck = checks.find((check) => check.name === "console_destination");
    expect(consoleCheck?.details?.argv_blocked_flags).toEqual([...ADYEN_ARGV_BLOCKED_FLAGS]);
    expect(consoleCheck?.message).toContain("--live-prefix");
  });
});
