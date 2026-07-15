import { describe, expect, it } from "vitest";

import {
  PAYSTACK_ARGV_BLOCKED_FLAGS,
  assertNoPaystackSensitiveArgv,
  buildPaystackDoctorChecks,
  buildPaystackReadyChecks,
  formatPaystackDoctorChecklist,
  rejectsPaystackSensitiveArgvFlag,
  resolvePaystackWebhookAddress,
  type PaystackSettlementConfigSnapshot,
} from "../../src/cli/commands/paystack.js";
import { CliError } from "../../src/cli/types.js";

const READY_FIXTURE: PaystackSettlementConfigSnapshot = {
  allowed_rails: ["paystack_nip", "stripe_connect"],
  plan_id: "growth",
  paystack_destination_configured: true,
  paystack_environment: "sandbox",
  paystack_label: "NGN corridor",
  paystack_currency: "NGN",
  paystack_secret_key_configured: true,
  paystack_webhook_url: "https://api.paybond.ai/webhooks/sandbox/paystack/abcd1234",
  rail_readiness: [
    {
      rail: "paystack_nip",
      ready: true,
      enabled: true,
      status: "ready",
      message: "Paystack destination credentials are active for NIP settlement.",
    },
  ],
};

const INCOMPLETE_FIXTURE: PaystackSettlementConfigSnapshot = {
  allowed_rails: [],
  paystack_destination_configured: false,
  paystack_secret_key_configured: false,
  rail_readiness: [
    {
      rail: "paystack_nip",
      ready: false,
      enabled: false,
      status: "not_configured",
      reason_code: "paystack_destination_missing",
      message: "Save Paystack secret key before enabling NIP settlement.",
    },
  ],
};

const LIVE_UNPAID_FIXTURE: PaystackSettlementConfigSnapshot = {
  allowed_rails: ["paystack_nip"],
  plan_id: "free",
  paystack_destination_configured: true,
  paystack_environment: "live",
  paystack_label: "Live NGN",
  paystack_currency: "NGN",
  paystack_secret_key_configured: true,
  rail_readiness: [
    {
      rail: "paystack_nip",
      ready: false,
      enabled: true,
      status: "plan_upgrade_needed",
      reason_code: "paystack_paid_plan_required",
      message: "Live Paystack settlement destinations are only available on paid self-serve plans.",
    },
  ],
};

describe("paystack CLI ready/doctor", () => {
  it("resolves live and sandbox webhook base addresses", () => {
    expect(resolvePaystackWebhookAddress("https://api.paybond.ai", "sandbox")).toBe(
      "https://api.paybond.ai/webhooks/sandbox/paystack",
    );
    expect(resolvePaystackWebhookAddress("https://api.paybond.ai/", "live")).toBe(
      "https://api.paybond.ai/webhooks/live/paystack",
    );
  });

  it("ready passes against a complete fixture config", () => {
    const checks = buildPaystackReadyChecks(READY_FIXTURE);
    expect(checks.every((check) => check.ok)).toBe(true);
    expect(checks.map((check) => check.name)).toEqual([
      "rail_enabled",
      "destination_configured",
      "secret_key",
      "paid_plan",
      "rail_readiness",
    ]);
  });

  it("ready fails when destination and secret key are missing", () => {
    const checks = buildPaystackReadyChecks(INCOMPLETE_FIXTURE);
    expect(checks.find((check) => check.name === "rail_enabled")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "destination_configured")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "secret_key")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "rail_readiness")?.ok).toBe(false);
    expect(checks.every((check) => check.ok)).toBe(false);
  });

  it("ready surfaces paid-plan block for live destinations", () => {
    const checks = buildPaystackReadyChecks(LIVE_UNPAID_FIXTURE);
    const paidPlan = checks.find((check) => check.name === "paid_plan");
    expect(paidPlan?.ok).toBe(false);
    expect(paidPlan?.message).toContain("paid self-serve");
  });

  it("doctor expands ready with webhook, environment, and console pointer", () => {
    const checks = buildPaystackDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    expect(checks.find((check) => check.name === "webhook_endpoint")?.message).toContain(
      "/webhooks/sandbox/paystack/abcd1234",
    );
    expect(checks.find((check) => check.name === "environment_match")?.ok).toBe(true);
    expect(checks.find((check) => check.name === "console_destination")?.ok).toBe(true);
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it("doctor surfaces token-append hint when no destination is saved", () => {
    const checks = buildPaystackDoctorChecks(INCOMPLETE_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const webhook = checks.find((check) => check.name === "webhook_endpoint");
    expect(webhook?.message).toContain("/webhooks/sandbox/paystack/<destination-token>");
  });

  it("doctor flags sandbox tenant with live Paystack destination", () => {
    const checks = buildPaystackDoctorChecks(LIVE_UNPAID_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const env = checks.find((check) => check.name === "environment_match");
    expect(env?.ok).toBe(false);
    expect(env?.message).toContain("tenant environment=sandbox");
  });

  it("formats checklist summary lines", () => {
    const checks = buildPaystackReadyChecks(INCOMPLETE_FIXTURE);
    const lines = formatPaystackDoctorChecklist(checks, false, "paystack ready");
    expect(lines.at(-1)).toBe("paystack ready: fail");
    expect(lines.some((line) => line.includes("rail_enabled"))).toBe(true);
  });

  it("rejects Paystack destination material on argv (SEC-011)", () => {
    for (const flag of PAYSTACK_ARGV_BLOCKED_FLAGS) {
      expect(rejectsPaystackSensitiveArgvFlag(flag)).toBe(true);
      expect(rejectsPaystackSensitiveArgvFlag(`${flag}=value`)).toBe(true);
      expect(() => assertNoPaystackSensitiveArgv([flag, "x"])).toThrow(CliError);
      try {
        assertNoPaystackSensitiveArgv([`${flag}=secret`]);
        expect.unreachable("expected argv rejection");
      } catch (err) {
        expect(err).toBeInstanceOf(CliError);
        const cliErr = err as CliError;
        expect(cliErr.code).toBe("cli.paystack.argv_secret_forbidden");
        expect(cliErr.message).toContain(flag);
        expect(cliErr.message).toContain("write-only");
      }
    }
    expect(rejectsPaystackSensitiveArgvFlag("--format")).toBe(false);
    expect(() => assertNoPaystackSensitiveArgv([])).not.toThrow();
  });

  it("doctor console pointer lists argv-blocked flags", () => {
    const checks = buildPaystackDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const consoleCheck = checks.find((check) => check.name === "console_destination");
    expect(consoleCheck?.details?.argv_blocked_flags).toEqual([...PAYSTACK_ARGV_BLOCKED_FLAGS]);
    expect(consoleCheck?.message).toContain("Console");
  });
});
