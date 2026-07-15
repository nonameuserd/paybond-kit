import { describe, expect, it } from "vitest";

import {
  FLUTTERWAVE_ARGV_BLOCKED_FLAGS,
  assertNoFlutterwaveSensitiveArgv,
  buildFlutterwaveDoctorChecks,
  buildFlutterwaveReadyChecks,
  formatFlutterwaveDoctorChecklist,
  rejectsFlutterwaveSensitiveArgvFlag,
  resolveFlutterwaveWebhookAddress,
  type FlutterwaveSettlementConfigSnapshot,
} from "../../src/cli/commands/flutterwave.js";
import { CliError } from "../../src/cli/types.js";

const READY_FIXTURE: FlutterwaveSettlementConfigSnapshot = {
  allowed_rails: ["flutterwave_virtual_account", "stripe_connect"],
  plan_id: "growth",
  flutterwave_destination_configured: true,
  flutterwave_environment: "sandbox",
  flutterwave_label: "NGN corridor",
  flutterwave_currency: "NGN",
  flutterwave_secret_key_configured: true,
  flutterwave_webhook_secret_configured: true,
  flutterwave_webhook_url: "https://api.paybond.ai/webhooks/sandbox/flutterwave/abcd1234",
  rail_readiness: [
    {
      rail: "flutterwave_virtual_account",
      ready: true,
      enabled: true,
      status: "ready",
      message: "Flutterwave destination credentials are active for virtual-account settlement.",
    },
  ],
};

const INCOMPLETE_FIXTURE: FlutterwaveSettlementConfigSnapshot = {
  allowed_rails: [],
  flutterwave_destination_configured: false,
  flutterwave_secret_key_configured: false,
  flutterwave_webhook_secret_configured: false,
  rail_readiness: [
    {
      rail: "flutterwave_virtual_account",
      ready: false,
      enabled: false,
      status: "not_configured",
      reason_code: "flutterwave_destination_missing",
      message: "Save Flutterwave secret key and webhook secret before enabling virtual-account settlement.",
    },
  ],
};

const LIVE_UNPAID_FIXTURE: FlutterwaveSettlementConfigSnapshot = {
  allowed_rails: ["flutterwave_virtual_account"],
  plan_id: "free",
  flutterwave_destination_configured: true,
  flutterwave_environment: "live",
  flutterwave_label: "Live NGN",
  flutterwave_currency: "NGN",
  flutterwave_secret_key_configured: true,
  flutterwave_webhook_secret_configured: true,
  rail_readiness: [
    {
      rail: "flutterwave_virtual_account",
      ready: false,
      enabled: true,
      status: "plan_upgrade_needed",
      reason_code: "flutterwave_paid_plan_required",
      message: "Live Flutterwave settlement destinations are only available on paid self-serve plans.",
    },
  ],
};

describe("flutterwave CLI ready/doctor", () => {
  it("resolves live and sandbox webhook base addresses", () => {
    expect(resolveFlutterwaveWebhookAddress("https://api.paybond.ai", "sandbox")).toBe(
      "https://api.paybond.ai/webhooks/sandbox/flutterwave",
    );
    expect(resolveFlutterwaveWebhookAddress("https://api.paybond.ai/", "live")).toBe(
      "https://api.paybond.ai/webhooks/live/flutterwave",
    );
  });

  it("ready passes against a complete fixture config", () => {
    const checks = buildFlutterwaveReadyChecks(READY_FIXTURE);
    expect(checks.every((check) => check.ok)).toBe(true);
    expect(checks.map((check) => check.name)).toEqual([
      "rail_enabled",
      "destination_configured",
      "secret_key",
      "webhook_secret",
      "paid_plan",
      "rail_readiness",
    ]);
  });

  it("ready fails when destination and secrets are missing", () => {
    const checks = buildFlutterwaveReadyChecks(INCOMPLETE_FIXTURE);
    expect(checks.find((check) => check.name === "rail_enabled")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "destination_configured")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "secret_key")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "webhook_secret")?.ok).toBe(false);
    expect(checks.find((check) => check.name === "rail_readiness")?.ok).toBe(false);
    expect(checks.every((check) => check.ok)).toBe(false);
  });

  it("ready surfaces paid-plan block for live destinations", () => {
    const checks = buildFlutterwaveReadyChecks(LIVE_UNPAID_FIXTURE);
    const paidPlan = checks.find((check) => check.name === "paid_plan");
    expect(paidPlan?.ok).toBe(false);
    expect(paidPlan?.message).toContain("paid self-serve");
  });

  it("doctor expands ready with webhook, environment, and console pointer", () => {
    const checks = buildFlutterwaveDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    expect(checks.find((check) => check.name === "webhook_endpoint")?.message).toContain(
      "/webhooks/sandbox/flutterwave/abcd1234",
    );
    expect(checks.find((check) => check.name === "environment_match")?.ok).toBe(true);
    expect(checks.find((check) => check.name === "console_destination")?.ok).toBe(true);
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it("doctor surfaces token-append hint when no destination is saved", () => {
    const checks = buildFlutterwaveDoctorChecks(INCOMPLETE_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const webhook = checks.find((check) => check.name === "webhook_endpoint");
    expect(webhook?.message).toContain("/webhooks/sandbox/flutterwave/<destination-token>");
  });

  it("doctor flags sandbox tenant with live Flutterwave destination", () => {
    const checks = buildFlutterwaveDoctorChecks(LIVE_UNPAID_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const env = checks.find((check) => check.name === "environment_match");
    expect(env?.ok).toBe(false);
    expect(env?.message).toContain("tenant environment=sandbox");
  });

  it("formats checklist summary lines", () => {
    const checks = buildFlutterwaveReadyChecks(INCOMPLETE_FIXTURE);
    const lines = formatFlutterwaveDoctorChecklist(checks, false, "flutterwave ready");
    expect(lines.at(-1)).toBe("flutterwave ready: fail");
    expect(lines.some((line) => line.includes("rail_enabled"))).toBe(true);
  });

  it("rejects Flutterwave destination material on argv (SEC-011)", () => {
    for (const flag of FLUTTERWAVE_ARGV_BLOCKED_FLAGS) {
      expect(rejectsFlutterwaveSensitiveArgvFlag(flag)).toBe(true);
      expect(rejectsFlutterwaveSensitiveArgvFlag(`${flag}=value`)).toBe(true);
      expect(() => assertNoFlutterwaveSensitiveArgv([flag, "x"])).toThrow(CliError);
      try {
        assertNoFlutterwaveSensitiveArgv([`${flag}=secret`]);
        expect.unreachable("expected argv rejection");
      } catch (err) {
        expect(err).toBeInstanceOf(CliError);
        const cliErr = err as CliError;
        expect(cliErr.code).toBe("cli.flutterwave.argv_secret_forbidden");
        expect(cliErr.message).toContain(flag);
        expect(cliErr.message).toContain("write-only");
      }
    }
    expect(rejectsFlutterwaveSensitiveArgvFlag("--format")).toBe(false);
    expect(() => assertNoFlutterwaveSensitiveArgv([])).not.toThrow();
  });

  it("doctor console pointer lists argv-blocked flags", () => {
    const checks = buildFlutterwaveDoctorChecks(READY_FIXTURE, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const consoleCheck = checks.find((check) => check.name === "console_destination");
    expect(consoleCheck?.details?.argv_blocked_flags).toEqual([...FLUTTERWAVE_ARGV_BLOCKED_FLAGS]);
    expect(consoleCheck?.message).toContain("Console");
  });
});
