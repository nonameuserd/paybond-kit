import { describe, expect, it, vi } from "vitest";
import { runCli } from "../../src/cli/router.js";
import { CliError } from "../../src/cli/types.js";
import {
  PLAID_ARGV_BLOCKED_FLAGS,
  assertNoPlaidSensitiveArgv,
  buildPlaidDoctorChecks,
  buildPlaidReadyChecks,
  formatPlaidChecklist,
  rejectsPlaidSensitiveArgvFlag,
  resolvePlaidWebhookAddress,
} from "../../src/cli/commands/plaid.js";
import { SANDBOX_RAW_KEY } from "./agent-gateway-mock.js";

const BANK_ID = "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function makeStdout() {
  return {
    chunks: [] as string[],
    write(chunk: string): boolean {
      this.chunks.push(chunk);
      return true;
    },
  };
}

const READY_LIST = {
  environment: "sandbox",
  bank_accounts: [
    {
      id: "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1",
      environment: "sandbox",
      bank_name: "Chase",
      bank_mask: "0000",
      bank_last4: "0000",
      status: "active",
      ready: true,
      readiness_reason: "ready",
      access_token: "access-sandbox-should-never-appear",
      link_token: "link-sandbox-should-never-appear",
    },
  ],
};

const PENDING_LIST = {
  environment: "sandbox",
  bank_accounts: [
    {
      id: "8f14e45f-ceea-4c9b-a71a-0d0e12b3f4d1",
      ready: false,
      readiness_reason: "pending_automatic_verification",
      status: "active",
      verification_status: "pending_automatic_verification",
    },
  ],
};

describe("plaid CLI ready/doctor", () => {
  it("resolves the corrected /webhooks/plaid address", () => {
    expect(resolvePlaidWebhookAddress("https://api.paybond.ai")).toBe(
      "https://api.paybond.ai/webhooks/plaid",
    );
    expect(resolvePlaidWebhookAddress("https://api.paybond.ai/")).toBe(
      "https://api.paybond.ai/webhooks/plaid",
    );
    expect(resolvePlaidWebhookAddress("https://api.paybond.ai")).not.toContain(
      "/webhooks/production/plaid",
    );
  });

  it("ready passes against a ready bank fixture", () => {
    const checks = buildPlaidReadyChecks(READY_LIST, null);
    expect(checks.every((check) => check.ok)).toBe(true);
    expect(checks.map((check) => check.name)).toEqual([
      "feature_available",
      "ready_bank_available",
    ]);
  });

  it("ready fails when no ready bank and surfaces attention reason codes", () => {
    const checks = buildPlaidReadyChecks(PENDING_LIST, null);
    const byName = Object.fromEntries(checks.map((check) => [check.name, check]));
    expect(byName.feature_available?.ok).toBe(true);
    expect(byName.ready_bank_available?.ok).toBe(false);
    expect(byName.attention_needed?.ok).toBe(true);
    expect(byName.attention_needed?.message).toContain("pending_automatic_verification");
  });

  it("ready surfaces feature_disabled gateway reason code", () => {
    const err = new CliError("Plaid Auth is disabled on this deployment.", {
      category: "gateway",
      code: "feature_disabled",
      details: { gateway_code: "feature_disabled", gateway_status: 404 },
    });
    const checks = buildPlaidReadyChecks(null, err);
    expect(checks).toHaveLength(1);
    expect(checks[0]?.ok).toBe(false);
    expect(checks[0]?.details?.reason_code).toBe("feature_disabled");
  });

  it("doctor expands with webhook and console pointers", () => {
    const checks = buildPlaidDoctorChecks(READY_LIST, null, {
      gatewayBase: "https://api.paybond.ai",
      tenantEnvironment: "sandbox",
    });
    const webhook = checks.find((check) => check.name === "webhook_endpoint");
    expect(webhook?.details?.webhook_address).toBe("https://api.paybond.ai/webhooks/plaid");
    expect(webhook?.details?.route).toBe("/webhooks/plaid");
    const docs = checks.find((check) => check.name === "console_and_docs");
    expect(docs?.details?.guide_path).toBe("/guides/configure-plaid-bank-verification");
    expect(checks.every((check) => check.ok)).toBe(true);
  });

  it("formats checklist summary", () => {
    const checks = buildPlaidReadyChecks(PENDING_LIST, null);
    const lines = formatPlaidChecklist(checks, false, "plaid ready");
    expect(lines.at(-1)).toBe("plaid ready: fail");
    expect(lines.some((line) => line.includes("ready_bank_available"))).toBe(true);
  });

  it("rejects Plaid token material on argv", () => {
    for (const flag of PLAID_ARGV_BLOCKED_FLAGS) {
      expect(rejectsPlaidSensitiveArgvFlag(flag)).toBe(true);
      expect(rejectsPlaidSensitiveArgvFlag(`${flag}=value`)).toBe(true);
      expect(() => assertNoPlaidSensitiveArgv([`${flag}=secret`])).toThrow(CliError);
      try {
        assertNoPlaidSensitiveArgv([`${flag}=secret`]);
      } catch (err) {
        expect(err).toBeInstanceOf(CliError);
        expect((err as CliError).code).toBe("cli.plaid.argv_secret_forbidden");
        expect((err as CliError).message).toContain(flag);
      }
    }
    expect(rejectsPlaidSensitiveArgvFlag("--format")).toBe(false);
    expect(() => assertNoPlaidSensitiveArgv([])).not.toThrow();
  });
});

describe("plaid banks get", () => {
  it("issues a per-id GET, not a list+filter", async () => {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.endsWith(`/v1/admin/plaid/bank-accounts/${BANK_ID}`)) {
        return jsonResponse({
          id: BANK_ID,
          environment: "sandbox",
          bank_name: "Chase",
          bank_mask: "0000",
          bank_last4: "0000",
          status: "active",
          ready: true,
          readiness_reason: "ready",
          access_token: "access-sandbox-should-never-appear",
          link_token: "link-sandbox-should-never-appear",
        });
      }
      throw new Error(`unexpected fetch: ${url}`);
    });
    const stdout = makeStdout();
    const code = await runCli(["--format", "json", "plaid", "banks", "get", BANK_ID], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    // Exactly one request to the per-id route; never GET /v1/admin/plaid/bank-accounts (list+filter).
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const calledUrl = String(fetchMock.mock.calls[0]?.[0]);
    expect(calledUrl).toContain(`/v1/admin/plaid/bank-accounts/${BANK_ID}`);
    const output = stdout.chunks.join("");
    const payload = JSON.parse(output);
    expect(payload.data.bank_account.id).toBe(BANK_ID);
    expect(payload.data.bank_account.bank_name).toBe("Chase");
    // Secret boundary: Link/access tokens must never reach CLI output.
    expect(output).not.toContain("access-sandbox-should-never-appear");
    expect(output).not.toContain("link-sandbox-should-never-appear");
    expect(payload.data.bank_account.access_token).toBeUndefined();
    expect(payload.data.bank_account.link_token).toBeUndefined();
  });

  it("maps an unknown/cross-tenant id to cli.plaid.bank_not_found", async () => {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: "plaid_bank_not_found", message: "Linked bank not found." }, 404),
    );
    const stdout = makeStdout();
    const stderr = makeStdout();
    const code = await runCli(["--format", "json", "plaid", "banks", "get", BANK_ID], {
      fetch: fetchMock,
      stdout,
      stderr,
    });
    vi.unstubAllEnvs();
    expect(code).not.toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("cli.plaid.bank_not_found");
    expect(payload.error.details?.reason_code).toBe("plaid_bank_not_found");
  });

  it("keeps feature_disabled 404s distinct from bank_not_found", async () => {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const fetchMock = vi.fn(async () =>
      jsonResponse({ error: "feature_disabled", message: "Plaid Auth is disabled on this deployment." }, 404),
    );
    const stdout = makeStdout();
    const code = await runCli(["--format", "json", "plaid", "banks", "get", BANK_ID], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).not.toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("feature_disabled");
    expect(payload.error.code).not.toBe("cli.plaid.bank_not_found");
    expect(payload.error.details?.gateway_code).toBe("feature_disabled");
  });

  it("keeps production_not_allowlisted 404s distinct from bank_not_found", async () => {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        { error: "production_not_allowlisted", message: "Plaid Auth is not enabled for this tenant." },
        404,
      ),
    );
    const stdout = makeStdout();
    const code = await runCli(["--format", "json", "plaid", "banks", "get", BANK_ID], {
      fetch: fetchMock,
      stdout,
    });
    vi.unstubAllEnvs();
    expect(code).not.toBe(0);
    const payload = JSON.parse(stdout.chunks.join(""));
    expect(payload.ok).toBe(false);
    expect(payload.error.code).toBe("production_not_allowlisted");
    expect(payload.error.code).not.toBe("cli.plaid.bank_not_found");
    expect(payload.error.details?.gateway_code).toBe("production_not_allowlisted");
  });
});
