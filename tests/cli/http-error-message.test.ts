import { describe, expect, it } from "vitest";
import {
  formatSdkHttpErrorMessage,
  resolveCliGatewayErrorMessage,
  summarizeGatewayHttpError,
} from "../../src/cli/http-error-message.js";
import { PaybondAutoEvidenceSubmitError } from "../../src/agent/types.js";
import { HarborHttpError } from "../../src/index.js";

const CLOUDFLARE_502 = JSON.stringify({
  type: "https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-5xx-errors/error-502/",
  title: "Error 502: Bad gateway",
  status: 502,
  detail: "The origin web server returned an invalid or incomplete response to Cloudflare.",
  instance: "a1538c5f4cc5c6f0",
  error_code: 502,
  error_name: "origin_bad_gateway",
  ray_id: "a1538c5f4cc5c6f0",
  timestamp: "2026-07-03T05:39:12Z",
  zone: "api.paybond.ai",
  cloudflare_error: true,
  retryable: true,
  retry_after: 60,
});

describe("summarizeGatewayHttpError", () => {
  it("redacts Cloudflare edge payloads", () => {
    const { message, details } = summarizeGatewayHttpError(502, CLOUDFLARE_502);
    expect(message).toBe(
      "gateway edge error (HTTP 502); upstream response was masked by the edge proxy. Retry after 60 seconds",
    );
    expect(message).not.toContain("ray_id");
    expect(message).not.toContain("api.paybond.ai");
    expect(message).not.toContain("Bad gateway");
    expect(details).toEqual({ gateway_status: 502, cloudflare_error: true, retry_after: 60 });
  });

  it("surfaces Paybond gateway validation messages", () => {
    const body = JSON.stringify({
      error: {
        code: "validation_error",
        message: "completion_preset and template_id cannot both be set",
      },
    });
    const { message, details } = summarizeGatewayHttpError(400, body);
    expect(message).toBe("completion_preset and template_id cannot both be set");
    expect(details.gateway_code).toBe("validation_error");
  });

  it("does not echo non-JSON bodies", () => {
    const { message } = summarizeGatewayHttpError(502, "<html>secret stack</html>");
    expect(message).toBe("Gateway HTTP 502");
  });
});

describe("formatSdkHttpErrorMessage", () => {
  it("surfaces Harbor sandbox guardrail rejections without HTTP noise", () => {
    const body = JSON.stringify({
      error: {
        code: "harbor_evidence_failed",
        message:
          'sandbox guardrail Harbor evidence rejected: predicate evaluation error: missing key "status"',
        harbor_status: 422,
        harbor_code: "predicate_error",
      },
    });
    const raw = `Gateway sandbox guardrail evidence HTTP 422: ${body}`;
    const message = formatSdkHttpErrorMessage(raw, 422, body);
    expect(message).toBe(
      'sandbox guardrail Harbor evidence rejected: predicate evaluation error: missing key "status"',
    );
  });

  it("formats sandbox bootstrap failures without raw JSON", () => {
    const raw = `Gateway sandbox guardrail bootstrap HTTP 502: ${CLOUDFLARE_502}`;
    const message = formatSdkHttpErrorMessage(raw, 502, CLOUDFLARE_502);
    expect(message).toBe(
      "sandbox guardrail Harbor bootstrap rejected (gateway unavailable; check sandbox guardrail bootstrap inputs)",
    );
    expect(message).not.toContain("cloudflare.com");
  });

  it("formats generic gateway failures masked by Cloudflare", () => {
    const raw = `Gateway intent create HTTP 502: ${CLOUDFLARE_502}`;
    const message = formatSdkHttpErrorMessage(raw, 502, CLOUDFLARE_502);
    expect(message).toBe(
      "Gateway intent create: gateway edge error (HTTP 502); upstream response was masked by the edge proxy. Retry after 60 seconds",
    );
    expect(message).not.toContain("Bad gateway");
  });
});

describe("resolveCliGatewayErrorMessage", () => {
  it("redacts HarborHttpError causes on auto-evidence failures", () => {
    const harbor = new HarborHttpError(`Gateway sandbox guardrail evidence HTTP 502: ${CLOUDFLARE_502}`, {
      statusCode: 502,
      url: "https://api.paybond.ai/v1/sandbox/guardrails/x/evidence",
      bodyText: CLOUDFLARE_502,
    });
    const err = new PaybondAutoEvidenceSubmitError({ status: "completed" }, harbor);
    const message = resolveCliGatewayErrorMessage(err);
    expect(message).toBe(
      "sandbox guardrail Harbor evidence rejected (gateway unavailable; check --result-body includes top-level status and cost_cents)",
    );
    expect(message).not.toContain("cloudflare.com");
    expect(message).not.toContain("Bad gateway");
  });

  it("redacts legacy messages that embedded raw JSON bodies", () => {
    const legacy = new Error(`Gateway sandbox guardrail evidence HTTP 502: ${CLOUDFLARE_502}`);
    const message = resolveCliGatewayErrorMessage(legacy);
    expect(message).toBe(
      "sandbox guardrail Harbor evidence rejected (gateway unavailable; check --result-body includes top-level status and cost_cents)",
    );
  });
});
