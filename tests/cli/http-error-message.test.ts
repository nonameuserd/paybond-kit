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
      "Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds.",
    );
    expect(message).not.toContain("ray_id");
    expect(message).not.toContain("api.paybond.ai");
    expect(details).toEqual({ gateway_status: 502, retry_after: 60 });
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
  it("formats sandbox bootstrap failures without raw JSON", () => {
    const raw = `Gateway sandbox guardrail bootstrap HTTP 502: ${CLOUDFLARE_502}`;
    const message = formatSdkHttpErrorMessage(raw, 502, CLOUDFLARE_502);
    expect(message).toBe(
      "Gateway sandbox guardrail bootstrap: Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds.",
    );
    expect(message).not.toContain("cloudflare.com");
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
      "Gateway sandbox guardrail evidence: Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds.",
    );
    expect(message).not.toContain("cloudflare.com");
  });

  it("redacts legacy messages that embedded raw JSON bodies", () => {
    const legacy = new Error(`Gateway sandbox guardrail evidence HTTP 502: ${CLOUDFLARE_502}`);
    const message = resolveCliGatewayErrorMessage(legacy);
    expect(message).toBe(
      "Gateway sandbox guardrail evidence: Gateway unavailable (HTTP 502): Bad gateway. Retry after 60 seconds.",
    );
  });
});
