import type { CliErrorDetails } from "./types.js";

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

/**
 * Summarize an HTTP error body for operator-facing CLI output.
 * Never includes raw edge payloads (Cloudflare ray IDs, zones, HTML, etc.).
 */
export function summarizeGatewayHttpError(
  statusCode: number,
  bodyText: string,
): { message: string; details: CliErrorDetails } {
  const trimmed = bodyText.trim();
  if (!trimmed) {
    return {
      message: `Gateway HTTP ${statusCode}`,
      details: { gateway_status: statusCode },
    };
  }

  try {
    const body = JSON.parse(trimmed) as JsonRecord;

    if (body.cloudflare_error === true) {
      const retryAfter =
        typeof body.retry_after === "number" ? body.retry_after : undefined;
      const title =
        typeof body.title === "string"
          ? body.title.replace(/^Error \d+:\s*/i, "")
          : "service temporarily unavailable";
      let message = `Gateway unavailable (HTTP ${statusCode}): ${title}`;
      if (retryAfter !== undefined) {
        message += `. Retry after ${retryAfter} seconds.`;
      }
      return {
        message,
        details: {
          gateway_status: statusCode,
          ...(retryAfter !== undefined ? { retry_after: retryAfter } : {}),
        },
      };
    }

    const nested = asRecord(body.error);
    if (nested) {
      const gatewayCode =
        typeof nested.code === "string" ? nested.code : String(nested.code ?? "");
      const gatewayMessage =
        typeof nested.message === "string" ? nested.message : "";
      if (gatewayMessage) {
        return {
          message: gatewayMessage,
          details: {
            gateway_status: statusCode,
            ...(gatewayCode ? { gateway_code: gatewayCode } : {}),
          },
        };
      }
    }

    const flatMessage = typeof body.message === "string" ? body.message : "";
    if (flatMessage) {
      const gatewayCode = typeof body.code === "string" ? body.code : "";
      return {
        message: flatMessage,
        details: {
          gateway_status: statusCode,
          ...(gatewayCode ? { gateway_code: gatewayCode } : {}),
        },
      };
    }

    if (typeof body.title === "string") {
      const detail = typeof body.detail === "string" ? body.detail : "";
      const combined = detail ? `${body.title}: ${detail}` : body.title;
      const message =
        combined.length > 240 ? `${combined.slice(0, 237)}...` : combined;
      return {
        message,
        details: { gateway_status: statusCode },
      };
    }
  } catch {
    // Non-JSON bodies must not be echoed (HTML, stack traces, etc.).
  }

  return {
    message: `Gateway HTTP ${statusCode}`,
    details: { gateway_status: statusCode },
  };
}

/**
 * Build a CLI-safe message for SDK HTTP failures that embed raw bodies in `.message`.
 */
export function formatSdkHttpErrorMessage(
  rawMessage: string,
  statusCode: number,
  bodyText: string,
): string {
  const operation = rawMessage.replace(/ HTTP \d+:[\s\S]*$/u, "").trim() || "Gateway request";
  const summary = summarizeGatewayHttpError(statusCode, bodyText);
  if (summary.message === `Gateway HTTP ${statusCode}`) {
    return `${operation} HTTP ${statusCode}`;
  }
  if (summary.message.startsWith("Gateway unavailable")) {
    return `${operation}: ${summary.message}`;
  }
  return `${operation} HTTP ${statusCode}: ${summary.message}`;
}
