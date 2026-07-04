import type { CliErrorDetails } from "./types.js";

type JsonRecord = Record<string, unknown>;

const HARBOR_REJECT_PREFIX = "sandbox guardrail Harbor ";
const HARBOR_GATEWAY_CODES = new Set(["harbor_evidence_failed", "harbor_create_failed"]);

function asRecord(value: unknown): JsonRecord | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : undefined;
}

function sandboxGuardrailPhaseFromOperation(operation: string): string | undefined {
  const lowered = operation.toLowerCase();
  if (lowered.includes("sandbox guardrail evidence")) {
    return "evidence";
  }
  if (lowered.includes("sandbox guardrail bootstrap")) {
    return "bootstrap";
  }
  return undefined;
}

function sandboxGuardrailHarborCloudflareFallback(operation: string): string {
  const phase = sandboxGuardrailPhaseFromOperation(operation) ?? "request";
  const hint =
    phase === "evidence"
      ? "check --result-body includes top-level status and cost_cents"
      : "check sandbox guardrail bootstrap inputs";
  return `sandbox guardrail Harbor ${phase} rejected (gateway unavailable; ${hint})`;
}

function cloudflareEdgeSummaryMessage(
  statusCode: number,
  retryAfter: number | undefined,
): string {
  let message = `gateway edge error (HTTP ${statusCode}); upstream response was masked by the edge proxy`;
  if (retryAfter !== undefined) {
    message += `. Retry after ${retryAfter} seconds`;
  }
  return message;
}

function formatCloudflareCliMessage(
  operation: string,
  statusCode: number,
  retryAfter: number | undefined,
): string {
  if (sandboxGuardrailPhaseFromOperation(operation) !== undefined) {
    return sandboxGuardrailHarborCloudflareFallback(operation);
  }
  return `${operation}: ${cloudflareEdgeSummaryMessage(statusCode, retryAfter)}`;
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
      const message = cloudflareEdgeSummaryMessage(statusCode, retryAfter);
      return {
        message,
        details: {
          gateway_status: statusCode,
          cloudflare_error: true,
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
      const harborCode =
        typeof nested.harbor_code === "string" ? nested.harbor_code : "";
      if (gatewayMessage) {
        const harborRejection =
          gatewayMessage.startsWith(HARBOR_REJECT_PREFIX) ||
          harborCode.length > 0 ||
          HARBOR_GATEWAY_CODES.has(gatewayCode);
        return {
          message: gatewayMessage,
          details: {
            gateway_status: statusCode,
            ...(gatewayCode ? { gateway_code: gatewayCode } : {}),
            ...(harborCode ? { harbor_code: harborCode } : {}),
            ...(harborRejection ? { harbor_rejection: true } : {}),
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
  if (summary.details.harbor_rejection) {
    return summary.message;
  }
  if (summary.details.cloudflare_error === true) {
    const retryAfter =
      typeof summary.details.retry_after === "number"
        ? summary.details.retry_after
        : undefined;
    return formatCloudflareCliMessage(operation, statusCode, retryAfter);
  }
  if (summary.message === `Gateway HTTP ${statusCode}`) {
    return `${operation} HTTP ${statusCode}`;
  }
  return `${operation} HTTP ${statusCode}: ${summary.message}`;
}

type SdkHttpErrorLike = {
  message: string;
  statusCode: number;
  bodyText: string;
};

function isSdkHttpErrorLike(err: unknown): err is SdkHttpErrorLike {
  if (!err || typeof err !== "object") {
    return false;
  }
  const candidate = err as SdkHttpErrorLike;
  return (
    typeof candidate.message === "string" &&
    typeof candidate.statusCode === "number" &&
    typeof candidate.bodyText === "string"
  );
}

function parseEmbeddedHttpErrorBody(
  message: string,
): { statusCode: number; bodyText: string } | undefined {
  const match = / HTTP (\d{3}):\s*(\{[\s\S]*\})\s*$/u.exec(message);
  if (!match) {
    return undefined;
  }
  return {
    statusCode: Number(match[1]),
    bodyText: match[2] ?? "",
  };
}

function extractSdkHttpError(err: unknown): SdkHttpErrorLike | undefined {
  const chain: unknown[] = [];
  let current: unknown = err;
  while (current) {
    chain.push(current);
    current =
      current instanceof Error && "cause" in current
        ? (current as Error & { cause?: unknown }).cause
        : undefined;
  }
  for (const item of chain) {
    if (isSdkHttpErrorLike(item)) {
      return item;
    }
  }
  return undefined;
}

/**
 * Resolve a CLI-safe gateway error message from SDK or agent middleware failures.
 * Never echoes Cloudflare edge JSON, HTML, or raw upstream bodies.
 */
export function resolveCliGatewayErrorMessage(err: unknown): string {
  const sdkError = extractSdkHttpError(err);
  if (sdkError) {
    return formatSdkHttpErrorMessage(
      sdkError.message,
      sdkError.statusCode,
      sdkError.bodyText,
    );
  }
  if (err instanceof Error) {
    const embedded = parseEmbeddedHttpErrorBody(err.message);
    if (embedded) {
      const operation = err.message.replace(/ HTTP \d{3}:[\s\S]*$/u, "").trim() || "Gateway request";
      return formatSdkHttpErrorMessage(
        operation,
        embedded.statusCode,
        embedded.bodyText,
      );
    }
    return err.message;
  }
  return String(err);
}
