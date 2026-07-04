/** Cap Cloudflare edge retry hints so CLI flows do not block for a full minute. */
export const CLOUDFLARE_EDGE_MAX_RETRY_DELAY_MS = 8_000;

type JsonRecord = Record<string, unknown>;

export function parseCloudflareRetryAfterMs(bodyText: string): number | null {
  if (!isCloudflareEdgeErrorBody(bodyText)) {
    return null;
  }
  try {
    const body = JSON.parse(bodyText.trim()) as JsonRecord;
    const raw = body.retry_after;
    if (typeof raw !== "number" || !Number.isFinite(raw)) {
      return null;
    }
    return Math.min(raw * 1000, CLOUDFLARE_EDGE_MAX_RETRY_DELAY_MS);
  } catch {
    return null;
  }
}

/** True when the body is a Cloudflare-generated edge error (not Paybond gateway JSON). */
export function isCloudflareEdgeErrorBody(bodyText: string): boolean {
  const trimmed = bodyText.trim();
  if (!trimmed) {
    return false;
  }
  try {
    const body = JSON.parse(trimmed) as JsonRecord;
    return body.cloudflare_error === true;
  } catch {
    return false;
  }
}

/** Whether an HTTP status/body pair should be retried by SDK gateway clients. */
export function shouldRetryGatewayHttpStatus(status: number, bodyText: string): boolean {
  if (![429, 500, 502, 503, 504].includes(status)) {
    return false;
  }
  if (isCloudflareEdgeErrorBody(bodyText)) {
    return false;
  }
  return true;
}

/** Inspect a response body (via clone) to decide whether to retry transient gateway errors. */
export async function shouldRetryGatewayResponse(res: Response): Promise<boolean> {
  if (![429, 500, 502, 503, 504].includes(res.status)) {
    return false;
  }
  const peek = await res.clone().text();
  return shouldRetryGatewayHttpStatus(res.status, peek);
}

export function backoffMs(attempt: number): number {
  const base = 200 * 2 ** attempt;
  const jitter = Math.random() * 100;
  return Math.min(base + jitter, 5000);
}

export function parseRetryAfterSeconds(value: string | null): number | null {
  if (!value) {
    return null;
  }
  const n = Number.parseFloat(value.trim());
  if (!Number.isFinite(n)) {
    return null;
  }
  return Math.min(n, 30);
}

/** Prefer `Retry-After` when present; otherwise exponential backoff with jitter. */
export function gatewayRetryDelayMs(
  attempt: number,
  retryAfterHeader: string | null,
): number {
  const raSec = parseRetryAfterSeconds(retryAfterHeader);
  return raSec != null ? raSec * 1000 : backoffMs(attempt);
}

/**
 * Shared 429/5xx retry loop for Paybond gateway HTTP clients.
 * Skips retries on Cloudflare edge error bodies. Returns the response on success;
 * otherwise throws the last network error.
 */
export async function fetchWithGatewayRetries(
  url: string,
  init: RequestInit,
  maxRetries: number,
): Promise<Response> {
  let lastErr: unknown;
  let cloudflareRetries = 0;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, init);
    } catch (e) {
      lastErr = e;
      if (attempt + 1 >= maxRetries) {
        throw e;
      }
      await new Promise((r) => setTimeout(r, gatewayRetryDelayMs(attempt, null)));
      continue;
    }
    if ([429, 500, 502, 503, 504].includes(res.status) && attempt + 1 < maxRetries) {
      const bodyText = await res.clone().text();
      if (isCloudflareEdgeErrorBody(bodyText)) {
        if (cloudflareRetries >= 1) {
          return res;
        }
        cloudflareRetries += 1;
        const delayMs =
          parseCloudflareRetryAfterMs(bodyText) ??
          gatewayRetryDelayMs(attempt, res.headers.get("retry-after"));
        await new Promise((r) => setTimeout(r, delayMs));
        continue;
      }
      if (!(await shouldRetryGatewayResponse(res))) {
        return res;
      }
      await new Promise((r) =>
        setTimeout(r, gatewayRetryDelayMs(attempt, res.headers.get("retry-after"))),
      );
      continue;
    }
    return res;
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}
