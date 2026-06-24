import { v4 as uuidv4 } from "uuid";

/** Generate a correlation id suitable for Gateway request headers and JSON envelopes. */
export function generateRequestId(): string {
  return `01${uuidv4().replace(/-/g, "").slice(0, 24).toUpperCase()}`;
}
