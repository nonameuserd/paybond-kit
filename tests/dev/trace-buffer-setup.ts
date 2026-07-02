import { beforeEach } from "vitest";

import { clearDevTraceEvents } from "../../src/dev/trace-buffer.js";

beforeEach(() => {
  clearDevTraceEvents();
});
