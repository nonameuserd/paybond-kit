import { readFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

declare const process: {
  cwd(): string;
};

/** Resolve bundled or monorepo dev trace dashboard HTML. */
export function resolveDevTraceUiDashboardPath(cwd = process.cwd()): string {
  const candidates = [
    join(cwd, "kit/dev/trace-ui/dashboard.html"),
    join(MODULE_DIR, "../../dev/trace-ui/dashboard.html"),
    join(MODULE_DIR, "../../../dev/trace-ui/dashboard.html"),
    join(MODULE_DIR, "../../../../dev/trace-ui/dashboard.html"),
    join(MODULE_DIR, "../../../../../kit/dev/trace-ui/dashboard.html"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error(
    "Dev trace dashboard not found. Run from the Paybond monorepo or install @paybond/kit with bundled dev assets.",
  );
}

/** Load the self-contained dev trace dashboard HTML shell. */
export function loadDevTraceDashboardHtml(cwd = process.cwd()): string {
  return readFileSync(resolveDevTraceUiDashboardPath(cwd), "utf8");
}
