#!/usr/bin/env node
/** @deprecated Use kit/scripts/sync-completion-catalog.mjs */
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const syncScript = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "sync-completion-catalog.mjs");
const result = spawnSync(process.execPath, [syncScript], { stdio: "inherit" });
process.exit(result.status ?? 1);
