import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  DEV_WIREMOCK_CONTAINER_NAME,
  DEV_WIREMOCK_DEFAULT_PORT,
} from "./offline-gateway.js";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

declare const process: {
  cwd(): string;
};

export type DevWiremockUpOptions = {
  port?: number;
  down?: boolean;
};

export type DevWiremockUpResult = {
  gateway_url: string;
  port: number;
  wiremock_dir: string;
  container_name: string;
  status: "started" | "already_running" | "stopped";
  next_commands: string[];
};

function spawnCommand(command: string, args: string[]): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout?.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    child.stderr?.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
      });
    });
  });
}

/** Resolve bundled or monorepo WireMock mapping directory for `paybond dev up`. */
export function resolveDevWiremockDir(cwd = process.cwd()): string {
  const candidates = [
    join(cwd, "examples/partner-dry-run-wiremock/gateway-wiremock"),
    join(cwd, "kit/dev/wiremock"),
    join(MODULE_DIR, "../../../dev/wiremock"),
    join(MODULE_DIR, "../../../../dev/wiremock"),
    join(MODULE_DIR, "../../../../../kit/dev/wiremock"),
  ];
  for (const candidate of candidates) {
    if (existsSync(join(candidate, "mappings"))) {
      return candidate;
    }
  }
  throw new Error(
    "WireMock mappings not found. Run from the Paybond monorepo or install @paybond/kit with bundled dev assets.",
  );
}

async function dockerContainerRunning(name: string): Promise<boolean> {
  const result = await spawnCommand("docker", ["inspect", "-f", "{{.State.Running}}", name]);
  return result.code === 0 && result.stdout.trim() === "true";
}

async function waitWiremockReady(baseUrl: string, attempts = 40, delayMs = 250): Promise<void> {
  const adminUrl = `${baseUrl.replace(/\/+$/, "")}/__admin/mappings`;
  let lastError: unknown;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      const response = await fetch(adminUrl, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) {
        return;
      }
    } catch (err) {
      lastError = err;
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(`WireMock not ready at ${adminUrl}: ${String(lastError)}`);
}

function buildNextCommands(gatewayUrl: string): string[] {
  return [
    `paybond dev loop --gateway ${gatewayUrl} --no-login`,
    "paybond dev smoke --offline",
    "paybond dev trace",
  ];
}

export async function runDevWiremockUp(options: DevWiremockUpOptions = {}): Promise<DevWiremockUpResult> {
  const port = options.port ?? DEV_WIREMOCK_DEFAULT_PORT;
  const gatewayUrl = `http://127.0.0.1:${port}`;
  const wiremockDir = resolveDevWiremockDir();

  if (options.down) {
    if (await dockerContainerRunning(DEV_WIREMOCK_CONTAINER_NAME)) {
      await spawnCommand("docker", ["rm", "-f", DEV_WIREMOCK_CONTAINER_NAME]);
    }
    return {
      gateway_url: gatewayUrl,
      port,
      wiremock_dir: wiremockDir,
      container_name: DEV_WIREMOCK_CONTAINER_NAME,
      status: "stopped",
      next_commands: [],
    };
  }

  if (await dockerContainerRunning(DEV_WIREMOCK_CONTAINER_NAME)) {
    return {
      gateway_url: gatewayUrl,
      port,
      wiremock_dir: wiremockDir,
      container_name: DEV_WIREMOCK_CONTAINER_NAME,
      status: "already_running",
      next_commands: buildNextCommands(gatewayUrl),
    };
  }

  const run = await spawnCommand("docker", [
    "run",
    "-d",
    "--name",
    DEV_WIREMOCK_CONTAINER_NAME,
    "-p",
    `${port}:8080`,
    "-v",
    `${wiremockDir}:/home/wiremock`,
    "wiremock/wiremock:3.3.1",
  ]);
  if (run.code !== 0) {
    throw new Error(run.stderr.trim() || run.stdout.trim() || "docker run failed");
  }

  await waitWiremockReady(gatewayUrl);
  return {
    gateway_url: gatewayUrl,
    port,
    wiremock_dir: wiremockDir,
    container_name: DEV_WIREMOCK_CONTAINER_NAME,
    status: "started",
    next_commands: buildNextCommands(gatewayUrl),
  };
}
