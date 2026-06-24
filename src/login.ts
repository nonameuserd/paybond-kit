#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { runCli } from "./cli/router.js";

declare const process: {
  argv: string[];
  cwd(): string;
  exitCode?: number;
  platform: string;
  stderr: { write(chunk: string): boolean };
  stdout: { write(chunk: string): boolean };
};

const DEFAULT_GATEWAY = "https://api.paybond.ai";
const DEFAULT_ENV_FILE = ".env.local";
const CLIENT_ID = "paybond-kit-cli";
const CLIENT_NAME = "Paybond CLI";
const DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
const MIN_POLL_INTERVAL_SECONDS = 1;
const DEFAULT_DEVICE_EXPIRES_IN_SECONDS = 600;
const DEFAULT_DEVICE_POLL_INTERVAL_SECONDS = 5;
const MS_PER_SECOND = 1_000;
const DEVICE_EXPIRY_GRACE_MS = MS_PER_SECOND;
const PROCESS_EXIT_SUCCESS = 0;
const SPAWN_COMMAND_NOT_FOUND_EXIT_CODE = 127;
const GIT_CHECK_IGNORE_MATCHED = PROCESS_EXIT_SUCCESS;
const GIT_CHECK_IGNORE_NOT_MATCHED = 1;
const MAX_GIT_WORKTREE_WALK_DEPTH = 256;
const ENV_FILE_MODE = 0o600;
const GITIGNORE_FILE_MODE = 0o644;
const API_KEY_MASK_MIN_PARTS = 5;
const API_KEY_MASK_MIN_ID_LENGTH = 12;
const API_KEY_MASK_ID_PREFIX_LENGTH = 8;
const API_KEY_MASK_ID_SUFFIX_LENGTH = 4;

type Writable = { write(chunk: string): boolean };

export type DeviceEnvironment = "sandbox";

export type LoginOptions = {
  envFile: string;
  gateway: string;
  environment: DeviceEnvironment;
  noOpen: boolean;
  force: boolean;
};

export type LoginResult = {
  envPath: string;
  keyMasked: string;
  keyWritten: true;
  environment: DeviceEnvironment;
  tenantId: string;
  tenantUuid: string;
  expiresAt?: string;
  verificationUri: string;
  userCode: string;
};

type DeviceStartResponse = {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
};

type DeviceTokenResponse = {
  access_token: string;
  token_type: string;
  tenant_id: string;
  tenant_uuid: string;
  environment: string;
  service_account_role: string;
  expires_at: string;
};

type OAuthErrorResponse = {
  error: string;
  error_description?: string;
  interval?: number;
};

type FetchInput = string | URL;
type FetchInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};
type FetchLike = (input: FetchInput, init?: FetchInit) => Promise<Response>;

export type LoginDependencies = {
  cwd?: string;
  fetch?: FetchLike;
  sleep?: (ms: number) => Promise<void>;
  openBrowser?: (url: string) => Promise<boolean>;
  stdout?: Writable;
  stderr?: Writable;
  now?: () => number;
  /** When false, suppress human-readable progress lines (for JSON CLI output). */
  humanOutput?: boolean;
};

class PaybondLoginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PaybondLoginError";
  }
}

class OAuthPollError extends PaybondLoginError {
  readonly code: string;
  readonly interval?: number;

  constructor(body: OAuthErrorResponse) {
    super(body.error_description?.trim() || body.error);
    this.name = "OAuthPollError";
    this.code = body.error;
    this.interval = body.interval;
  }
}

function usage(): string {
  return [
    "Usage: paybond login [--env sandbox] [--env-file .env.local] [--gateway https://api.paybond.ai] [--no-open] [--force]",
    "",
    "Starts a device login and writes PAYBOND_API_KEY to a local env file.",
    "The default .env.local target is added to .gitignore when needed.",
    "Defaults to the sandbox environment. Production keys are created in Console and stored in secret managers.",
  ].join("\n");
}

function parseEnvironment(raw: string): DeviceEnvironment {
  const value = raw.trim().toLowerCase();
  if (value === "sandbox") {
    return value;
  }
  if (value === "live") {
    throw new PaybondLoginError(
      "live device login is not supported; create production keys in Console and store them in a secret manager",
    );
  }
  throw new PaybondLoginError("invalid --env (expected sandbox)");
}

export function parseArgs(argv: string[]): LoginOptions | "help" {
  if (argv.length === 0) {
    throw new PaybondLoginError(`missing command: login\n\n${usage()}`);
  }
  const [command, ...rest] = argv;
  if (command === "--help" || command === "-h") {
    return "help";
  }
  if (command !== "login") {
    throw new PaybondLoginError(`unknown command: ${command}\n\n${usage()}`);
  }

  let envFile = DEFAULT_ENV_FILE;
  let gateway = DEFAULT_GATEWAY;
  let environment: DeviceEnvironment = "sandbox";
  let noOpen = false;
  let force = false;

  for (let i = 0; i < rest.length; i += 1) {
    const arg = rest[i]!;
    if (arg === "--help" || arg === "-h") {
      return "help";
    }
    if (arg === "--no-open") {
      noOpen = true;
      continue;
    }
    if (arg === "--force") {
      force = true;
      continue;
    }
    if (arg === "--live") {
      throw new PaybondLoginError(
        "live device login is not supported; create production keys in Console and store them in a secret manager",
      );
    }
    if (arg === "--env" || arg.startsWith("--env=")) {
      const raw = arg === "--env" ? rest[++i] : arg.slice("--env=".length);
      if (!raw || raw.startsWith("-")) {
        throw new PaybondLoginError("invalid --env (expected sandbox)");
      }
      environment = parseEnvironment(raw);
      continue;
    }
    if (arg === "--env-file" || arg.startsWith("--env-file=")) {
      const raw =
        arg === "--env-file" ? rest[++i] : arg.slice("--env-file=".length);
      if (!raw || raw.startsWith("-")) {
        throw new PaybondLoginError("invalid --env-file");
      }
      envFile = raw;
      continue;
    }
    if (arg === "--gateway" || arg.startsWith("--gateway=")) {
      const raw =
        arg === "--gateway" ? rest[++i] : arg.slice("--gateway=".length);
      if (!raw || raw.startsWith("-")) {
        throw new PaybondLoginError("invalid --gateway");
      }
      gateway = raw;
      continue;
    }
    throw new PaybondLoginError(`unknown argument: ${arg}`);
  }

  if (!envFile.trim()) {
    throw new PaybondLoginError("invalid --env-file");
  }
  if (!gateway.trim()) {
    throw new PaybondLoginError("invalid --gateway");
  }

  return { envFile, gateway, environment, noOpen, force };
}

function envKeyPattern(): RegExp {
  return /^\s*(?:export\s+)?PAYBOND_API_KEY\s*=/m;
}

function quoteEnvValue(value: string): string {
  if (/^[A-Za-z0-9_./:@+-]+$/.test(value)) {
    return value;
  }
  return JSON.stringify(value);
}

function replaceOrAppendEnvValue(
  existing: string,
  rawKey: string,
  force: boolean,
): string {
  const line = `PAYBOND_API_KEY=${quoteEnvValue(rawKey)}`;
  const pattern = /^(\s*(?:export\s+)?PAYBOND_API_KEY\s*=).*$/m;
  if (pattern.test(existing)) {
    if (!force) {
      throw new PaybondLoginError(
        "PAYBOND_API_KEY already exists in the target env file; pass --force to replace it.",
      );
    }
    return existing.replace(pattern, line);
  }
  const suffix = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  return `${existing}${suffix}${line}\n`;
}

async function spawnCommand(
  command: string,
  args: string[],
  cwd: string,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return await new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: unknown) => {
      stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk: unknown) => {
      stderr += String(chunk);
    });
    child.on("error", (err: Error) => {
      resolve({ code: SPAWN_COMMAND_NOT_FOUND_EXIT_CODE, stdout: "", stderr: err.message });
    });
    child.on("close", (code: number | null) => {
      resolve({ code, stdout, stderr });
    });
  });
}

async function resolveEnvFile(envFile: string, cwd: string): Promise<string> {
  return path.isAbsolute(envFile) ? path.resolve(envFile) : path.resolve(cwd, envFile);
}

export async function assertGitIgnored(
  envPath: string,
  cwd: string,
): Promise<void> {
  await ensureGitIgnored(envPath, cwd, false);
}

async function inGitWorkTree(start: string): Promise<boolean> {
  let current = path.resolve(start);
  for (let depth = 0; depth < MAX_GIT_WORKTREE_WALK_DEPTH; depth += 1) {
    try {
      await fs.access(path.join(current, ".git"));
      return true;
    } catch {
      // continue walking parents
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return false;
    }
    current = parent;
  }
  return false;
}

function gitMissingForSecretWriteError(): PaybondLoginError {
  return new PaybondLoginError(
    "git is required to verify the env file is ignored before writing secrets; install git or pass --env-file outside the repository",
  );
}

async function ensureGitIgnored(
  envPath: string,
  cwd: string,
  autoAddDefaultEnvFile: boolean,
): Promise<void> {
  const rootResult = await spawnCommand(
    "git",
    ["rev-parse", "--show-toplevel"],
    cwd,
  );
  if (rootResult.code !== 0) {
    if (rootResult.code === SPAWN_COMMAND_NOT_FOUND_EXIT_CODE || /ENOENT/i.test(rootResult.stderr)) {
      if (await inGitWorkTree(cwd)) {
        throw gitMissingForSecretWriteError();
      }
    }
    return;
  }
  const repoRoot = await fs.realpath(path.resolve(rootResult.stdout.trim()));
  const targetDir = await fs.realpath(path.dirname(path.resolve(envPath)));
  const target = path.resolve(targetDir, path.basename(envPath));
  const relativeTarget = path.relative(repoRoot, target);
  if (
    relativeTarget !== "" &&
    (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget))
  ) {
    return;
  }

  const ignoreResult = await spawnCommand(
    "git",
    ["-C", repoRoot, "check-ignore", "--quiet", "--", relativeTarget],
    cwd,
  );
  if (ignoreResult.code === GIT_CHECK_IGNORE_MATCHED) {
    return;
  }
  if (ignoreResult.code === GIT_CHECK_IGNORE_NOT_MATCHED) {
    if (autoAddDefaultEnvFile && relativeTarget === DEFAULT_ENV_FILE) {
      const gitignorePath = path.resolve(repoRoot, ".gitignore");
      let existing = "";
      try {
        existing = await fs.readFile(gitignorePath, "utf8");
      } catch (err) {
        if (
          !(
            err &&
            typeof err === "object" &&
            "code" in err &&
            err.code === "ENOENT"
          )
        ) {
          throw err;
        }
      }
      const suffix =
        existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
      await fs.writeFile(
        gitignorePath,
        `${existing}${suffix}${DEFAULT_ENV_FILE}\n`,
        { encoding: "utf8", mode: GITIGNORE_FILE_MODE },
      );
      const recheck = await spawnCommand(
        "git",
        ["-C", repoRoot, "check-ignore", "--quiet", "--", relativeTarget],
        cwd,
      );
      if (recheck.code === GIT_CHECK_IGNORE_MATCHED) {
        return;
      }
    }
    throw new PaybondLoginError(
      `Refusing to write ${target} because it is not ignored by git. Add ${relativeTarget} to .gitignore or pass --env-file pointing outside the repo.`,
    );
  }
  throw new PaybondLoginError(
    `Unable to verify git ignore status for ${target}: ${ignoreResult.stderr.trim() || "git check-ignore failed"}`,
  );
}

export async function assertCanWriteEnvFile(
  envPath: string,
  force: boolean,
): Promise<void> {
  try {
    const existing = await fs.readFile(envPath, "utf8");
    if (envKeyPattern().test(existing) && !force) {
      throw new PaybondLoginError(
        "PAYBOND_API_KEY already exists in the target env file; pass --force to replace it.",
      );
    }
  } catch (err) {
    if (
      err &&
      typeof err === "object" &&
      "code" in err &&
      err.code === "ENOENT"
    ) {
      return;
    }
    throw err;
  }
}

export async function writeEnvFile(
  envPath: string,
  rawKey: string,
  force: boolean,
): Promise<void> {
  let existing = "";
  try {
    existing = await fs.readFile(envPath, "utf8");
  } catch (err) {
    if (
      !(
        err &&
        typeof err === "object" &&
        "code" in err &&
        err.code === "ENOENT"
      )
    ) {
      throw err;
    }
  }
  const next = replaceOrAppendEnvValue(existing, rawKey, force);
  await fs.writeFile(envPath, next, { encoding: "utf8", mode: ENV_FILE_MODE });
  await fs.chmod(envPath, ENV_FILE_MODE);
}

function gatewayUrl(base: string, path: string): string {
  return `${base.trim().replace(/\/+$/, "")}${path}`;
}

async function parseJsonResponse(
  response: Response,
): Promise<Record<string, unknown>> {
  const text = await response.text();
  if (!text.trim()) {
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // Fall through to the shaped error below.
  }
  throw new PaybondLoginError(
    `Gateway returned non-JSON response (${response.status}).`,
  );
}

function stringField(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  return typeof value === "string" ? value.trim() : "";
}

function numberField(
  body: Record<string, unknown>,
  field: string,
  fallback: number,
): number {
  const value = body[field];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

async function postGatewayJson(
  fetchFn: FetchLike,
  gateway: string,
  path: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await fetchFn(gatewayUrl(gateway, path), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const parsed = await parseJsonResponse(response);
  if (response.ok) {
    return parsed;
  }
  const error = stringField(parsed, "error");
  if (error) {
    throw new OAuthPollError({
      error,
      error_description:
        stringField(parsed, "error_description") ||
        stringField(parsed, "message"),
      interval: numberField(parsed, "interval", 0) || undefined,
    });
  }
  throw new PaybondLoginError(`Gateway ${path} HTTP ${response.status}.`);
}

function toDeviceStartResponse(
  body: Record<string, unknown>,
): DeviceStartResponse {
  const response = {
    device_code: stringField(body, "device_code"),
    user_code: stringField(body, "user_code"),
    verification_uri: stringField(body, "verification_uri"),
    verification_uri_complete:
      stringField(body, "verification_uri_complete") || undefined,
    expires_in: numberField(body, "expires_in", DEFAULT_DEVICE_EXPIRES_IN_SECONDS),
    interval: numberField(body, "interval", DEFAULT_DEVICE_POLL_INTERVAL_SECONDS),
  };
  if (
    !response.device_code ||
    !response.user_code ||
    !response.verification_uri
  ) {
    throw new PaybondLoginError(
      "Gateway device start response was missing required fields.",
    );
  }
  return response;
}

function toDeviceTokenResponse(
  body: Record<string, unknown>,
  environment: DeviceEnvironment,
): DeviceTokenResponse {
  const response = {
    access_token: stringField(body, "access_token"),
    token_type: stringField(body, "token_type"),
    tenant_id: stringField(body, "tenant_id"),
    tenant_uuid: stringField(body, "tenant_uuid"),
    environment: stringField(body, "environment"),
    service_account_role: stringField(body, "service_account_role"),
    expires_at: stringField(body, "expires_at"),
  };
  if (!response.access_token || !response.tenant_id || !response.tenant_uuid) {
    throw new PaybondLoginError(
      "Gateway device token response was missing required fields.",
    );
  }
  if (response.environment !== environment) {
    throw new PaybondLoginError(
      `Gateway returned a ${response.environment || "unknown"} key but ${environment} was requested.`,
    );
  }
  if (response.service_account_role !== "operator") {
    throw new PaybondLoginError(
      `Gateway returned a non-operator key (${response.service_account_role || "unknown"}).`,
    );
  }
  if (!response.access_token.startsWith(`paybond_sk_${environment}_`)) {
    throw new PaybondLoginError(
      `Gateway returned an unexpected ${environment} API key shape.`,
    );
  }
  return response;
}

async function startDeviceFlow(
  fetchFn: FetchLike,
  gateway: string,
  environment: DeviceEnvironment,
): Promise<DeviceStartResponse> {
  const body = await postGatewayJson(
    fetchFn,
    gateway,
    "/v1/public/auth/device/start",
    {
      client_id: CLIENT_ID,
      client_name: CLIENT_NAME,
      requested_environment: environment,
      service_account_role: "operator",
    },
  );
  return toDeviceStartResponse(body);
}

async function pollDeviceToken(
  fetchFn: FetchLike,
  gateway: string,
  environment: DeviceEnvironment,
  start: DeviceStartResponse,
  deps: Required<Pick<LoginDependencies, "sleep" | "now">>,
): Promise<DeviceTokenResponse> {
  let intervalSeconds = Math.max(
    MIN_POLL_INTERVAL_SECONDS,
    Math.trunc(start.interval || DEFAULT_DEVICE_POLL_INTERVAL_SECONDS),
  );
  const expiresAtMs = deps.now() + Math.max(1, start.expires_in) * MS_PER_SECOND;

  for (;;) {
    await deps.sleep(intervalSeconds * MS_PER_SECOND);
    if (deps.now() > expiresAtMs + DEVICE_EXPIRY_GRACE_MS) {
      throw new PaybondLoginError(
        "Device authorization expired before approval.",
      );
    }
    try {
      const body = await postGatewayJson(
        fetchFn,
        gateway,
        "/v1/public/auth/device/token",
        {
          grant_type: DEVICE_GRANT_TYPE,
          device_code: start.device_code,
          client_id: CLIENT_ID,
        },
      );
      return toDeviceTokenResponse(body, environment);
    } catch (err) {
      if (!(err instanceof OAuthPollError)) {
        throw err;
      }
      if (err.code === "authorization_pending") {
        intervalSeconds = Math.max(
          intervalSeconds,
          Math.trunc(err.interval || intervalSeconds),
        );
        continue;
      }
      if (err.code === "slow_down") {
        intervalSeconds = Math.max(
          intervalSeconds + MIN_POLL_INTERVAL_SECONDS,
          Math.trunc(err.interval || 0),
        );
        continue;
      }
      if (err.code === "access_denied") {
        throw new PaybondLoginError("Device authorization was denied.");
      }
      if (err.code === "expired_token") {
        throw new PaybondLoginError(
          "Device authorization expired before approval.",
        );
      }
      throw new PaybondLoginError(err.message);
    }
  }
}

function maskAPIKey(rawKey: string): string {
  const trimmed = rawKey.trim();
  const parts = trimmed.split("_");
  if (parts.length >= API_KEY_MASK_MIN_PARTS && parts[0] === "paybond" && parts[1] === "sk") {
    const environment = parts[2]!;
    const keyID = parts[3]!;
    const redactedKeyID =
      keyID.length > API_KEY_MASK_MIN_ID_LENGTH
        ? `${keyID.slice(0, API_KEY_MASK_ID_PREFIX_LENGTH)}...${keyID.slice(-API_KEY_MASK_ID_SUFFIX_LENGTH)}`
        : "redacted";
    return `paybond_sk_${environment}_${redactedKeyID}`;
  }
  return "paybond_sk_...";
}

async function defaultSleep(ms: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

async function defaultOpenBrowser(url: string): Promise<boolean> {
  const platform = process.platform;
  const command =
    platform === "darwin" ? "open" : platform === "win32" ? "cmd" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  const result = await spawnCommand(command, args, process.cwd());
  return result.code === PROCESS_EXIT_SUCCESS;
}

export async function runLogin(
  options: LoginOptions,
  deps: LoginDependencies = {},
): Promise<LoginResult> {
  const cwd = deps.cwd ?? process.cwd();
  const stdout = deps.stdout ?? process.stdout;
  const humanOutput = deps.humanOutput ?? true;
  const fetchFn = deps.fetch ?? fetch;
  const sleep = deps.sleep ?? defaultSleep;
  const now = deps.now ?? Date.now;
  const openBrowser = deps.openBrowser ?? defaultOpenBrowser;
  const envPath = await resolveEnvFile(options.envFile, cwd);

  await assertCanWriteEnvFile(envPath, options.force);
  await ensureGitIgnored(envPath, cwd, options.envFile === DEFAULT_ENV_FILE);

  const start = await startDeviceFlow(
    fetchFn,
    options.gateway,
    options.environment,
  );
  const verificationUrl =
    start.verification_uri_complete || start.verification_uri;
  if (humanOutput) {
    stdout.write(`Paybond ${options.environment} login\n`);
    stdout.write(`Verification URL: ${verificationUrl}\n`);
    stdout.write(`Code: ${start.user_code}\n`);
    if (!options.noOpen) {
      const opened = await openBrowser(verificationUrl);
      if (!opened) {
        stdout.write(
          `Open the verification URL in a browser to approve this login.\n`,
        );
      }
    }
    stdout.write(`Waiting for approval...\n`);
  }

  const token = await pollDeviceToken(
    fetchFn,
    options.gateway,
    options.environment,
    start,
    { sleep, now },
  );
  await writeEnvFile(envPath, token.access_token, options.force);

  const keyMasked = maskAPIKey(token.access_token);
  if (humanOutput) {
    stdout.write(`Wrote PAYBOND_API_KEY to ${envPath}\n`);
    stdout.write(`Key: ${keyMasked}\n`);
    stdout.write(
      `Target ${token.environment} tenant: ${token.tenant_id} (${token.tenant_uuid})\n`,
    );
    if (token.expires_at) {
      stdout.write(
        `This key auto-expires at ${token.expires_at}; re-run paybond login to mint a new one.\n`,
      );
    }
  }
  return {
    envPath,
    keyMasked,
    keyWritten: true,
    environment: options.environment,
    tenantId: token.tenant_id,
    tenantUuid: token.tenant_uuid,
    expiresAt: token.expires_at || undefined,
    verificationUri: verificationUrl,
    userCode: start.user_code,
  };
}

export async function main(
  argv: string[] = process.argv.slice(2),
  deps: LoginDependencies = {},
): Promise<number> {
  let parsed: LoginOptions | "help";
  try {
    parsed = parseArgs(argv);
    if (parsed === "help") {
      (deps.stdout ?? process.stdout).write(`${usage()}\n`);
      return 0;
    }
    await runLogin(parsed, deps);
    return 0;
  } catch (err) {
    (deps.stderr ?? process.stderr).write(
      `${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 1;
  }
}

function normalizeFileURL(url: string): string {
  return url.startsWith("file:///var/")
    ? url.replace("file:///var/", "file:///private/var/")
    : url;
}

async function invokedFromCLI(): Promise<boolean> {
  const scriptPath = process.argv[1];
  if (!scriptPath) {
    return false;
  }

  async function realFileURL(filePath: string): Promise<string> {
    let resolved = path.resolve(filePath);
    try {
      resolved = await fs.realpath(resolved);
    } catch {
      // If realpath fails, compare the absolute path. This keeps direct execution
      // working even when the script path disappears during process startup.
    }
    return normalizeFileURL(pathToFileURL(resolved).href);
  }

  return (
    (await realFileURL(scriptPath)) ===
    (await realFileURL(fileURLToPath(import.meta.url)))
  );
}

invokedFromCLI().then(
  (invoked) => {
    if (!invoked) {
      return;
    }
    runCli(["login", ...process.argv.slice(2)]).then(
      (code) => {
        process.exitCode = code;
      },
      (err) => {
        process.stderr.write(
          `${err instanceof Error ? err.message : String(err)}\n`,
        );
        process.exitCode = 1;
      },
    );
  },
  (err) => {
    process.stderr.write(
      `${err instanceof Error ? err.message : String(err)}\n`,
    );
    process.exitCode = 1;
  },
);
