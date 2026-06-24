import { spawn } from "node:child_process";
import { access } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

import {
  defaultMcpInstallFormat,
  defaultMcpServerCommand,
  parseMcpInstallHost,
  planMcpInstall,
} from "./mcp-install.js";
import { validateMcpToolSchema } from "./mcp-policy.js";
import { validateMcpHostConfig } from "./mcp-verify-config.js";

const require = createRequire(import.meta.url);
const packageJson = require("../../package.json") as { version: string };

export type DoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export function packageVersion(): string {
  return packageJson.version;
}

export function encodeMcpMessage(payload: Record<string, unknown>): Buffer {
  const body = JSON.stringify(payload);
  return Buffer.from(`Content-Length: ${Buffer.byteLength(body, "utf8")}\r\n\r\n${body}`, "utf8");
}

function consumeMcpMessages(raw: Buffer): { messages: Array<Record<string, unknown>>; remainder: Buffer } {
  const messages: Array<Record<string, unknown>> = [];
  let offset = 0;
  while (true) {
    const headerEnd = raw.indexOf("\r\n\r\n", offset);
    if (headerEnd < 0) {
      return { messages, remainder: raw.subarray(offset) };
    }
    const headerText = raw.subarray(offset, headerEnd).toString("ascii");
    const contentLength = Number.parseInt(
      headerText
        .split("\r\n")
        .find((line) => line.toLowerCase().startsWith("content-length:"))
        ?.split(":", 2)[1]
        ?.trim() ?? "",
      10,
    );
    if (!Number.isFinite(contentLength) || contentLength <= 0) {
      throw new Error("MCP response missing Content-Length");
    }
    const bodyStart = headerEnd + 4;
    const bodyEnd = bodyStart + contentLength;
    if (raw.length < bodyEnd) {
      return { messages, remainder: raw.subarray(offset) };
    }
    const body = raw.subarray(bodyStart, bodyEnd).toString("utf8");
    const parsed = JSON.parse(body) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("MCP response was not a JSON object");
    }
    messages.push(parsed as Record<string, unknown>);
    offset = bodyEnd;
    if (offset >= raw.length) {
      return { messages, remainder: Buffer.alloc(0) };
    }
  }
}

async function readMcpMessage(
  stream: NodeJS.ReadableStream,
  deadlineMs: number,
  rawBuffer: Buffer[],
): Promise<Record<string, unknown>> {
  const started = Date.now();
  while (true) {
    const joined = Buffer.concat(rawBuffer);
    const { messages, remainder } = consumeMcpMessages(joined);
    rawBuffer.length = 0;
    if (remainder.length > 0) {
      rawBuffer.push(remainder);
    }
    if (messages[0]) {
      return messages[0];
    }
    if (Date.now() - started > deadlineMs) {
      throw new Error("timed out waiting for MCP response");
    }
    const chunk = await new Promise<Buffer | null>((resolve, reject) => {
      const onData = (data: Buffer) => {
        cleanup();
        resolve(data);
      };
      const onEnd = () => {
        cleanup();
        resolve(null);
      };
      const onError = (err: Error) => {
        cleanup();
        reject(err);
      };
      const cleanup = () => {
        stream.off("data", onData);
        stream.off("end", onEnd);
        stream.off("error", onError);
      };
      stream.once("data", onData);
      stream.once("end", onEnd);
      stream.once("error", onError);
    });
    if (!chunk) {
      throw new Error("MCP server closed stdout before responding");
    }
    rawBuffer.push(chunk);
    if (Buffer.concat(rawBuffer).length > 1_048_576) {
      throw new Error("MCP stdout buffer too large");
    }
  }
}

function stdoutIsMcpPure(rawStdout: Buffer): boolean {
  if (rawStdout.length === 0) {
    return true;
  }
  try {
    const { messages, remainder } = consumeMcpMessages(rawStdout);
    if (remainder.toString("utf8").trim()) {
      return false;
    }
    return messages.length > 0;
  } catch {
    return false;
  }
}

export async function runAgentMcpChecks(input: {
  envFile: string;
  cwd: string;
  host?: string;
  serverCommand?: string[];
  timeoutMs?: number;
}): Promise<DoctorCheck[]> {
  const checks: DoctorCheck[] = [];
  const installHost = parseMcpInstallHost(input.host ?? "generic");
  const format = defaultMcpInstallFormat(installHost);
  const plan = planMcpInstall({
    host: installHost,
    scope: "local",
    format,
    envFile: input.envFile,
    cwd: input.cwd,
    home: process.env.HOME ?? process.env.USERPROFILE ?? input.cwd,
    serverCommand: input.serverCommand ?? defaultMcpServerCommand(),
  });
  const configResult = validateMcpHostConfig({
    host: installHost,
    format,
    payload: plan.payload,
    cwd: input.cwd,
    expectedEnvFile: input.envFile,
  });
  checks.push({
    name: "mcp_host_config",
    ok: configResult.ok,
    message: configResult.message,
    details: { host: installHost, format },
  });

  const envPath = path.isAbsolute(input.envFile)
    ? path.resolve(input.envFile)
    : path.resolve(input.cwd, input.envFile);
  let envOk = false;
  try {
    await access(envPath);
    envOk = true;
  } catch {
    envOk = false;
  }
  checks.push({
    name: "mcp_env_resolution",
    ok: envOk,
    message: envOk ? envPath : `env file not found: ${envPath}`,
    details: { env_file: input.envFile, resolved: envPath },
  });
  if (!envOk) {
    checks.push(
      { name: "mcp_launch", ok: false, message: "skipped (env file missing)" },
      { name: "mcp_initialize", ok: false, message: "skipped (env file missing)" },
      { name: "mcp_tools_list", ok: false, message: "skipped (env file missing)" },
      { name: "mcp_tool_schemas", ok: false, message: "skipped (env file missing)" },
      { name: "mcp_stdout_purity", ok: false, message: "skipped (env file missing)" },
    );
    return checks;
  }

  const command = input.serverCommand ?? defaultMcpServerCommand();
  const env: Record<string, string | undefined> = {
    ...process.env,
    PAYBOND_ENV_FILE: envPath,
  };
  delete env.PAYBOND_API_KEY;

  return await new Promise<DoctorCheck[]>((resolve) => {
    let child;
    try {
      child = spawn(command[0]!, command.slice(1), {
        cwd: input.cwd,
        env,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (err) {
      resolve([
        { name: "mcp_launch", ok: false, message: `unable to launch MCP server: ${err instanceof Error ? err.message : String(err)}` },
        { name: "mcp_initialize", ok: false, message: "skipped (launch failed)" },
        { name: "mcp_tools_list", ok: false, message: "skipped (launch failed)" },
        { name: "mcp_tool_schemas", ok: false, message: "skipped (probe failed)" },
        { name: "mcp_stdout_purity", ok: false, message: "skipped (launch failed)" },
      ]);
      return;
    }

    const timeoutMs = input.timeoutMs ?? 10_000;
    const stderrChunks: Buffer[] = [];
    const rawStdout: Buffer[] = [];
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrChunks.push(chunk);
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      rawStdout.push(chunk);
    });

    void (async () => {
      try {
        if (!child.stdin || !child.stdout) {
          throw new Error("MCP server stdio pipes unavailable");
        }
        checks.push({
          name: "mcp_launch",
          ok: true,
          message: `launched ${command.join(" ")}`,
        });
        child.stdin.write(
          encodeMcpMessage({
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2025-11-25",
              capabilities: {},
              clientInfo: { name: "paybond-doctor", version: packageVersion() },
            },
          }),
        );
        const initResponse = await readMcpMessage(child.stdout, timeoutMs, rawStdout);
        if (initResponse.error) {
          checks.push({
            name: "mcp_initialize",
            ok: false,
            message: "MCP initialize failed",
            details: { error: initResponse.error },
          });
          checks.push(
            { name: "mcp_tools_list", ok: false, message: "skipped (initialize failed)" },
            { name: "mcp_tool_schemas", ok: false, message: "skipped (initialize failed)" },
            { name: "mcp_stdout_purity", ok: false, message: "skipped (initialize failed)" },
          );
          resolve(checks);
          return;
        }
        const serverInfo = (initResponse.result as Record<string, unknown> | undefined)?.serverInfo;
        const initOk = Boolean(serverInfo && typeof serverInfo === "object");
        checks.push({
          name: "mcp_initialize",
          ok: initOk,
          message: initOk ? "MCP initialize succeeded" : "MCP initialize response missing serverInfo",
          details: initOk
            ? {
                server_name: (serverInfo as Record<string, unknown>).name,
                server_version: (serverInfo as Record<string, unknown>).version,
              }
            : undefined,
        });
        if (!initOk) {
          checks.push(
            { name: "mcp_tools_list", ok: false, message: "skipped (initialize failed)" },
            { name: "mcp_tool_schemas", ok: false, message: "skipped (initialize failed)" },
            { name: "mcp_stdout_purity", ok: false, message: "skipped (initialize failed)" },
          );
          resolve(checks);
          return;
        }

        child.stdin.write(
          encodeMcpMessage({
            jsonrpc: "2.0",
            method: "notifications/initialized",
          }),
        );
        child.stdin.write(
          encodeMcpMessage({
            jsonrpc: "2.0",
            id: 2,
            method: "tools/list",
            params: {},
          }),
        );
        const toolsResponse = await readMcpMessage(child.stdout, timeoutMs, rawStdout);
        if (toolsResponse.error) {
          checks.push({
            name: "mcp_tools_list",
            ok: false,
            message: "MCP tools/list failed",
            details: { error: toolsResponse.error },
          });
          checks.push(
            { name: "mcp_tool_schemas", ok: false, message: "skipped (tools/list failed)" },
            { name: "mcp_stdout_purity", ok: false, message: "skipped (tools/list failed)" },
          );
          resolve(checks);
          return;
        }
        const tools = (toolsResponse.result as Record<string, unknown> | undefined)?.tools;
        const toolCount = Array.isArray(tools) ? tools.length : 0;
        checks.push({
          name: "mcp_tools_list",
          ok: toolCount > 0,
          message: `${toolCount} tools listed`,
          details: { tool_count: toolCount },
        });
        const schemaErrors: string[] = [];
        if (Array.isArray(tools)) {
          for (const tool of tools) {
            if (tool && typeof tool === "object" && !Array.isArray(tool)) {
              schemaErrors.push(...validateMcpToolSchema(tool as Record<string, unknown>));
            }
          }
        }
        checks.push({
          name: "mcp_tool_schemas",
          ok: toolCount > 0 && schemaErrors.length === 0,
          message: schemaErrors.length === 0 ? "all listed tools have valid schemas" : schemaErrors[0]!,
          details: { invalid_count: schemaErrors.length, errors: schemaErrors.slice(0, 5) },
        });
        const pure = stdoutIsMcpPure(Buffer.concat(rawStdout));
        checks.push({
          name: "mcp_stdout_purity",
          ok: pure,
          message: pure ? "stdout contains only MCP-framed JSON-RPC" : "stdout contains non-MCP material",
        });
        resolve(checks);
      } catch (err) {
        const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
        const suffix = stderr ? `: ${stderr}` : "";
        checks.push({
          name: "mcp_initialize",
          ok: false,
          message: `MCP stdio probe failed: ${err instanceof Error ? err.message : String(err)}${suffix}`,
        });
        checks.push(
          { name: "mcp_tools_list", ok: false, message: "skipped (probe failed)" },
          { name: "mcp_tool_schemas", ok: false, message: "skipped (probe failed)" },
          { name: "mcp_stdout_purity", ok: false, message: "skipped (probe failed)" },
        );
        resolve(checks);
      } finally {
        child.kill("SIGTERM");
      }
    })();
  });
}

declare const process: {
  env: Record<string, string | undefined>;
};
