import path from "node:path";

import type { PaybondApiKeyKind } from "../mcp/scope-catalog.js";
import { detectEnvFileApiKeyKind } from "./credentials.js";
import { defaultMcpInstallFormat, type McpInstallHost } from "./mcp-install.js";
import { DEFAULT_MCP_TOOL_POLICY, MCP_TOOL_ALLOWLIST_ENV, MCP_TOOL_POLICY_ENV } from "./mcp-policy.js";
import { verifyMcpInstallPlan } from "./mcp-verify-config.js";

/**
 * Command that mints the credential this check recommends. Kept as one string so
 * the TypeScript and Python doctors emit byte-identical guidance.
 */
export const MCP_RESTRICTED_KEY_HINT =
  "paybond keys create --name mcp-agent --role operator --kind restricted --preset mcp-readonly";

export type McpDoctorCheck = {
  name: string;
  ok: boolean;
  message: string;
  details?: Record<string, unknown>;
};

export type McpDoctorConfigContext = {
  /** Key kind the MCP server will actually authenticate with at runtime. */
  keyKind: PaybondApiKeyKind;
  /** `PAYBOND_MCP_TOOL_POLICY` found in the host config env, if any. */
  toolPolicy: string | null;
  /** `PAYBOND_MCP_TOOL_ALLOWLIST` found in the host config env, if any. */
  toolAllowlist: string | null;
  /** Host config that was inspected, or null when the plan was generated. */
  configPath: string | null;
  /** Env file the host config points the MCP server at. */
  envFile: string;
};

/**
 * Grades the credential an MCP host config will use.
 *
 * The load-bearing check is `mcp_credential_kind`: a standard `paybond_sk_*` key
 * gives an MCP host the full role surface, so the key stops being a boundary and
 * the only thing standing between an agent and settlement is host-side config.
 * A restricted `paybond_rk_*` key carries its own scope grant that the gateway
 * enforces, which is why it is the only configuration this check passes.
 *
 * `mcp_credential_tool_policy` is the mitigation check: an unrestricted key
 * explicitly narrowed to `readonly` or an allowlist is a dev-grade guardrail,
 * while one left on the default policy exposes every non-settlement tool the
 * role allows.
 */
export function evaluateMcpCredentialChecks(context: McpDoctorConfigContext): McpDoctorCheck[] {
  const details: Record<string, unknown> = {
    key_kind: context.keyKind,
    env_file: context.envFile,
    config_path: context.configPath,
  };
  const checks: McpDoctorCheck[] = [];

  if (context.keyKind === "restricted") {
    checks.push({
      name: "mcp_credential_kind",
      ok: true,
      message: "MCP host config uses a restricted paybond_rk_ key",
      details,
    });
  } else if (context.keyKind === "standard") {
    checks.push({
      name: "mcp_credential_kind",
      ok: false,
      message: `MCP host config uses an unrestricted paybond_sk_ key; the gateway cannot cap its MCP surface. Mint a restricted key: ${MCP_RESTRICTED_KEY_HINT}`,
      details: { ...details, severity: "warning", remediation: MCP_RESTRICTED_KEY_HINT },
    });
  } else {
    checks.push({
      name: "mcp_credential_kind",
      ok: false,
      message: "skipped MCP credential check (no readable Paybond API key)",
      details: { ...details, severity: "warning" },
    });
  }

  const policy = context.toolPolicy?.trim() ?? "";
  const allowlist = context.toolAllowlist?.trim() ?? "";
  const policyDetails = {
    ...details,
    tool_policy: policy || null,
    tool_allowlist: allowlist || null,
  };
  if (context.keyKind === "restricted") {
    checks.push(
      policy || allowlist
        ? {
            name: "mcp_credential_tool_policy",
            ok: true,
            message: `${MCP_TOOL_POLICY_ENV}/${MCP_TOOL_ALLOWLIST_ENV} is ignored for restricted keys; the key's scopes decide the tool surface`,
            details: policyDetails,
          }
        : {
            name: "mcp_credential_tool_policy",
            ok: true,
            message: "tool surface comes from the restricted key's MCP scopes",
            details: policyDetails,
          },
    );
    return checks;
  }
  if (context.keyKind !== "standard") {
    checks.push({
      name: "mcp_credential_tool_policy",
      ok: true,
      message: "skipped tool-policy check (no readable Paybond API key)",
      details: policyDetails,
    });
    return checks;
  }
  // `spend-write` is the default the MCP server falls back to when no policy is
  // set, so it is not evidence that anyone narrowed anything: only an explicit
  // readonly or allowlist policy counts as a host-side guardrail.
  const narrowed = policy === "readonly" || policy === "allowlist" || allowlist !== "";
  checks.push(
    narrowed
      ? {
          name: "mcp_credential_tool_policy",
          ok: true,
          message: `unrestricted key narrowed to ${policy || "allowlist"} by ${MCP_TOOL_POLICY_ENV} (dev override; a restricted key is enforced at the gateway)`,
          details: policyDetails,
        }
      : {
          name: "mcp_credential_tool_policy",
          ok: false,
          message: `unrestricted key on the default ${MCP_TOOL_POLICY_ENV}=${DEFAULT_MCP_TOOL_POLICY} surface: every non-settlement tool this role allows is exposed and the gateway cannot cap it`,
          details: { ...policyDetails, severity: "warning", remediation: MCP_RESTRICTED_KEY_HINT },
        },
  );
  return checks;
}

/**
 * Reads the MCP host config for one host and grades the credential it will use.
 *
 * When `configPath` is omitted the config `paybond mcp install` would generate is
 * graded instead, so the check works before a host config has been written.
 * Failures to read or parse the config surface as a single failed check rather
 * than an exception: `doctor` must always produce a report.
 */
export async function runMcpDoctorChecks(input: {
  envFile: string;
  cwd: string;
  home: string;
  host: McpInstallHost;
  configPath?: string;
}): Promise<McpDoctorCheck[]> {
  const format = defaultMcpInstallFormat(input.host);
  let config;
  try {
    config = await verifyMcpInstallPlan({
      host: input.host,
      format,
      envFile: input.envFile,
      cwd: input.cwd,
      home: input.home,
      configPath: input.configPath,
    });
  } catch (err) {
    return [
      {
        name: "mcp_credential_kind",
        ok: false,
        message: `unable to read MCP host config: ${err instanceof Error ? err.message : String(err)}`,
        details: { config_path: input.configPath ?? null, severity: "warning" },
      },
    ];
  }
  // Without an entry there is no credential to grade, and falling back to the
  // workspace env file would report a pass for a config the MCP host cannot use.
  if (!config.entry) {
    return [
      {
        name: "mcp_credential_kind",
        ok: false,
        message: `no usable Paybond MCP server entry in the host config: ${config.message}`,
        details: {
          config_path: config.configPath,
          issues: config.issues,
          severity: "warning",
        },
      },
    ];
  }
  const env = config.entry.env ?? {};
  const envFile = env.PAYBOND_ENV_FILE?.trim() || input.envFile;
  const keyKind = await detectEnvFileApiKeyKind(envFile, input.cwd);
  return evaluateMcpCredentialChecks({
    keyKind,
    toolPolicy: env[MCP_TOOL_POLICY_ENV] ?? null,
    toolAllowlist: env[MCP_TOOL_ALLOWLIST_ENV] ?? null,
    configPath: config.configPath,
    envFile: path.isAbsolute(envFile) ? envFile : path.resolve(input.cwd, envFile),
  });
}