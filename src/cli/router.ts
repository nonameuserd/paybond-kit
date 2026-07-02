import { commandPath, createContext } from "./context.js";
import {
  handleA2a,
  handleAuditExports,
  handleMandates,
  handleReceipts,
  handleSignal,
} from "./commands/discovery.js";
import {
  handleConfig,
  handleDoctor,
  handleDiagnose,
  handleInitCompletion,
  handleInitAgentMiddleware,
  handleInitGuardrail,
  handleInitWizard,
  handleLogin,
  handleMcpInstall,
  handleMcpServe,
  handleMcpTools,
  handleMcpVerifyConfig,
  handleVersion,
  handleWhoami,
} from "./commands/setup.js";
import {
  handlePolicyExtend,
  handlePolicyImportMcpReceipt,
  handlePolicyImportX402Receipt,
  handlePolicyInit,
  handlePolicyInitOrg,
  handlePolicyPresetsList,
  handlePolicyPresetsShow,
  handlePolicyPreview,
  handlePolicyTemplates,
  handlePolicyValidateEvidence,
  handlePolicyValidateTools,
} from "./commands/policy.js";
import { handleAgent } from "./commands/agent.js";
import { handleDev } from "./commands/dev.js";
import {
  handleGuardrails,
  handleIntents,
  handleKeys,
  handleSpendAuthorize,
} from "./commands/workflows.js";
import { failureEnvelope, prepareCommandOutput, successEnvelope, writeEnvelope, writeTableLines } from "./envelope.js";
import { defaultGlobalOptions, parseCliArgv } from "./globals.js";
import { deprecatedAliasWarning } from "./automation.js";
import { helpForCommand } from "./help.js";
import { generateRequestId } from "./request-id.js";
import { colorize, shouldUseColor } from "./color.js";
import { formatUnknownCommandMessage } from "./suggest.js";
import {
  handleCompletionCommand,
  handleExamplesCommand,
  handleHelpCommand,
  handleOnboarding,
} from "./ux.js";
import {
  CliError,
  EXIT_SUCCESS,
  type CliDependencies,
  type CliErrorShape,
  type CommandResult,
  type GlobalOptions,
} from "./types.js";

function isHelp(argv: string[]): boolean {
  return argv.length === 0 || argv.includes("--help") || argv.includes("-h");
}

function renderTable(command: string, result: CommandResult, globals: GlobalOptions): string[] {
  const useColor = shouldUseColor(globals);
  const lines = [colorize(`${command}: ok`, "green", useColor)];
  for (const [key, value] of Object.entries(result.data)) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      lines.push(`${key}: ${JSON.stringify(value)}`);
    } else if (Array.isArray(value)) {
      lines.push(`${key}: ${value.length} item(s)`);
    } else {
      lines.push(`${key}: ${String(value)}`);
    }
  }
  if (result.warnings?.length) {
    lines.push(colorize(`warnings: ${result.warnings.join("; ")}`, "yellow", useColor));
  }
  return lines;
}

function toErrorShape(err: unknown): { shape: CliErrorShape; exitCode: number } {
  if (err instanceof CliError) {
    if (err.message === "help") {
      return {
        shape: { category: "usage", code: "cli.help", message: "help" },
        exitCode: EXIT_SUCCESS,
      };
    }
    return {
      shape: {
        category: err.category,
        code: err.code,
        message: err.message,
        details: err.details ?? {},
      },
      exitCode: err.exitCode,
    };
  }
  return {
    shape: {
      category: "internal",
      code: "cli.internal",
      message: err instanceof Error ? err.message : String(err),
      details: {},
    },
    exitCode: 1,
  };
}

function outputFormatFromArgv(argv: string[]): "table" | "json" {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--format" && argv[i + 1] === "json") {
      return "json";
    }
    if (arg === "--format=json") {
      return "json";
    }
  }
  return "table";
}

function requestIdFromArgv(argv: string[]): string {
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]!;
    if (arg === "--request-id" && argv[i + 1]) {
      return argv[i + 1]!;
    }
    if (arg.startsWith("--request-id=")) {
      return arg.slice("--request-id=".length);
    }
  }
  return generateRequestId();
}

export async function runCli(argv: string[], deps: CliDependencies = {}): Promise<number> {
  const stdout = deps.stdout ?? process.stdout;
  const stderr = deps.stderr ?? process.stderr;
  let globals;
  let command: string[];
  try {
    ({ globals, command } = parseCliArgv(argv));
  } catch (err) {
    const { shape, exitCode } = toErrorShape(err);
    if (shape.message === "help") {
      stdout.write(`${helpForCommand("")}\n`);
      return EXIT_SUCCESS;
    }
    if (outputFormatFromArgv(argv) === "json") {
      writeEnvelope(
        stdout,
        failureEnvelope("paybond", { ...defaultGlobalOptions(), format: "json", requestId: requestIdFromArgv(argv) }, shape),
      );
    } else {
      stderr.write(`${shape.message}\n`);
    }
    return exitCode;
  }
  const ctx = createContext(globals, deps);
  const aliasWarning = deprecatedAliasWarning(process.argv[1]);
  if (aliasWarning) {
    stderr.write(`${aliasWarning}\n`);
  }
  const helpPath = command.filter((part) => part !== "--help" && part !== "-h").join(" ");

  if (isHelp(command)) {
    const text = helpPath ? helpForCommand(helpPath) : helpForCommand("");
    ctx.stdout.write(`${text}\n`);
    return EXIT_SUCCESS;
  }

  let canonical = "";
  let result: CommandResult;
  try {
    const [head, second, third] = command;
    const tail = command.slice(2);
    if (head === "help") {
      canonical = "help";
      result = handleHelpCommand(command.slice(1));
    } else if (head === "examples") {
      canonical = "examples";
      result = handleExamplesCommand(command.slice(1));
    } else if (head === "completion" && second) {
      canonical = "completion";
      result = handleCompletionCommand(command.slice(1));
    } else if (head === "onboarding") {
      canonical = "onboarding";
      result = await handleOnboarding(ctx, command.slice(1));
    } else if (head === "login") {
      canonical = "login";
      result = await handleLogin(ctx, command.slice(1));
    } else if (head === "init" && second === "guardrail") {
      canonical = "init guardrail";
      result = await handleInitGuardrail(ctx, command.slice(2));
    } else if (head === "init" && second === "agent-middleware") {
      canonical = "init agent-middleware";
      result = await handleInitAgentMiddleware(ctx, command.slice(2));
    } else if (head === "init" && second === "completion") {
      canonical = "init completion";
      result = await handleInitCompletion(ctx, command.slice(2));
    } else if (head === "init") {
      canonical = "init";
      result = await handleInitWizard(ctx, command.slice(1));
    } else if (head === "mcp" && second === "serve") {
      canonical = "mcp serve";
      result = await handleMcpServe(ctx, command.slice(2));
    } else if (head === "mcp" && second === "install") {
      canonical = "mcp install";
      result = await handleMcpInstall(ctx, command.slice(2));
    } else if (head === "mcp" && second === "tools") {
      canonical = "mcp tools";
      result = await handleMcpTools(ctx);
    } else if (head === "mcp" && second === "verify-config") {
      canonical = "mcp verify-config";
      result = await handleMcpVerifyConfig(ctx, command.slice(2));
    } else if (head === "doctor") {
      canonical = "doctor";
      result = await handleDoctor(ctx, command.slice(1));
    } else if (head === "dev" && second) {
      canonical = commandPath(["dev", second]);
      result = await handleDev(ctx, second, tail);
    } else if (head === "version") {
      canonical = "version";
      result = await handleVersion(ctx, command.slice(1));
    } else if (head === "diagnose") {
      canonical = "diagnose";
      result = await handleDiagnose(ctx, command.slice(1));
    } else if (head === "config" && second) {
      canonical = commandPath(["config", second]);
      result = await handleConfig(ctx, second, tail);
    } else if (head === "whoami") {
      canonical = "whoami";
      result = await handleWhoami(ctx);
    } else if (head === "keys" && second) {
      canonical = commandPath(["keys", second]);
      result = await handleKeys(ctx, second, tail);
    } else if (head === "intents" && second) {
      canonical = commandPath(["intents", second]);
      result = await handleIntents(ctx, second, tail);
    } else if (head === "guardrails" && second) {
      canonical = commandPath(["guardrails", second]);
      result = await handleGuardrails(ctx, second, tail);
    } else if (head === "spend" && second === "authorize") {
      canonical = "spend authorize";
      result = await handleSpendAuthorize(ctx, tail);
    } else if (head === "signal" && second) {
      canonical = commandPath(["signal", second]);
      result = await handleSignal(ctx, second, tail);
    } else if (head === "receipts" && second) {
      canonical = commandPath(["receipts", second]);
      result = await handleReceipts(ctx, second, tail);
    } else if (head === "mandates" && second) {
      canonical = commandPath(["mandates", second]);
      result = await handleMandates(ctx, second, tail);
    } else if (head === "a2a" && second) {
      canonical = commandPath(["a2a", second]);
      result = await handleA2a(ctx, second, tail);
    } else if (head === "audit" && second === "exports" && third) {
      canonical = commandPath(["audit", "exports", third]);
      result = await handleAuditExports(ctx, third, command.slice(3));
    } else if (head === "policy" && second === "presets" && third === "list") {
      canonical = "policy presets list";
      result = await handlePolicyPresetsList(ctx, command.slice(3));
    } else if (head === "policy" && second === "presets" && third === "show") {
      canonical = "policy presets show";
      result = await handlePolicyPresetsShow(ctx, command.slice(3));
    } else if (head === "policy" && second === "templates") {
      canonical = "policy templates";
      result = await handlePolicyTemplates(ctx, command.slice(2));
    } else if (head === "policy" && second === "preview") {
      canonical = "policy preview";
      result = await handlePolicyPreview(ctx, command.slice(2));
    } else if (head === "policy" && second === "import-mcp-receipt") {
      canonical = "policy import-mcp-receipt";
      result = await handlePolicyImportMcpReceipt(ctx, command.slice(2));
    } else if (head === "policy" && second === "import-x402-receipt") {
      canonical = "policy import-x402-receipt";
      result = await handlePolicyImportX402Receipt(ctx, command.slice(2));
    } else if (head === "policy" && second === "validate-evidence") {
      canonical = "policy validate-evidence";
      result = await handlePolicyValidateEvidence(ctx, command.slice(2));
    } else if (head === "policy" && second === "init-org") {
      canonical = "policy init-org";
      result = await handlePolicyInitOrg(ctx, command.slice(2));
    } else if (head === "policy" && second === "extend") {
      canonical = "policy extend";
      result = await handlePolicyExtend(ctx, command.slice(2));
    } else if (head === "policy" && second === "init") {
      canonical = "policy init";
      result = await handlePolicyInit(ctx, command.slice(2));
    } else if (head === "policy" && second === "validate-tools") {
      canonical = "policy validate-tools";
      result = await handlePolicyValidateTools(ctx, command.slice(2));
    } else if (head === "agent" && second && third) {
      canonical = commandPath(["agent", second, third]);
      result = await handleAgent(ctx, second, third, command.slice(3));
    } else {
      throw new CliError(formatUnknownCommandMessage(command.join(" ")), {
        category: "usage",
        code: "cli.usage.unknown_command",
      });
    }

    const output = prepareCommandOutput(canonical, globals, result);
    if (globals.format === "json") {
      writeEnvelope(
        ctx.stdout,
        successEnvelope(canonical, globals, { data: output.data as Record<string, unknown>, warnings: output.warnings }),
      );
    } else if (output.automationPlain) {
      ctx.stdout.write(`${JSON.stringify(output.data, null, 2)}\n`);
      if (output.warnings.length) {
        for (const warning of output.warnings) {
          ctx.stderr.write(`${warning}\n`);
        }
      }
    } else if (canonical === "help" || canonical === "examples") {
      ctx.stdout.write(`${String(result.data.text ?? "")}\n`);
    } else if (canonical === "completion") {
      ctx.stdout.write(String(result.data.script ?? ""));
    } else if (canonical === "version" && !("package_name" in (result.data as Record<string, unknown>))) {
      ctx.stdout.write(`${String(result.data.version ?? "")}\n`);
    } else if (canonical === "diagnose") {
      const lines = Array.isArray(result.data.lines) ? (result.data.lines as string[]) : [];
      for (const line of lines) {
        ctx.stdout.write(`${line}\n`);
      }
    } else if (canonical === "agent sandbox smoke" && Array.isArray(result.data.checklist_lines)) {
      writeTableLines(ctx.stdout, result.data.checklist_lines as string[]);
      if (output.warnings.length) {
        for (const warning of output.warnings) {
          ctx.stderr.write(`${warning}\n`);
        }
      }
    } else if (
      (canonical === "dev smoke" || canonical === "dev loop") &&
      Array.isArray(result.data.checklist_lines)
    ) {
      if (canonical === "dev loop" && Array.isArray(result.data.banner_lines)) {
        writeTableLines(ctx.stdout, result.data.banner_lines as string[]);
      }
      writeTableLines(ctx.stdout, result.data.checklist_lines as string[]);
      if (output.warnings.length) {
        for (const warning of output.warnings) {
          ctx.stderr.write(`${warning}\n`);
        }
      }
    } else if (canonical === "agent run trace" && Array.isArray(result.data.trace_lines)) {
      writeTableLines(ctx.stdout, result.data.trace_lines as string[]);
      if (output.warnings.length) {
        for (const warning of output.warnings) {
          ctx.stderr.write(`${warning}\n`);
        }
      }
    } else if (canonical === "policy presets show" && Array.isArray(result.data.yaml_lines)) {
      writeTableLines(ctx.stdout, result.data.yaml_lines as string[]);
      if (output.warnings.length) {
        for (const warning of output.warnings) {
          ctx.stderr.write(`${warning}\n`);
        }
      }
    } else if (canonical !== "login" && canonical !== "mcp serve" && canonical !== "dev trace") {
      writeTableLines(ctx.stdout, renderTable(canonical, result, globals));
    }
    return EXIT_SUCCESS;
  } catch (err) {
    const { shape, exitCode } = toErrorShape(err);
    if (shape.message === "help") {
      const text = helpPath ? helpForCommand(helpPath) : helpForCommand("");
      ctx.stdout.write(`${text}\n`);
      return EXIT_SUCCESS;
    }
    if (globals.format === "json") {
      writeEnvelope(ctx.stdout, failureEnvelope(canonical || helpPath || "paybond", globals, shape));
    } else {
      ctx.stderr.write(`${shape.message}\n`);
    }
    return exitCode;
  }
}
