import { resolve } from "node:path";
import { readFile } from "node:fs/promises";

import {
  PaybondAgentRun,
  PaybondAutoEvidenceSubmitError,
  PaybondToolRegistryValidationError,
  PaybondUnregisteredSideEffectingToolError,
} from "../../agent/index.js";
import { runGenericSandboxDemo } from "../../agent/generic-sandbox-demo.js";
import {
  loadRunClaudeAgentsSandboxDemo,
  loadRunLangGraphSandboxDemo,
  loadRunOpenAIAgentsSandboxDemo,
  loadRunVercelAiSandboxDemo,
} from "../agent/demo-loaders.js";
import {
  buildSmokeRegistry,
  loadAgentRegistryFile,
  validateAgentRegistryDocument,
} from "../../agent/registry-file.js";
import { createPaybondToolRegistry } from "../../agent/registry.js";
import {
  devTraceStepsFromEvents,
  devTraceUrl,
  findDevTraceEventForRun,
  resolveDevTraceSink,
  recordSmokeTraceEvent,
} from "../../dev/trace-buffer.js";
import {
  PaybondSpendApprovalRequiredError,
  PaybondSpendDeniedError,
  type Paybond,
} from "../../index.js";
import { readJsonBody } from "../automation.js";
import { formatAgentSandboxSmokeChecklist } from "../agent-sandbox-smoke-checklist.js";
import {
  appendSmokeDeepLinkChecklistLines,
  buildAgentSandboxSmokeDeepLinks,
} from "../smoke-deep-links.js";
import { appendAgentRunEnvVars } from "../agent/env-write.js";
import {
  productionEvidenceToPersisted,
  resolveProductionEvidenceForReattach,
  resolveProductionEvidenceFromCli,
  type PersistedProductionEvidence,
} from "../agent/production-evidence.js";
import { resolveAgentPolicyBind, resolveAgentPolicyBindFromContent, type ResolvedAgentPolicyBind } from "../agent/policy-file.js";
import { resolvePolicyPresetPath } from "../../policy/presets.js";
import { getSolutionSmokeDefaults, isKnownSolutionId } from "../../solutions/catalog.js";
import { withPaybondAgentCli } from "../agent/paybond.js";
import {
  loadAgentRunContext,
  persistAgentRunContext,
  type PersistedAgentRunContext,
} from "../agent/run-store.js";
import {
  agentRunTraceFilePath,
  loadAgentRunTraceIfExists,
  resolveAgentRunTraceSink,
  createGatewayAgentRunTraceSink,
  registerGatewayAgentRun,
} from "../agent/run-trace-store.js";
import { formatAgentRunTraceTable } from "../agent-run-trace-table.js";
import { PaybondPolicySandboxBootstrapError } from "../../policy/sandbox-bootstrap.js";
import {
  PaybondPolicyReloadError,
  type PaybondPolicyReloadResult,
} from "../../policy/reload.js";
import type { CliContext } from "../context.js";
import {
  consumeBooleanFlag,
  consumeFlag,
  parseOptionalNonNegativeInt,
  parseRequiredNonNegativeInt,
} from "../globals.js";
import { CliError, type CommandResult } from "../types.js";

declare const process: { stdin: NodeJS.ReadableStream };

function agentCliError(
  message: string,
  options: {
    code: string;
    exitCode?: number;
    category?: "usage" | "validation" | "gateway" | "forbidden";
    details?: Record<string, unknown>;
  },
): CliError {
  return new CliError(message, {
    category: options.category ?? "validation",
    code: options.code,
    exitCode: options.exitCode ?? 1,
    details: options.details,
  });
}

function resolveBindTraceSink(
  ctx: CliContext,
  runId?: string,
  paybond?: Parameters<typeof createGatewayAgentRunTraceSink>[0],
) {
  const devSink = resolveDevTraceSink();
  const gatewaySink =
    paybond && runId?.trim() ? createGatewayAgentRunTraceSink(paybond, runId) : undefined;
  if (!runId?.trim()) {
    return gatewaySink ?? devSink;
  }
  return resolveAgentRunTraceSink(ctx.cwd, runId, undefined, devSink, gatewaySink);
}

async function resolveRegistryFromFile(registryFile: string, cwd: string) {
  const path = resolve(cwd, registryFile);
  const doc = await loadAgentRegistryFile(path);
  const validation = validateAgentRegistryDocument(doc);
  if (!validation.ok || !validation.registry) {
    const message = validation.issues
      .filter((issue) => issue.code !== "registry.default_deny_documented")
      .map((issue) => issue.message)
      .join("; ");
    throw agentCliError(message || "registry validation failed", {
      code: "cli.agent.registry_invalid",
      details: { issues: validation.issues },
    });
  }
  return { registry: validation.registry, doc, path, validation };
}

async function resolveRegistryForRun(ctx: CliContext, runId: string) {
  const stored = await loadAgentRunContext(ctx.cwd, runId);
  if (stored.registry_file) {
    const loaded = await resolveRegistryFromFile(stored.registry_file, ctx.cwd);
    return { stored, registry: loaded.registry };
  }
  if (stored.completion_preset) {
    return {
      stored,
      registry: buildSmokeRegistry(stored.operation, stored.completion_preset),
    };
  }
  throw agentCliError(
    `run ${runId} has no registry_file; re-bind with --registry-file`,
    { code: "cli.agent.missing_registry" },
  );
}

async function attachAgentRunFromStore(
  paybond: Paybond,
  ctx: CliContext,
  runId: string,
  options?: {
    policyFile?: string;
    payeeSigningSeedHex?: string;
    agentRecognitionSigningSeedHex?: string;
    reattachCommand?: string;
  },
): Promise<PaybondAgentRun> {
  const stored = await loadAgentRunContext(ctx.cwd, runId);
  const policyPath = options?.policyFile ?? stored.registry_file;
  let registry;
  let policySnapshot: ResolvedAgentPolicyBind["policySnapshot"] | undefined;
  let policyFilePath: string | undefined;

  if (stored.policy_digest && policyPath) {
    const absolutePolicyPath = resolve(ctx.cwd, policyPath);
    const resolved = stored.policy_bind_content
      ? resolveAgentPolicyBindFromContent({
          policyPath: absolutePolicyPath,
          content: stored.policy_bind_content,
          forAttach: true,
        })
      : await resolveAgentPolicyBind({
          cwd: ctx.cwd,
          policyFile: policyPath,
          forAttach: true,
        });
    registry = resolved.registry;
    policySnapshot = resolved.policySnapshot;
    policyFilePath = resolved.policyPath;
  } else {
    const resolved = await resolveRegistryForRun(ctx, runId);
    registry = resolved.registry;
  }

  const sandbox = stored.sandbox
    ? {
        operation: stored.operation,
        requestedSpendCents: stored.requested_spend_cents ?? 0,
        sandboxLifecycleStatus: stored.sandbox_lifecycle_status ?? "",
      }
    : undefined;
  let productionEvidence: Awaited<ReturnType<typeof resolveProductionEvidenceForReattach>> | undefined;
  if (!sandbox) {
    if (!stored.production_evidence) {
      throw agentCliError(
        `run ${runId} is missing production_evidence; re-bind with production attach flags`,
        { code: "cli.agent.missing_production_evidence", category: "validation" },
      );
    }
    productionEvidence = await resolveProductionEvidenceForReattach({
      cwd: ctx.cwd,
      envFile: ctx.globals.envFile,
      persisted: stored.production_evidence,
      payeeSigningSeedHex: options?.payeeSigningSeedHex,
      agentRecognitionSigningSeedHex: options?.agentRecognitionSigningSeedHex,
      command: options?.reattachCommand,
    });
  }
  const run = await PaybondAgentRun.bind(paybond, {
    runId: stored.run_id,
    registry,
    policySnapshot,
    policyFile: policyFilePath,
    traceSink: resolveBindTraceSink(ctx, stored.run_id, paybond),
    attach: {
      intentId: stored.intent_id,
      capabilityToken: stored.capability_token,
      allowedTools: stored.allowed_tools,
      sandbox,
      productionEvidence,
    },
  });
  registerGatewayAgentRun(paybond, run, { completionPreset: stored.completion_preset });
  return run;
}

function parseProductionSigningSeedFlags(argv: string[]): {
  payeeSigningSeedHex?: string;
  agentRecognitionSigningSeedHex?: string;
  rest: string[];
} {
  const payeeFlag = consumeFlag(argv, "--payee-signing-seed-hex");
  const agentFlag = consumeFlag(payeeFlag.rest, "--agent-recognition-signing-seed-hex");
  return {
    payeeSigningSeedHex: payeeFlag.value,
    agentRecognitionSigningSeedHex: agentFlag.value,
    rest: agentFlag.rest,
  };
}

function buildReloadStatus(stored: PersistedAgentRunContext): Record<string, unknown> | undefined {
  if (!stored.reload_watch && !stored.reload_poll && !stored.last_reload_at) {
    return undefined;
  }
  return {
    watch: stored.reload_watch ?? false,
    poll: stored.reload_poll ?? false,
    last_reload_at: stored.last_reload_at ?? null,
  };
}

function mapPolicyReloadError(err: unknown): CliError {
  if (err instanceof PaybondPolicyReloadError) {
    return agentCliError(err.message, {
      code: `cli.agent.policy_reload.${err.code}`,
      category: "validation",
      details: { reload_code: err.code },
    });
  }
  if (err instanceof CliError) {
    return err;
  }
  return agentCliError(err instanceof Error ? err.message : String(err), {
    code: "cli.agent.policy_reload_failed",
  });
}

function mapAuthorizationDecision(decision: {
  kind: string;
  operation?: string;
  auditId?: string;
  decisionId?: string;
  message?: string;
  code?: string;
}) {
  if (decision.kind === "allow") {
    return {
      allow: true,
      operation: decision.operation,
      audit_id: decision.auditId,
      decision_id: decision.decisionId,
    };
  }
  return {
    allow: false,
    operation: decision.operation,
    audit_id: decision.auditId,
    decision_id: decision.decisionId,
    message: decision.message,
    code: decision.code,
  };
}

async function parseInlineJson(
  argv: string[],
  flagName: string,
  fileFlagName: string,
): Promise<{ payload: Record<string, unknown>; rest: string[] }> {
  const inlineFlag = consumeFlag(argv, flagName);
  const fileFlag = consumeFlag(inlineFlag.rest, fileFlagName);
  if (inlineFlag.value) {
    try {
      const parsed = JSON.parse(inlineFlag.value) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("expected JSON object");
      }
      return { payload: parsed as Record<string, unknown>, rest: fileFlag.rest };
    } catch (err) {
      throw agentCliError(`invalid ${flagName} JSON`, {
        code: "cli.agent.invalid_json",
        category: "usage",
        details: { error: err instanceof Error ? err.message : String(err) },
      });
    }
  }
  if (fileFlag.value) {
    const payload = await readJsonBody(fileFlag.value, process.stdin);
    return { payload, rest: fileFlag.rest };
  }
  return { payload: {}, rest: fileFlag.rest };
}

export async function handleAgentRunBind(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const sandboxFlag = consumeBooleanFlag(productionFlag.rest, "--sandbox");
  const policyFlag = consumeFlag(sandboxFlag.rest, "--policy-file");
  const operationFlag = consumeFlag(policyFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--completion-preset");
  const registryFlag = consumeFlag(presetFlag.rest, "--registry-file");
  const runIdFlag = consumeFlag(registryFlag.rest, "--run-id");
  const attachIntentFlag = consumeFlag(runIdFlag.rest, "--attach-intent-id");
  const capabilityFlag = consumeFlag(attachIntentFlag.rest, "--capability-token");
  const payeeDidFlag = consumeFlag(capabilityFlag.rest, "--payee-did");
  const payeeSeedFlag = consumeFlag(payeeDidFlag.rest, "--payee-signing-seed-hex");
  const recognitionKeyFlag = consumeFlag(payeeSeedFlag.rest, "--agent-recognition-key-id");
  const recognitionSeedFlag = consumeFlag(recognitionKeyFlag.rest, "--agent-recognition-signing-seed-hex");
  const writeEnvFlag = consumeBooleanFlag(recognitionSeedFlag.rest, "--write-env");
  const envOutFlag = consumeFlag(writeEnvFlag.rest, "--env-file");
  const watchFlag = consumeBooleanFlag(envOutFlag.rest, "--watch");

  const attachIntentId = attachIntentFlag.value?.trim();
  const capabilityToken = capabilityFlag.value?.trim();
  const hasAttach = Boolean(attachIntentId || capabilityToken);
  if (hasAttach && (!attachIntentId || !capabilityToken)) {
    throw agentCliError(
      "attach requires both --attach-intent-id and --capability-token",
      { code: "cli.agent.attach_incomplete", category: "usage" },
    );
  }
  if (policyFlag.value && registryFlag.value) {
    throw agentCliError("agent run bind accepts --policy-file or --registry-file, not both", {
      code: "cli.usage.conflicting_args",
      category: "usage",
    });
  }
  if (watchFlag.present && !policyFlag.value) {
    throw agentCliError("--watch requires --policy-file", {
      code: "cli.usage.missing_args",
      category: "usage",
    });
  }

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    let registry;
    let registryPath: string | undefined;
    let policyPath: string | undefined;
    let defaultDeny = false;
    let policyBootstrap: ResolvedAgentPolicyBind["bootstrap"];
    let policySnapshot: ResolvedAgentPolicyBind["policySnapshot"] | undefined;
    let resolvedOperation = operationFlag.value?.trim() ?? "";
    let resolvedCompletionPreset = presetFlag.value?.trim();

    if (policyFlag.value) {
      try {
        const resolved = await resolveAgentPolicyBind({
          cwd: ctx.cwd,
          policyFile: policyFlag.value,
          operation: operationFlag.value,
          requestedSpendCents: spendFlag.value
            ? parseRequiredNonNegativeInt(spendFlag.value, "--requested-spend-cents")
            : undefined,
          forAttach: hasAttach,
        });
        registry = resolved.registry;
        policyPath = resolved.policyPath;
        defaultDeny = resolved.defaultDeny;
        policyBootstrap = resolved.bootstrap;
        policySnapshot = resolved.policySnapshot;
        resolvedOperation = resolved.operation;
        if (!resolvedCompletionPreset && resolved.completionPreset) {
          resolvedCompletionPreset = resolved.completionPreset;
        }
      } catch (err) {
        if (err instanceof PaybondPolicySandboxBootstrapError) {
          throw agentCliError(err.message, {
            code: "cli.agent.policy_bootstrap_failed",
            category: "validation",
          });
        }
        throw err;
      }
    } else if (registryFlag.value) {
      const loaded = await resolveRegistryFromFile(registryFlag.value, ctx.cwd);
      registry = loaded.registry;
      registryPath = loaded.path;
      defaultDeny = loaded.validation.default_deny;
    } else if (!hasAttach) {
      if (!operationFlag.value) {
        throw agentCliError(
          "agent run bind requires --operation, --policy-file, or --attach-intent-id with --capability-token",
          { code: "cli.usage.missing_args", category: "usage" },
        );
      }
      const preset = presetFlag.value?.trim() || "cost_and_completion";
      registry = buildSmokeRegistry(operationFlag.value, preset);
      defaultDeny = true;
    } else {
      registry = createPaybondToolRegistry({ defaultDeny: false, sideEffecting: {} });
    }

    let run: PaybondAgentRun;
    const bindReload = watchFlag.present && policyPath ? { watch: true } : undefined;
    let persistedProductionEvidence: PersistedProductionEvidence | undefined;
    if (hasAttach) {
      const productionEvidence = await resolveProductionEvidenceFromCli({
        cwd: ctx.cwd,
        envFile: envOutFlag.value ?? ctx.globals.envFile,
        payeeDid: payeeDidFlag.value,
        payeeSigningSeedHex: payeeSeedFlag.value,
        agentRecognitionKeyId: recognitionKeyFlag.value,
        agentRecognitionSigningSeedHex: recognitionSeedFlag.value,
      });
      persistedProductionEvidence = productionEvidenceToPersisted(productionEvidence);
      run = await PaybondAgentRun.bind(session.paybond, {
        runId: runIdFlag.value,
        registry,
        policySnapshot,
        policyFile: policyPath,
        reload: bindReload,
        traceSink: resolveBindTraceSink(ctx, runIdFlag.value, session.paybond),
        attach: {
          intentId: attachIntentId!,
          capabilityToken: capabilityToken!,
          productionEvidence,
        },
      });
    } else {
      if (policyBootstrap) {
        run = await PaybondAgentRun.bind(session.paybond, {
          runId: runIdFlag.value,
          registry,
          policySnapshot,
          policyFile: policyPath,
          reload: bindReload,
          traceSink: resolveBindTraceSink(ctx, runIdFlag.value, session.paybond),
          bootstrap: policyBootstrap,
        });
      } else {
        if (!operationFlag.value || !spendFlag.value) {
          throw agentCliError(
            "sandbox bind requires --operation and --requested-spend-cents (or --policy-file)",
            { code: "cli.usage.missing_args", category: "usage" },
          );
        }
        const requestedSpendCents = parseRequiredNonNegativeInt(spendFlag.value, "--requested-spend-cents");
        run = await PaybondAgentRun.bind(session.paybond, {
          runId: runIdFlag.value,
          registry,
          policySnapshot,
          policyFile: policyPath,
          reload: bindReload,
          traceSink: resolveBindTraceSink(ctx, runIdFlag.value, session.paybond),
          bootstrap: {
            kind: "sandbox",
            operation: operationFlag.value,
            requestedSpendCents,
            completionPreset: presetFlag.value,
          },
        });
      }
    }

    const sandbox = run.binding.sandbox;
    const data: Record<string, unknown> = {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation: sandbox?.operation ?? resolvedOperation ?? run.allowedTools[0] ?? "",
      sandbox_lifecycle_status: sandbox?.sandboxLifecycleStatus ?? "",
      allowed_tools: [...run.allowedTools],
    };
    if (policyPath) {
      data.policy_file = policyPath;
    }
    if (run.policyDigest) {
      data.policy_digest = run.policyDigest;
      data.policy_version = run.policyVersion;
      data.policy_loaded_at = run.policyLoadedAt;
    }
    if (watchFlag.present && policyPath) {
      data.reload = { watch: true };
    }

    let policyBindContent: string | undefined;
    if (policyPath) {
      policyBindContent = await readFile(policyPath, "utf8");
    }

    await persistAgentRunContext(ctx.cwd, {
      run_id: run.runId,
      tenant_id: run.tenantId,
      intent_id: run.intentId,
      capability_token: run.capabilityToken,
      operation: String(data.operation),
      allowed_tools: [...run.allowedTools],
      sandbox: Boolean(sandbox),
      sandbox_lifecycle_status: sandbox?.sandboxLifecycleStatus,
      requested_spend_cents: sandbox?.requestedSpendCents,
      completion_preset:
        resolvedCompletionPreset || (!registryPath && !policyPath && !hasAttach ? "cost_and_completion" : undefined),
      registry_file: registryPath ?? policyPath,
      default_deny: defaultDeny,
      policy_digest: run.policyDigest,
      policy_version: run.policyVersion,
      policy_loaded_at: run.policyLoadedAt,
      reload_watch: watchFlag.present && policyPath ? true : undefined,
      policy_bind_content: policyBindContent,
      production_evidence: persistedProductionEvidence,
      created_at: new Date().toISOString(),
    });

    registerGatewayAgentRun(session.paybond, run, {
      completionPreset:
        resolvedCompletionPreset || (!registryPath && !policyPath && !hasAttach ? "cost_and_completion" : undefined),
    });

    if (writeEnvFlag.present) {
      const envFile = envOutFlag.value ?? ctx.globals.envFile;
      const written = await appendAgentRunEnvVars({
        envFile,
        cwd: ctx.cwd,
        intentId: run.intentId,
        capabilityToken: run.capabilityToken,
        runId: run.runId,
      });
      data.env_file = written;
    }

    return { data, warnings: session.warnings };
  });
}

export async function handleAgentRunStatus(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const runIdFlag = consumeFlag(argv, "--run-id");
  if (!runIdFlag.value) {
    throw agentCliError("agent run status requires --run-id", {
      code: "cli.usage.missing_args",
      category: "usage",
    });
  }
  const stored = await loadAgentRunContext(ctx.cwd, runIdFlag.value);
  const reload = buildReloadStatus(stored);
  return {
    data: {
      run_id: stored.run_id,
      tenant_id: stored.tenant_id,
      intent_id: stored.intent_id,
      operation: stored.operation,
      allowed_tools: stored.allowed_tools,
      sandbox: stored.sandbox,
      sandbox_lifecycle_status: stored.sandbox_lifecycle_status ?? "",
      registry_file: stored.registry_file ?? null,
      policy_digest: stored.policy_digest ?? null,
      policy_version: stored.policy_version ?? null,
      policy_loaded_at: stored.policy_loaded_at ?? null,
      ...(reload ? { reload } : {}),
    },
  };
}

export async function handleAgentRunTrace(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const runIdFlag = consumeFlag(argv, "--run-id");
  if (!runIdFlag.value) {
    throw agentCliError("agent run trace requires --run-id", {
      code: "cli.usage.missing_args",
      category: "usage",
    });
  }

  const stored = await loadAgentRunContext(ctx.cwd, runIdFlag.value);
  const persisted = await loadAgentRunTraceIfExists(ctx.cwd, runIdFlag.value);
  const devEvent = findDevTraceEventForRun(runIdFlag.value);
  const traceEvents = persisted?.trace_events ?? devEvent?.trace_events ?? [];

  if (traceEvents.length === 0) {
    throw agentCliError(
      `no trace events for run "${runIdFlag.value}"; run paybond agent tool execute first`,
      {
        code: "cli.agent.trace_not_found",
        category: "validation",
        details: { run_id: runIdFlag.value },
      },
    );
  }

  const steps = devEvent?.steps ?? devTraceStepsFromEvents(traceEvents);
  const traceLines = formatAgentRunTraceTable({
    runId: stored.run_id,
    intentId: stored.intent_id,
    steps,
    globals: ctx.globals,
  });

  return {
    data: {
      run_id: stored.run_id,
      intent_id: stored.intent_id,
      trace_events: traceEvents,
      steps,
      trace_lines: traceLines,
      trace_url: devTraceUrl(undefined, stored.run_id),
      trace_file: persisted ? agentRunTraceFilePath(ctx.cwd, stored.run_id) : undefined,
      updated_at: persisted?.updated_at ?? devEvent?.recorded_at,
    },
  };
}

export async function handleAgentRunReloadPolicy(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runIdFlag = consumeFlag(productionFlag.rest, "--run-id");
  const policyFlag = consumeFlag(runIdFlag.rest, "--policy-file");
  const remoteFlag = consumeBooleanFlag(policyFlag.rest, "--remote");
  const resolveInheritanceFlag = consumeBooleanFlag(remoteFlag.rest, "--resolve-inheritance");
  const allowLoosenFlag = consumeBooleanFlag(resolveInheritanceFlag.rest, "--allow-loosen");
  const seedFlags = parseProductionSigningSeedFlags(allowLoosenFlag.rest);

  if (!runIdFlag.value) {
    throw agentCliError("agent run reload-policy requires --run-id", {
      code: "cli.usage.missing_args",
      category: "usage",
    });
  }

  const stored = await loadAgentRunContext(ctx.cwd, runIdFlag.value);
  const policyPath = policyFlag.value ?? stored.registry_file;
  if (!stored.policy_digest || !policyPath) {
    throw agentCliError(
      "agent run reload-policy requires a policy-bound run; bind with --policy-file first",
      { code: "cli.agent.missing_policy", category: "usage" },
    );
  }

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const run = await attachAgentRunFromStore(session.paybond, ctx, runIdFlag.value!, {
      policyFile: policyFlag.value ?? policyPath,
      payeeSigningSeedHex: seedFlags.payeeSigningSeedHex,
      agentRecognitionSigningSeedHex: seedFlags.agentRecognitionSigningSeedHex,
      reattachCommand: "agent run reload-policy",
    });

    let result: PaybondPolicyReloadResult;
    try {
      const useGateway = remoteFlag.present || resolveInheritanceFlag.present;
      result = await run.reloadPolicy({
        file: policyFlag.value ? resolve(ctx.cwd, policyFlag.value) : undefined,
        remote: remoteFlag.present,
        resolveInheritance: resolveInheritanceFlag.present,
        allowLoosen: allowLoosenFlag.present,
        gateway: useGateway ? session.paybond.harbor : undefined,
      });
    } catch (err) {
      throw mapPolicyReloadError(err);
    }

    const lastReloadAt = result.applied ? new Date().toISOString() : stored.last_reload_at;
    const policyFileOnDisk = resolve(ctx.cwd, policyFlag.value ?? policyPath);
    const policyBindContent = result.applied
      ? await readFile(policyFileOnDisk, "utf8")
      : stored.policy_bind_content;
    await persistAgentRunContext(ctx.cwd, {
      ...stored,
      policy_digest: run.policyDigest,
      policy_version: run.policyVersion,
      policy_loaded_at: run.policyLoadedAt,
      last_reload_at: lastReloadAt,
      policy_bind_content: policyBindContent,
    });

    return {
      data: {
        run_id: run.runId,
        applied: result.applied,
        unchanged: result.unchanged ?? false,
        previous_digest: result.previousDigest ?? null,
        new_digest: result.newDigest ?? null,
        policy_digest: run.policyDigest ?? null,
        policy_version: run.policyVersion ?? null,
        policy_loaded_at: run.policyLoadedAt ?? null,
      },
      warnings: session.warnings,
    };
  });
}

export async function handleAgentToolExecute(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runIdFlag = consumeFlag(productionFlag.rest, "--run-id");
  const operationFlag = consumeFlag(runIdFlag.rest, "--operation");
  const toolCallFlag = consumeFlag(operationFlag.rest, "--tool-call-id");
  if (!runIdFlag.value || !operationFlag.value || !toolCallFlag.value) {
    throw agentCliError(
      "agent tool execute requires --run-id, --operation, and --tool-call-id",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const argsParsed = await parseInlineJson(
    toolCallFlag.rest,
    "--arguments",
    "--arguments-file",
  );
  const resultParsed = await parseInlineJson(
    argsParsed.rest,
    "--result-body",
    "--result-file",
  );
  const seedFlags = parseProductionSigningSeedFlags(resultParsed.rest);
  const args = argsParsed.payload;
  const resultBody = resultParsed.payload;
  if (Object.keys(resultBody).length === 0) {
    throw agentCliError(
      "agent tool execute requires --result-body or --result-file",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const run = await attachAgentRunFromStore(session.paybond, ctx, runIdFlag.value!, {
      payeeSigningSeedHex: seedFlags.payeeSigningSeedHex,
      agentRecognitionSigningSeedHex: seedFlags.agentRecognitionSigningSeedHex,
      reattachCommand: "agent tool execute",
    });
    try {
      const wrapped = await run.interceptor.wrapExecute({
        toolName: operationFlag.value!,
        toolCallId: toolCallFlag.value!,
        operation: operationFlag.value!,
        arguments: args,
        execute: async () => resultBody,
      });
      return {
        data: {
          authorization: wrapped.authorization
            ? {
                allow: true,
                audit_id: wrapped.authorization.auditId,
                decision_id: wrapped.authorization.decisionId,
              }
            : undefined,
          tool_result: wrapped.toolResult,
          evidence: wrapped.evidence
            ? {
                submitted: wrapped.evidence.submitted,
                intent_state: wrapped.evidence.intentState,
                predicate_passed: wrapped.evidence.predicatePassed,
                sandbox_lifecycle_status: wrapped.evidence.sandboxLifecycleStatus,
              }
            : undefined,
        },
        warnings: session.warnings,
      };
    } catch (err) {
      throw mapToolExecuteError(err, {
        tool_result: resultBody,
      });
    }
  });
}

export async function handleAgentToolValidate(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runIdFlag = consumeFlag(productionFlag.rest, "--run-id");
  const operationFlag = consumeFlag(runIdFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  if (!runIdFlag.value || !operationFlag.value) {
    throw agentCliError(
      "agent tool validate requires --run-id and --operation",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }
  const requestedSpendCents = spendFlag.value
    ? parseRequiredNonNegativeInt(spendFlag.value, "--requested-spend-cents")
    : parseOptionalNonNegativeInt(undefined, "--requested-spend-cents");

  const argsParsed = await parseInlineJson(
    spendFlag.rest,
    "--arguments",
    "--arguments-file",
  );
  const seedFlags = parseProductionSigningSeedFlags(argsParsed.rest);
  const args = argsParsed.payload;

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const run = await attachAgentRunFromStore(session.paybond, ctx, runIdFlag.value!, {
      payeeSigningSeedHex: seedFlags.payeeSigningSeedHex,
      agentRecognitionSigningSeedHex: seedFlags.agentRecognitionSigningSeedHex,
      reattachCommand: "agent tool validate",
    });
    const decision = await run.interceptor.authorizeToolCall({
      toolName: operationFlag.value!,
      toolCallId: `validate-${Date.now()}`,
      operation: operationFlag.value!,
      requestedSpendCents,
      arguments: args,
    });

    const authorization = mapAuthorizationDecision(decision);
    if (authorization.allow) {
      return { data: { authorization }, warnings: session.warnings };
    }

    throw agentCliError(authorization.message ?? "spend authorization denied", {
      code: "cli.agent.authorization_denied",
      exitCode: 3,
      category: "forbidden",
      details: { authorization },
    });
  });
}

export async function handleAgentRegistryValidate(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const fileFlag = consumeFlag(argv, "--file");
  if (!fileFlag.value) {
    throw agentCliError("agent registry validate requires --file", {
      code: "cli.usage.missing_args",
      category: "usage",
    });
  }
  const doc = await loadAgentRegistryFile(resolve(ctx.cwd, fileFlag.value));
  const validation = validateAgentRegistryDocument(doc);
  return {
    data: {
      ok: validation.ok,
      version: validation.version,
      default_deny: validation.default_deny,
      tool_count: validation.tool_count,
      side_effecting_count: validation.side_effecting_count,
      issues: validation.issues,
    },
  };
}

export async function handleAgentSandboxSmoke(ctx: CliContext, argv: string[]): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const policyPresetFlag = consumeFlag(productionFlag.rest, "--preset");
  const policyFlag = consumeFlag(policyPresetFlag.rest, "--policy-file");
  const operationFlag = consumeFlag(policyFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");

  let resolvedPolicyFile = policyFlag.value?.trim();
  const solutionPresetId = policyPresetFlag.value?.trim() ?? "";
  let solutionSmokeDefaults: ReturnType<typeof getSolutionSmokeDefaults> | undefined;
  if (solutionPresetId) {
    if (resolvedPolicyFile) {
      throw agentCliError("agent sandbox smoke accepts --preset or --policy-file, not both", {
        code: "cli.usage.conflicting_args",
        category: "usage",
      });
    }
    try {
      resolvedPolicyFile = resolvePolicyPresetPath(solutionPresetId);
      if (isKnownSolutionId(solutionPresetId)) {
        solutionSmokeDefaults = getSolutionSmokeDefaults(solutionPresetId);
      }
    } catch (err) {
      throw agentCliError(err instanceof Error ? err.message : String(err), {
        code: "cli.agent.policy_preset_invalid",
        category: "validation",
      });
    }
  }

  const resolvedOperation = operationFlag.value?.trim() || solutionSmokeDefaults?.operation;
  const resolvedSpend = spendFlag.value?.trim() || (
    solutionSmokeDefaults ? String(solutionSmokeDefaults.requestedSpendCents) : undefined
  );
  const resolvedEvidencePreset = presetFlag.value?.trim() || solutionSmokeDefaults?.evidencePreset;

  if (
    !resolvedPolicyFile &&
    (!resolvedOperation || !resolvedSpend || !resolvedEvidencePreset)
  ) {
    throw agentCliError(
      "agent sandbox smoke requires --preset, --policy-file, or (--operation, --requested-spend-cents, and --evidence-preset)",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const resultParsed = await parseInlineJson(
    presetFlag.rest,
    "--result-body",
    "--result-file",
  );
  let resultBody = resultParsed.payload;
  if (Object.keys(resultBody).length === 0) {
    if (solutionSmokeDefaults) {
      resultBody = { ...solutionSmokeDefaults.resultBody };
    } else {
      throw agentCliError(
        "agent sandbox smoke requires --result-body or --result-file",
        { code: "cli.usage.missing_args", category: "usage" },
      );
    }
  }

  let smokeOperation = resolvedOperation ?? "";
  const bindArgv: string[] = [...(productionFlag.present ? ["--production"] : [])];
  if (resolvedPolicyFile) {
    bindArgv.push("--policy-file", resolvedPolicyFile);
    if (resolvedOperation) {
      bindArgv.push("--operation", resolvedOperation);
    }
    if (resolvedSpend) {
      bindArgv.push("--requested-spend-cents", resolvedSpend);
    }
    if (resolvedEvidencePreset) {
      bindArgv.push("--completion-preset", resolvedEvidencePreset);
    }
  } else {
    bindArgv.push(
      "--operation",
      resolvedOperation!,
      "--requested-spend-cents",
      resolvedSpend!,
      "--completion-preset",
      resolvedEvidencePreset!,
    );
  }

  const bindResult = await handleAgentRunBind(ctx, bindArgv);
  smokeOperation = String(bindResult.data.operation ?? smokeOperation);

  const runId = String(bindResult.data.run_id ?? "");
  try {
    const executeResult = await handleAgentToolExecute(ctx, [
      ...(productionFlag.present ? ["--production"] : []),
      "--run-id",
      runId,
      "--operation",
      smokeOperation,
      "--tool-call-id",
      "smoke-1",
      "--result-body",
      JSON.stringify(resultBody),
    ]);
    const stored = await loadAgentRunContext(ctx.cwd, runId);
    const bindForChecklist = {
      ...bindResult.data,
      completion_preset: stored.completion_preset,
      requested_spend_cents: stored.requested_spend_cents,
    };
    const checklistLines = appendSmokeDeepLinkChecklistLines(
      formatAgentSandboxSmokeChecklist({
        presetId: policyPresetFlag.value?.trim(),
        bind: bindForChecklist,
        execute: executeResult.data,
        resultBody,
        globals: ctx.globals,
      }),
      buildAgentSandboxSmokeDeepLinks({ bind: bindForChecklist }),
      ctx.globals,
    );
    const deepLinks = buildAgentSandboxSmokeDeepLinks({ bind: bindForChecklist });
    recordSmokeTraceEvent(
      {
        preset: policyPresetFlag.value?.trim() || "travel",
        bind: bindForChecklist,
        execute: executeResult.data,
        resultBody,
      },
      ctx.cwd,
    );
    return {
      data: {
        bind: bindResult.data,
        execute: executeResult.data,
        checklist_lines: checklistLines,
        ...deepLinks,
      },
      warnings: bindResult.warnings,
    };
  } catch (err) {
    if (err instanceof CliError) {
      throw new CliError(err.message, {
        category: err.category,
        code: err.code,
        exitCode: err.exitCode,
        details: {
          ...(err.details ?? {}),
          bind: bindResult.data,
        },
      });
    }
    throw err;
  }
}

export async function handleAgentDemoVercelAiSmoke(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const operationFlag = consumeFlag(productionFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");
  if (!operationFlag.value || !spendFlag.value || !presetFlag.value) {
    throw agentCliError(
      "agent demo vercel-ai smoke requires --operation, --requested-spend-cents, and --evidence-preset",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const requestedSpendCents = parseRequiredNonNegativeInt(
    spendFlag.value,
    "--requested-spend-cents",
  );

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const runVercelAiSandboxDemo = await loadRunVercelAiSandboxDemo();
    const demo = await runVercelAiSandboxDemo({
      paybond: session.paybond,
      operation: operationFlag.value,
      requestedSpendCents,
      evidencePreset: presetFlag.value,
    });

    if (demo.tool_approval !== "approved") {
      throw agentCliError("tool approval did not pass in Vercel AI sandbox demo", {
        code: "cli.agent.authorization_denied",
        exitCode: 3,
        category: "forbidden",
        details: { tool_approval: demo.tool_approval },
      });
    }

    if (!demo.execute.tool_result) {
      throw agentCliError("Vercel AI sandbox demo did not produce a paid tool result", {
        code: "cli.agent.tool_execute_failed",
        details: { generate_text: demo.generate_text },
      });
    }

    return {
      data: demo,
      warnings: session.warnings,
    };
  });
}

export async function handleAgentDemoLanggraphSmoke(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runtimeFlag = consumeFlag(productionFlag.rest, "--runtime");
  const operationFlag = consumeFlag(runtimeFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");
  if (!operationFlag.value || !spendFlag.value || !presetFlag.value) {
    throw agentCliError(
      "agent demo langgraph smoke requires --operation, --requested-spend-cents, and --evidence-preset",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const runtime = (runtimeFlag.value ?? "typescript").trim().toLowerCase();
  if (runtime !== "typescript") {
    throw agentCliError(
      `agent demo langgraph smoke --runtime ${runtime} is not supported in the TypeScript CLI; use paybond-kit Python CLI`,
      { code: "cli.usage.unsupported_runtime", category: "usage" },
    );
  }

  const requestedSpendCents = parseRequiredNonNegativeInt(
    spendFlag.value,
    "--requested-spend-cents",
  );

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const runLangGraphSandboxDemo = await loadRunLangGraphSandboxDemo();
    const demo = await runLangGraphSandboxDemo({
      paybond: session.paybond,
      operation: operationFlag.value,
      requestedSpendCents,
      evidencePreset: presetFlag.value,
    });

    if (!demo.authorization.allow) {
      throw agentCliError("LangGraph sandbox demo authorization did not pass", {
        code: "cli.agent.authorization_denied",
        exitCode: 3,
        category: "forbidden",
        details: { tool_message: demo.tool_message },
      });
    }

    if (demo.tool_message.status === "error") {
      throw agentCliError("LangGraph sandbox demo returned an error tool message", {
        code: "cli.agent.tool_execute_failed",
        details: { tool_message: demo.tool_message },
      });
    }

    return {
      data: demo,
      warnings: session.warnings,
    };
  });
}

export async function handleAgentDemoGenericSmoke(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runtimeFlag = consumeFlag(productionFlag.rest, "--runtime");
  const operationFlag = consumeFlag(runtimeFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");
  if (!operationFlag.value || !spendFlag.value || !presetFlag.value) {
    throw agentCliError(
      "agent demo generic smoke requires --operation, --requested-spend-cents, and --evidence-preset",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const runtime = (runtimeFlag.value ?? "typescript").trim().toLowerCase();
  if (runtime !== "typescript") {
    throw agentCliError(
      `agent demo generic smoke --runtime ${runtime} is not supported in the TypeScript CLI; use paybond-kit Python CLI`,
      { code: "cli.usage.unsupported_runtime", category: "usage" },
    );
  }

  const requestedSpendCents = parseRequiredNonNegativeInt(
    spendFlag.value,
    "--requested-spend-cents",
  );

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const demo = await runGenericSandboxDemo({
      paybond: session.paybond,
      operation: operationFlag.value,
      requestedSpendCents,
      evidencePreset: presetFlag.value,
    });

    if (!demo.authorization.allow) {
      throw agentCliError("generic sandbox demo authorization did not pass", {
        code: "cli.agent.authorization_denied",
        exitCode: 3,
        category: "forbidden",
        details: { authorization: demo.authorization },
      });
    }

    if (!demo.execute.tool_result) {
      throw agentCliError("generic sandbox demo did not produce a paid tool result", {
        code: "cli.agent.tool_execute_failed",
        details: { execute: demo.execute },
      });
    }

    return {
      data: demo,
      warnings: session.warnings,
    };
  });
}

export async function handleAgentDemoClaudeAgentsSmoke(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const runtimeFlag = consumeFlag(productionFlag.rest, "--runtime");
  const operationFlag = consumeFlag(runtimeFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");
  if (!operationFlag.value || !spendFlag.value || !presetFlag.value) {
    throw agentCliError(
      "agent demo claude-agents smoke requires --operation, --requested-spend-cents, and --evidence-preset",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const runtime = (runtimeFlag.value ?? "typescript").trim().toLowerCase();
  if (runtime !== "typescript") {
    throw agentCliError(
      `agent demo claude-agents smoke --runtime ${runtime} is not supported in the TypeScript CLI; use paybond-kit Python CLI`,
      { code: "cli.usage.unsupported_runtime", category: "usage" },
    );
  }

  const requestedSpendCents = parseRequiredNonNegativeInt(
    spendFlag.value,
    "--requested-spend-cents",
  );

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const runClaudeAgentsSandboxDemo = await loadRunClaudeAgentsSandboxDemo();
    const demo = await runClaudeAgentsSandboxDemo({
      paybond: session.paybond,
      operation: operationFlag.value,
      requestedSpendCents,
      evidencePreset: presetFlag.value,
    });

    if (!demo.evidence.submitted) {
      throw agentCliError("Claude Agents sandbox demo did not submit evidence", {
        code: "cli.agent.evidence_failed",
        exitCode: 5,
        category: "gateway",
        details: { tool_result: demo.tool_result },
      });
    }

    if (!demo.tool_result) {
      throw agentCliError("Claude Agents sandbox demo did not produce a paid tool result", {
        code: "cli.agent.tool_execute_failed",
        details: { allowed_tools: demo.allowed_tools },
      });
    }

    return {
      data: demo,
      warnings: session.warnings,
    };
  });
}

export async function handleAgentDemoOpenAIAgentsSmoke(
  ctx: CliContext,
  argv: string[],
): Promise<CommandResult> {
  const productionFlag = consumeBooleanFlag(argv, "--production");
  const operationFlag = consumeFlag(productionFlag.rest, "--operation");
  const spendFlag = consumeFlag(operationFlag.rest, "--requested-spend-cents");
  const presetFlag = consumeFlag(spendFlag.rest, "--evidence-preset");
  if (!operationFlag.value || !spendFlag.value || !presetFlag.value) {
    throw agentCliError(
      "agent demo openai-agents smoke requires --operation, --requested-spend-cents, and --evidence-preset",
      { code: "cli.usage.missing_args", category: "usage" },
    );
  }

  const requestedSpendCents = parseRequiredNonNegativeInt(
    spendFlag.value,
    "--requested-spend-cents",
  );

  return withPaybondAgentCli(ctx, productionFlag.present, async (session) => {
    const runOpenAIAgentsSandboxDemo = await loadRunOpenAIAgentsSandboxDemo();
    const demo = await runOpenAIAgentsSandboxDemo({
      paybond: session.paybond,
      operation: operationFlag.value,
      requestedSpendCents,
      evidencePreset: presetFlag.value,
    });

    if (demo.guardrail.behavior !== "allow" && demo.guardrail.behavior !== "not-applicable") {
      throw agentCliError("OpenAI Agents sandbox demo guardrail did not allow execution", {
        code: "cli.agent.authorization_denied",
        exitCode: 3,
        category: "forbidden",
        details: { guardrail: demo.guardrail },
      });
    }

    if (!demo.execute.tool_result) {
      throw agentCliError("OpenAI Agents sandbox demo did not produce a paid tool result", {
        code: "cli.agent.tool_execute_failed",
        details: { execute: demo.execute },
      });
    }

    return {
      data: demo,
      warnings: session.warnings,
    };
  });
}

function mapToolExecuteError(
  err: unknown,
  partial: { tool_result: unknown },
): CliError {
  if (err instanceof PaybondSpendDeniedError) {
    return agentCliError(err.message, {
      code: "cli.agent.authorization_denied",
      exitCode: 3,
      category: "forbidden",
      details: {
        authorization: { ...(err.result ?? {}), allow: false },
        tool_result: partial.tool_result,
      },
    });
  }
  if (err instanceof PaybondSpendApprovalRequiredError) {
    return agentCliError(err.message, {
      code: "cli.agent.approval_required",
      exitCode: 3,
      category: "forbidden",
      details: {
        authorization: { ...(err.result ?? {}), allow: false, approval_required: true },
        tool_result: partial.tool_result,
      },
    });
  }
  if (err instanceof PaybondUnregisteredSideEffectingToolError) {
    return agentCliError(err.message, {
      code: "cli.agent.unregistered_tool",
      exitCode: 3,
      category: "forbidden",
      details: { tool_result: partial.tool_result },
    });
  }
  if (err instanceof PaybondAutoEvidenceSubmitError) {
    return agentCliError(err.message, {
      code: "cli.agent.evidence_failed",
      exitCode: 5,
      category: "gateway",
      details: {
        tool_result: partial.tool_result,
        evidence: { submitted: false },
      },
    });
  }
  if (err instanceof PaybondToolRegistryValidationError) {
    return agentCliError(err.message, {
      code: "cli.agent.registry_invalid",
      details: { tool_result: partial.tool_result },
    });
  }
  if (err instanceof CliError) {
    return err;
  }
  return agentCliError(err instanceof Error ? err.message : String(err), {
    code: "cli.agent.tool_execute_failed",
    details: { tool_result: partial.tool_result },
  });
}

export async function handleAgent(
  ctx: CliContext,
  group: string,
  subcommand: string,
  argv: string[],
): Promise<CommandResult> {
  if (group === "run" && subcommand === "bind") {
    return handleAgentRunBind(ctx, argv);
  }
  if (group === "run" && subcommand === "status") {
    return handleAgentRunStatus(ctx, argv);
  }
  if (group === "run" && subcommand === "trace") {
    return handleAgentRunTrace(ctx, argv);
  }
  if (group === "run" && subcommand === "reload-policy") {
    return handleAgentRunReloadPolicy(ctx, argv);
  }
  if (group === "tool" && subcommand === "execute") {
    return handleAgentToolExecute(ctx, argv);
  }
  if (group === "tool" && subcommand === "validate") {
    return handleAgentToolValidate(ctx, argv);
  }
  if (group === "registry" && subcommand === "validate") {
    return handleAgentRegistryValidate(ctx, argv);
  }
  if (group === "sandbox" && subcommand === "smoke") {
    return handleAgentSandboxSmoke(ctx, argv);
  }
  if (group === "demo" && subcommand === "vercel-ai") {
    if (argv[0] !== "smoke") {
      throw agentCliError("agent demo vercel-ai requires smoke subcommand", {
        code: "cli.usage.unknown_command",
        category: "usage",
      });
    }
    return handleAgentDemoVercelAiSmoke(ctx, argv.slice(1));
  }
  if (group === "demo" && subcommand === "langgraph") {
    if (argv[0] !== "smoke") {
      throw agentCliError("agent demo langgraph requires smoke subcommand", {
        code: "cli.usage.unknown_command",
        category: "usage",
      });
    }
    return handleAgentDemoLanggraphSmoke(ctx, argv.slice(1));
  }
  if (group === "demo" && subcommand === "generic") {
    if (argv[0] !== "smoke") {
      throw agentCliError("agent demo generic requires smoke subcommand", {
        code: "cli.usage.unknown_command",
        category: "usage",
      });
    }
    return handleAgentDemoGenericSmoke(ctx, argv.slice(1));
  }
  if (group === "demo" && subcommand === "claude-agents") {
    if (argv[0] !== "smoke") {
      throw agentCliError("agent demo claude-agents requires smoke subcommand", {
        code: "cli.usage.unknown_command",
        category: "usage",
      });
    }
    return handleAgentDemoClaudeAgentsSmoke(ctx, argv.slice(1));
  }
  if (group === "demo" && subcommand === "openai-agents") {
    if (argv[0] !== "smoke") {
      throw agentCliError("agent demo openai-agents requires smoke subcommand", {
        code: "cli.usage.unknown_command",
        category: "usage",
      });
    }
    return handleAgentDemoOpenAIAgentsSmoke(ctx, argv.slice(1));
  }
  throw agentCliError(`unknown agent subcommand: agent ${group} ${subcommand}`, {
    code: "cli.usage.unknown_command",
    category: "usage",
  });
}
