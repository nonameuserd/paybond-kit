import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  parseAgentRegistryText,
  validateAgentRegistryDocument,
} from "../../src/agent/registry-file.js";
import { runCli } from "../../src/cli/router.js";
import {
  AGENT_SMOKE_INTENT,
  ATTACH_INTENT_ID,
  createAgentGatewayFetch,
  LIVE_RAW_KEY,
  PRODUCTION_ATTACH_SEEDS,
  SANDBOX_RAW_KEY,
} from "./agent-gateway-mock.js";

function stdoutCollector() {
  return {
    chunks: [] as string[],
    write(chunk: string): boolean {
      this.chunks.push(chunk);
      return true;
    },
  };
}

async function runAgentCli(
  argv: string[],
  options: { cwd?: string; fetch?: typeof fetch; env?: Record<string, string> } = {},
) {
  if (options.env) {
    for (const [key, value] of Object.entries(options.env)) {
      vi.stubEnv(key, value);
    }
  } else {
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
  }
  const stdout = stdoutCollector();
  const code = await runCli(["--format", "json", ...argv], {
    cwd: options.cwd,
    fetch: options.fetch,
    stdout,
  });
  vi.unstubAllEnvs();
  return { code, payload: JSON.parse(stdout.chunks.join("")) };
}

describe("paybond agent registry validate", () => {
  it("accepts a valid registry document", () => {
    const doc = parseAgentRegistryText(`
version: 1
default_deny: true
tools:
  travel.book_hotel:
    side_effecting: true
    evidence_preset: cost_and_completion
  search.web:
    side_effecting: false
`);
    const validation = validateAgentRegistryDocument(doc);
    expect(validation.ok).toBe(true);
    expect(validation.side_effecting_count).toBe(1);
  });

  it("rejects side-effecting tools without evidence_preset", () => {
    const validation = validateAgentRegistryDocument({
      version: 1,
      tools: {
        "travel.book_hotel": { side_effecting: true },
      },
    });
    expect(validation.ok).toBe(false);
    expect(validation.issues.some((issue) => issue.code === "registry.missing_evidence_preset")).toBe(true);
  });
});

describe("paybond agent CLI commands", () => {
  it("agent sandbox smoke runs bind and execute with --preset travel", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-preset-smoke-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "sandbox",
        "smoke",
        "--preset",
        "travel",
        "--result-body",
        '{"status":"completed","cost_cents":18700}',
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.operation).toBe("travel.book_hotel");
    expect(payload.data.bind.policy_file).toMatch(/travel\.yaml$/);
    expect(payload.data.execute.evidence.submitted).toBe(true);
    expect(payload.data.checklist_lines).toEqual([
      expect.stringContaining("Policy loaded (travel)"),
      "✓ Sandbox intent created",
      "✓ Tool call: travel.book_hotel",
      "✓ Spend approved ($187.00)",
      "✓ Evidence validated (cost_and_completion)",
      "✓ Settlement simulated",
      expect.stringMatching(/^✓ Trace → http:\/\/localhost:9477\/runs\/.+/),
      expect.stringMatching(/^✓ Console → .+\/console\/operations\/intents\/.+/),
      expect.stringMatching(/^✓ Replay → .+\/demo\/agent-trace\?intent=.+/),
      "Success",
    ]);
    expect(String(payload.data.trace_url)).toMatch(/^http:\/\/localhost:9477\/runs\/.+/);
    expect(String(payload.data.console_url)).toContain("/console/operations/intents/");
    expect(String(payload.data.agent_trace_url)).toContain("/demo/agent-trace?intent=");
  });

  it("agent sandbox smoke uses solution defaults with --preset travel only", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-preset-smoke-defaults-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      ["agent", "sandbox", "smoke", "--preset", "travel"],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.operation).toBe("travel.book_hotel");
    expect(payload.data.execute.evidence.submitted).toBe(true);
  });

  it("agent sandbox smoke renders checklist in table format", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-preset-smoke-table-"));
    const fetch = createAgentGatewayFetch();
    vi.stubEnv("PAYBOND_API_KEY", SANDBOX_RAW_KEY);
    const stdout = stdoutCollector();
    const code = await runCli(
      [
        "--no-color",
        "agent",
        "sandbox",
        "smoke",
        "--preset",
        "travel",
        "--result-body",
        '{"status":"completed","cost_cents":18700}',
      ],
      { cwd, fetch: fetch as typeof fetch, stdout },
    );
    vi.unstubAllEnvs();
    expect(code).toBe(0);
    const output = stdout.chunks.join("");
    expect(output).toContain("Policy loaded (travel)");
    expect(output).toContain("Tool call: travel.book_hotel");
    expect(output).toContain("Spend approved ($187.00)");
    expect(output).toContain("Evidence validated (cost_and_completion)");
    expect(output).toContain("Settlement simulated");
    expect(output).toContain("Success");
  });

  it("agent sandbox smoke runs bind and execute with --policy-file", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-policy-smoke-"));
    const policyPath = join(cwd, "paybond.policy.json");
    await writeFile(
      policyPath,
      JSON.stringify({
        version: 1,
        name: "travel-agent-v1",
        default_deny: true,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            max_spend_cents: 100,
            evidence_preset: "cost_and_completion",
          },
        },
      }),
      "utf8",
    );
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "sandbox",
        "smoke",
        "--policy-file",
        "paybond.policy.json",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.operation).toBe("travel.book_hotel");
    expect(payload.data.bind.policy_file).toBe(policyPath);
    expect(payload.data.execute.evidence.submitted).toBe(true);
  });

  it("agent sandbox smoke rejects --policy-file with --evidence-preset", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-policy-smoke-conflict-"));
    const policyPath = join(cwd, "paybond.policy.json");
    await writeFile(
      policyPath,
      JSON.stringify({
        version: 1,
        name: "travel-agent-v1",
        default_deny: true,
        tools: {
          "travel.book_hotel": {
            side_effecting: true,
            max_spend_cents: 100,
            evidence_preset: "cost_and_completion",
          },
        },
      }),
      "utf8",
    );
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "sandbox",
        "smoke",
        "--policy-file",
        "paybond.policy.json",
        "--evidence-preset",
        "cost_and_completion",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd },
    );
    expect(code).toBe(1);
    expect(payload.ok).toBe(false);
    expect(payload.error?.code).toBe("cli.usage.conflicting_args");
    expect(payload.error?.message).toContain("--policy-file or --evidence-preset, not both");
  });

  it("agent run reload-policy applies stricter policy to persisted run", async () => {
    const cwd = await mkdtemp(join(process.cwd(), ".tmp-paybond-reload-policy-"));
    const policyPath = join(cwd, "paybond.policy.json");
    const initialPolicy = {
      version: 1,
      name: "travel-agent-v1",
      default_deny: true,
      tools: {
        "travel.book_hotel": {
          side_effecting: true,
          max_spend_cents: 20_000,
          evidence_preset: "cost_and_completion",
        },
      },
      intent: {
        allowed_tools: ["travel.book_hotel"],
      },
    };
    await writeFile(policyPath, JSON.stringify(initialPolicy, null, 2), "utf8");
    const fetch = createAgentGatewayFetch();

    const bind = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--policy-file",
        "paybond.policy.json",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(bind.code).toBe(0);
    const runId = bind.payload.data.run_id as string;
    const initialDigest = bind.payload.data.policy_digest as string;
    expect(initialDigest).toBeTruthy();

    await writeFile(
      policyPath,
      JSON.stringify(
        {
          ...initialPolicy,
          tools: {
            "travel.book_hotel": {
              side_effecting: true,
              max_spend_cents: 5_000,
              evidence_preset: "cost_and_completion",
            },
          },
        },
        null,
        2,
      ),
      "utf8",
    );

    const reload = await runAgentCli(
      ["agent", "run", "reload-policy", "--run-id", runId],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(reload.code).toBe(0);
    expect(reload.payload.data.applied).toBe(true);
    expect(reload.payload.data.new_digest).not.toBe(initialDigest);

    const status = await runAgentCli(["agent", "run", "status", "--run-id", runId], { cwd });
    expect(status.code).toBe(0);
    expect(status.payload.data.policy_digest).toBe(reload.payload.data.new_digest);
    expect(status.payload.data.reload?.last_reload_at).toBeTruthy();
  });

  it("agent sandbox smoke runs bind and execute against gateway", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-smoke-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "sandbox",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
    expect(payload.data.execute.evidence.submitted).toBe(true);
    expect(payload.data.execute.authorization.allow).toBe(true);
  });

  it("agent demo vercel-ai smoke runs bundled mock model demo", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-vercel-demo-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "demo",
        "vercel-ai",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.tool_approval).toBe("approved");
    expect(payload.data.generate_text.text).toContain("paid tool completed");
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
  });

  it("agent demo langgraph smoke runs bundled ToolNode demo", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-langgraph-demo-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "demo",
        "langgraph",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.authorization.allow).toBe(true);
    expect(payload.data.tool_message.status).toBe("success");
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
  });

  it("agent demo generic smoke runs bundled generic runner demo", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-generic-demo-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "demo",
        "generic",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.authorization.allow).toBe(true);
    expect(payload.data.execute.tool_result).toBeDefined();
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
  });

  it("agent demo claude-agents smoke runs bundled SDK tool demo", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-claude-demo-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "demo",
        "claude-agents",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.evidence.submitted).toBe(true);
    expect(payload.data.tool_result).toBeDefined();
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
  });

  it("agent demo openai-agents smoke runs bundled guardrail demo", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-openai-demo-"));
    const fetch = createAgentGatewayFetch();
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "demo",
        "openai-agents",
        "smoke",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--evidence-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.guardrail.behavior).toBe("allow");
    expect(payload.data.execute.tool_result).toBeDefined();
    expect(payload.data.bind.intent_id).toBe(AGENT_SMOKE_INTENT);
  });

  it("agent registry validate reads yaml file", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-registry-"));
    const registryPath = join(cwd, "paybond.agent.registry.yaml");
    await writeFile(
      registryPath,
      `version: 1
default_deny: true
tools:
  paid-tool:
    side_effecting: true
    evidence_preset: cost_and_completion
`,
      "utf8",
    );
    const { code, payload } = await runAgentCli(
      ["agent", "registry", "validate", "--file", registryPath],
      { cwd },
    );
    expect(code).toBe(0);
    expect(payload.data.ok).toBe(true);
  });

  it("agent run bind, status, tool execute, and validate share run store", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-flow-"));
    const fetch = createAgentGatewayFetch();

    const bind = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--sandbox",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--completion-preset",
        "cost_and_completion",
        "--write-env",
        "--env-file",
        ".env.agent",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(bind.code).toBe(0);
    const runId = bind.payload.data.run_id as string;
    expect(runId).toBeTruthy();

    const envText = await readFile(join(cwd, ".env.agent"), "utf8");
    expect(envText).toContain(`PAYBOND_RUN_ID=${runId}`);
    expect(envText).toContain(`PAYBOND_INTENT_ID=${AGENT_SMOKE_INTENT}`);

    const status = await runAgentCli(["agent", "run", "status", "--run-id", runId], { cwd });
    expect(status.code).toBe(0);
    expect(status.payload.data.run_id).toBe(runId);
    expect(status.payload.data.intent_id).toBe(AGENT_SMOKE_INTENT);

    const validate = await runAgentCli(
      [
        "agent",
        "tool",
        "validate",
        "--run-id",
        runId,
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(validate.code).toBe(0);
    expect(validate.payload.data.authorization.allow).toBe(true);

    const execute = await runAgentCli(
      [
        "agent",
        "tool",
        "execute",
        "--run-id",
        runId,
        "--operation",
        "paid-tool",
        "--tool-call-id",
        "call-flow-1",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(execute.code).toBe(0);
    expect(execute.payload.data.evidence.submitted).toBe(true);

    const trace = await runAgentCli(["agent", "run", "trace", "--run-id", runId], { cwd });
    expect(trace.code).toBe(0);
    expect(trace.payload.data.run_id).toBe(runId);
    expect(Array.isArray(trace.payload.data.trace_events)).toBe(true);
    expect((trace.payload.data.trace_events as unknown[]).length).toBeGreaterThan(0);
    expect(Array.isArray(trace.payload.data.steps)).toBe(true);

    const traceTableStdout = stdoutCollector();
    const traceTableCode = await runCli(
      ["--format", "table", "agent", "run", "trace", "--run-id", runId],
      { cwd, fetch: fetch as typeof fetch, stdout: traceTableStdout },
    );
    expect(traceTableCode).toBe(0);
    const traceTableOutput = traceTableStdout.chunks.join("");
    expect(traceTableOutput).toContain(`run_id: ${runId}`);
    expect(traceTableOutput).toContain("Tool call:");
  });

  it("rejects production attach bind without production evidence flags", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-attach-missing-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--production",
        "--attach-intent-id",
        ATTACH_INTENT_ID,
        "--capability-token",
        "cap-prod-1",
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(1);
    expect(payload.error.code).toBe("cli.agent.production_evidence_incomplete");
  });

  it("production attach bind persists production_evidence in run store", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-attach-prod-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--production",
        "--attach-intent-id",
        ATTACH_INTENT_ID,
        "--capability-token",
        "cap-prod-1",
        "--payee-did",
        PRODUCTION_ATTACH_SEEDS.payeeDid,
        "--payee-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.payeeSigningSeedHex,
        "--agent-recognition-key-id",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionKeyId,
        "--agent-recognition-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionSigningSeedHex,
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(0);
    const runId = payload.data.run_id as string;
    const stored = JSON.parse(await readFile(join(cwd, ".paybond", "runs", `${runId}.json`), "utf8"));
    expect(stored.intent_id).toBe(ATTACH_INTENT_ID);
    expect(stored.production_evidence).toEqual({
      payee_did: PRODUCTION_ATTACH_SEEDS.payeeDid,
      agent_recognition_key_id: PRODUCTION_ATTACH_SEEDS.agentRecognitionKeyId,
    });
    expect(stored.sandbox).toBe(false);
  });

  it("agent production attach smoke runs bind and execute via /harbor/*", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-prod-attach-smoke-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "production",
        "attach",
        "smoke",
        "--attach-intent-id",
        ATTACH_INTENT_ID,
        "--capability-token",
        "cap-prod-1",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--payee-did",
        PRODUCTION_ATTACH_SEEDS.payeeDid,
        "--payee-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.payeeSigningSeedHex,
        "--agent-recognition-key-id",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionKeyId,
        "--agent-recognition-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionSigningSeedHex,
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.bind.intent_id).toBe(ATTACH_INTENT_ID);
    expect(payload.data.execute.evidence.submitted).toBe(true);
    expect(payload.data.execute.authorization.allow).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/harbor/intents/${ATTACH_INTENT_ID}/evidence`),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("rejects production attach smoke without attach credentials", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-prod-attach-missing-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "production",
        "attach",
        "smoke",
        "--operation",
        "paid-tool",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(1);
    expect(payload.error.code).toBe("cli.usage.missing_args");
  });

  it("agent harbor evidence smoke submits single /harbor/* evidence with recognition", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-harbor-evidence-smoke-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "harbor",
        "evidence",
        "smoke",
        "--intent-id",
        ATTACH_INTENT_ID,
        "--payee-did",
        PRODUCTION_ATTACH_SEEDS.payeeDid,
        "--payee-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.payeeSigningSeedHex,
        "--agent-recognition-key-id",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionKeyId,
        "--agent-recognition-signing-seed-hex",
        PRODUCTION_ATTACH_SEEDS.agentRecognitionSigningSeedHex,
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(0);
    expect(payload.ok).toBe(true);
    expect(payload.data.intent_id).toBe(ATTACH_INTENT_ID);
    expect(payload.data.harbor_path).toBe(`/harbor/intents/${ATTACH_INTENT_ID}/evidence`);
    expect(payload.data.evidence.predicatePassed).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/harbor/intents/${ATTACH_INTENT_ID}/evidence`),
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("rejects harbor evidence smoke without intent id", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-harbor-evidence-missing-"));
    const fetch = createAgentGatewayFetch({ environment: "live" });
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "harbor",
        "evidence",
        "smoke",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(1);
    expect(payload.error.code).toBe("cli.usage.missing_args");
  });

  it("rejects live credentials without --production", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-live-"));
    const { code, payload } = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
      ],
      { cwd, env: { PAYBOND_API_KEY: LIVE_RAW_KEY } },
    );
    expect(code).toBe(1);
    expect(payload.error.code).toBe("cli.agent.production_required");
  });

  it("agent tool execute returns exit 3 when verify denies spend", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "paybond-agent-deny-"));
    const fetch = createAgentGatewayFetch({ allowVerify: false, denyMessage: "budget exceeded" });

    const bind = await runAgentCli(
      [
        "agent",
        "run",
        "bind",
        "--operation",
        "paid-tool",
        "--requested-spend-cents",
        "100",
        "--completion-preset",
        "cost_and_completion",
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    const runId = bind.payload.data.run_id as string;

    const execute = await runAgentCli(
      [
        "agent",
        "tool",
        "execute",
        "--run-id",
        runId,
        "--operation",
        "paid-tool",
        "--tool-call-id",
        "call-deny",
        "--result-body",
        '{"status":"ok","cost_cents":100}',
      ],
      { cwd, fetch: fetch as typeof fetch },
    );
    expect(execute.code).toBe(3);
    expect(execute.payload.error.code).toBe("cli.agent.authorization_denied");
  });
});
