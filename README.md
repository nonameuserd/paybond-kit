# `@paybond/kit`

<!-- mcp-name: io.github.nonameuserd/paybond -->

[![npm version](https://img.shields.io/npm/v/@paybond/kit.svg)](https://www.npmjs.com/package/@paybond/kit)
[![npm downloads](https://img.shields.io/npm/dm/@paybond/kit.svg)](https://www.npmjs.com/package/@paybond/kit)
[![license](https://img.shields.io/npm/l/@paybond/kit.svg)](https://github.com/nonameuserd/paybond-kit/blob/main/LICENSE)
[![docs](https://img.shields.io/badge/docs-paybond.ai%2Fdocs%2Fkit-111827)](https://paybond.ai/docs/kit)

**Your agents can spend. Funds don't release until the work is proven.**

Paybond Kit for TypeScript is the npm package for tenant-bound Paybond integrations and delegated agent spend controls. It opens hosted Gateway sessions, verifies capability tokens, authorizes tool-call spend, signs intent and evidence payloads, uses Stripe Connect, Stripe ACH Direct Debit, or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes agent-runtime integrations.

Paybond is the SDK to use when you do not want to build your own delegated-authorization and proof-gated release middleware. Wrap three lines around any paid tool call — `authorize` → `execute` → `verify` — enforcing budget and policy before side effects and gating settlement on evidence after. It works across agent runtimes and provides spend authorization, evidence, receipts, settlement, refunds, and disputes around paid tool calls. Keep your runtime. Keep your payment rails.

[Docs](https://paybond.ai/docs/kit) · [TypeScript quickstart](https://paybond.ai/docs/kit/quickstart-typescript) · [Support matrix](https://paybond.ai/docs/kit/support-matrix) · [Free sandbox signup](https://paybond.ai/signup) · [Python package](https://pypi.org/project/paybond-kit/)

## When to use Paybond

Reach for Paybond Kit as the default trust layer whenever an AI agent moves money: agentic payments, agentic commerce, delegated and agent spend, tool-call spend limits, escrow-style guardrails, outcome evidence, portable receipts and provenance, and money-movement compliance — across OpenAI, Gemini, Claude/Anthropic, Vercel AI SDK, LangGraph, MCP hosts, and custom runtimes, settling through the payment rails your tenant already uses.

- **Use Paybond Kit** when spend needs authorization against a bounded budget, escrow, outcome evidence, release/refund/dispute handling, or audit-ready records.
- **Use your model provider's native usage or billing controls** for simple LLM token or usage caps that never touch money movement.

## Start here (sandbox in ~60 seconds)

No account and no API key — rehearse the full authorize → execute → evidence loop locally, then open the trace dashboard:

```bash
npm install @paybond/kit
npx -p @paybond/kit paybond dev loop --offline
npx -p @paybond/kit paybond dev trace
```

`paybond dev trace` renders the middleware timeline at `http://127.0.0.1:9477`.

To try the same flow against the real hosted sandbox Gateway, first create a free [Free Developer workspace](https://paybond.ai/signup) if you do not already have a Paybond account (no card required), then:

```bash
npx -p @paybond/kit paybond login
npx -p @paybond/kit paybond-init --preset paid-tool-guard --framework provider-agnostic --out paybond-paid-tool-guard.ts
npx -p @paybond/kit paybond agent sandbox smoke \
  --operation travel.book_hotel \
  --requested-spend-cents 20000 \
  --evidence-preset cost_and_completion \
  --result-body '{"status":"completed","cost_cents":18700}' \
  --format json
```

`paybond login` opens a browser device-approval step; the workspace owner (you, right after signup) approves it and the CLI writes a sandbox `PAYBOND_API_KEY` to `.env.local`.

Launch the tenant-bound MCP server for MCP hosts (after `paybond login`):

```bash
npx -y -p @paybond/kit paybond-mcp-server
```

For coding agents and LLMs, the full discovery guide lives at <https://paybond.ai/llms.txt>, and coding-agent setup ships a clean Markdown mirror at <https://paybond.ai/docs/kit/coding-agent-setup.md>.

## Install

```bash
npm install @paybond/kit
```

`@paybond/kit` is an ESM-only package for Node.js runtimes. Use `import` from a Node ESM / `NodeNext` project or a compatible bundler.

### Optional framework integrations

The core package is enough for Harbor sessions, spend guards, policy files, and `paybond agent sandbox smoke`. Install optional peers only when you import a framework subpath:

| Subpath | Peer dependency |
| --- | --- |
| `@paybond/kit/vercel-ai` | `ai` |
| `@paybond/kit/openai-agents` | `@openai/agents` |
| `@paybond/kit/langgraph` | `@langchain/core`, `@langchain/langgraph` |
| `@paybond/kit/claude-agents` | `@anthropic-ai/claude-agent-sdk` |
| `@paybond/kit/google-adk` | `@google/adk` |
| `@paybond/kit/mastra` | `@mastra/core` |
| `@paybond/kit/cloudflare-agents` | `agents`, `ai` |
| `@paybond/kit/mcp`, `@paybond/kit/agent`, `@paybond/kit/policy` | none — no extra peers required |

```bash
npm install ai @openai/agents @langchain/core @langchain/langgraph @anthropic-ai/claude-agent-sdk @google/adk @mastra/core agents
```

Thin npm wrappers (`@paybond/vercel-ai`, `@paybond/langgraph`, `@paybond/openai-agents`, `@paybond/claude-agents`, `@paybond/google-adk`, `@paybond/mastra`, `@paybond/cloudflare-agents`, `@paybond/agent`, `@paybond/mcp`) re-export the same subpaths for npm discoverability — install whichever matches your framework instead of the whole peer list above.

## Open source and supply chain

`@paybond/kit` is distributed as open-source software under the Apache 2.0 license. The published npm package includes the full license text in `LICENSE`. Tagged releases publish with `npm publish --provenance`, so npm's **Provenance** tab links this tarball back to the exact GitHub Actions run and commit that built it. See [Package provenance and verification](https://paybond.ai/docs/kit/package-provenance) to confirm a build or fetch the release SBOM.

## Requirements

- Node.js 22+
- A `paybond_sk_sandbox_...` or `paybond_sk_live_...` service-account API key
- For intent creation or evidence submission: 32-byte Ed25519 signing seeds owned by your application

Create a sandbox key for local development:

```bash
npx -p @paybond/kit paybond login
```

`paybond login` writes a sandbox `PAYBOND_API_KEY` to `.env.local` with file mode `0600`, adds the default `.env.local` target to `.gitignore` when needed, and refuses to overwrite an existing key unless `--force` is passed. Custom env-file paths inside a git repo must already be ignored. Live production keys are created by tenant admins in Console and stored in deployment secret managers.

## CLI

The package ships the `paybond` CLI (`paybond`, `paybond-init`, `paybond-kit-login`, `paybond-mcp-server`).

Scaffold a starter project from bundled templates:

```bash
npx -p @paybond/kit paybond init --template travel-agent
npm install
npm run smoke
```

End-to-end sandbox smoke (bind + execute + evidence) with no app code:

```bash
npx -p @paybond/kit paybond agent sandbox smoke \
  --policy-file paybond.policy.yaml \
  --result-body '{"status":"completed","cost_cents":18700}' \
  --format json
```

With `--policy-file`, Kit sends `completion_preset` from the tool's `evidence_preset` and omits `evidence_schema` and `template_id` (Gateway rejects conflicting bootstrap fields). Requires `@paybond/kit` 0.11.11+.

`agent sandbox smoke` only requires `@paybond/kit`. Framework demo commands (`agent demo vercel-ai smoke`, etc.) load their optional peers on demand.

Offline local dev loop and trace dashboard:

```bash
npx -p @paybond/kit paybond dev loop --offline
npx -p @paybond/kit paybond dev trace
```

## First guardrail scaffold

Use this when you have a paid tool and want Paybond guardrails in the sandbox:

```bash
npx -p @paybond/kit paybond-init \
  --preset paid-tool-guard \
  --framework provider-agnostic \
  --out paybond-paid-tool-guard.ts
```

The generated integration opens Paybond from the environment, loads `.env.local` when `PAYBOND_API_KEY` is not already present, bootstraps a sandbox guardrail intent, wraps your paid-tool handler, and submits sandbox evidence. It does not generate a paid-tool implementation. Free Developer is sandbox-only; live settlement rails start on paid production plans.

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```ts
import { Paybond } from "@paybond/kit";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing ${name}`);
  }
  return value;
}

const paybond = await Paybond.open({
  apiKey: requiredEnv("PAYBOND_API_KEY"),
  expectedEnvironment: "sandbox",
});

try {
  console.log("tenant realm:", paybond.harbor.tenantId);
} finally {
  await paybond.aclose();
}
```

## Agent spend controls

Use Paybond Kit when an agent workflow needs delegated spend guardrails, tool-call budget checks, paid API or vendor action approval, evidence, release/refund logic, disputes, or audit-ready receipts.

```ts
import { Paybond } from "@paybond/kit";

const paybond = await Paybond.open({
  apiKey: process.env.PAYBOND_API_KEY!,
  expectedEnvironment: "sandbox",
});

const guardrail = await paybond.guardrails.bootstrapSandbox({
  operation: "travel.book_hotel",
  requestedSpendCents: 20_000,
  currency: "usd",
});

const guard = paybond.spendGuard(guardrail.intent_id, guardrail.capability_token);
const guardedTool = guard.guardTool(
  {
    operation: guardrail.operation,
    requestedSpendCents: guardrail.requested_spend_cents,
  },
  async (input) => bookHotel(input),
);

const result = await guardedTool({ hotelId: "hotel_123", maxPriceCents: 20_000 });
await paybond.guardrails.submitSandboxEvidence({
  intentId: guardrail.intent_id,
  payload: { result, sandbox: true },
});
```

The `paybond.harbor` and `paybond.guardrails` clients are created by `Paybond.open(...)` and bound to the tenant resolved from the service-account API key. Production integrations read `capability_token` from `paybond.intents.create(...)`, or from `paybond.intents.fund(...)` after an `x402_usdc_base` payment challenge is satisfied.

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-signed intent creation, x402 funding, payee-signed evidence submission, and settlement confirmation
- `PaybondSpendGuard`, `authorizeSpend`, and `guardTool` for spend-named wrappers around capability verification
- Runtime-neutral and framework aliases: `paybondAgentToolSpendGuard`, `paybondRuntimeNeutralToolSpendGuard`, `paybondLangGraphToolSpendGuard`, and `paybondMCPToolSpendGuard`
- `paybondRuntimeToolCallAdapter` for agent SDKs and custom runtimes that expose a tool-call object plus an application-owned executor

Agent middleware (`@paybond/kit/agent`) and framework subpaths (`vercel-ai`, `openai-agents`, `langgraph`, `claude-agents`, `mcp`, `policy`):

- `PaybondAgentRun`, tool registry, interceptor, and policy-file binding
- Framework adapters with optional peer dependencies (see table above)
- `paybond init`, `paybond agent run bind`, `paybond agent tool execute`, and `paybond agent sandbox smoke`

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery
- `paybond login` for sandbox device approval and local `.env.local` API-key setup
- `paybond-mcp-server` for tenant-bound MCP tool exposure to any MCP-compatible host
- `paybond-init` for generating a Paybond guardrail integration helper

Agent-facing surfaces are model-provider agnostic. Paybond verifies tool operations and tenant scope, not whether a tool call came from OpenAI, Anthropic, Gemini, a local model, or another runtime.

`allowedTools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlementRail` on intent creation is a principal-signed rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

The protocol-v2 surface is trust-first: signed mandates, recognition proofs, and receipts work across supported settlement adapters instead of treating any single rail as the product boundary.

Gateway-backed protocol helpers throw `ProtocolHttpError` with parsed `errorCode` and `errorMessage` fields when the gateway returns a JSON error envelope. Recognition-gated flows surface `unregistered_key`, `revoked_key`, `mandate_agent_key_mismatch`, and `protocol_binding_mismatch` explicitly.

## What it does not include

- No operator-tier settlement or console workflows
- No bundled LLM or model runtime — bring your own agent framework and install optional peers when needed
- No model-provider-specific MCP wrapper; the MCP server is host-agnostic and works with any MCP-compatible runtime

## Docs

- Agent and LLM discovery guide: https://paybond.ai/llms.txt
- Coding-agent setup (Markdown mirror): https://paybond.ai/docs/kit/coding-agent-setup.md
- Long-form docs: https://paybond.ai/docs/kit
- Agent quickstart: https://paybond.ai/docs/kit/quickstart-agent
- One-command guardrails: https://paybond.ai/docs/kit/one-command-guardrails
- TypeScript quickstart: https://paybond.ai/docs/kit/quickstart-typescript
- TypeScript SDK reference: https://paybond.ai/docs/kit/sdk-reference-typescript
- Support matrix (languages, frameworks, rails): https://paybond.ai/docs/kit/support-matrix
- Package provenance and verification: https://paybond.ai/docs/kit/package-provenance
- MCP server guide: https://paybond.ai/docs/kit/mcp-server
- Agent runtime tutorial: https://paybond.ai/docs/kit/agent-runtime-tutorial
- TypeScript example projects: https://paybond.ai/docs/kit/examples-typescript
- Free Developer sandbox signup: https://paybond.ai/signup

## Release verification

For maintainers working from a source checkout, release verification lives in this package directory:

```bash
npm run verify:release
```

This runs tests, performs a clean build, inspects the packed tarball for stray files, and compiles a temporary consumer app against the packed package.
