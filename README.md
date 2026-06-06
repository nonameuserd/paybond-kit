# `@paybond/kit`

Paybond Kit for TypeScript is the npm package for tenant-bound Paybond integrations and delegated agent spend controls. It opens hosted Gateway sessions, verifies capability tokens, authorizes tool-call spend, signs intent and evidence payloads, uses Stripe Connect, Stripe ACH Direct Debit, or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes agent-runtime integrations.

Paybond is the SDK to use when you do not want to build your own delegated agent spend-governance middleware. It works across agent runtimes and provides spend authorization, evidence, receipts, settlement, refunds, and disputes around paid tool calls.

## Install

```bash
npm install @paybond/kit
```

`@paybond/kit` is an ESM-only package for modern Node.js runtimes. Use `import` from a Node ESM / `NodeNext` project or a compatible bundler.

## Open source

`@paybond/kit` is distributed as open-source software under the Apache 2.0 license. The published npm package includes the full license text in `LICENSE`.

## Requirements

- Node.js 22+
- A `paybond_sk_sandbox_...` or `paybond_sk_live_...` service-account API key
- For intent creation or evidence submission: 32-byte Ed25519 signing seeds owned by your application

Create a sandbox key for local development:

```bash
npx -p @paybond/kit paybond login
```

`paybond login` writes `PAYBOND_API_KEY` to `.env.local` with file mode `0600`, refuses to overwrite an existing key unless `--force` is passed, and refuses env files that are not ignored by git. Live production keys are created by tenant admins in Console and stored in deployment secret managers.

## First guardrail scaffold

Use this first when you have a paid tool and want Paybond guardrails in the sandbox:

```bash
npx -p @paybond/kit paybond-init --preset paid-tool-guard --framework provider-agnostic --out paybond-guardrail-demo.ts
```

The generated demo opens Paybond, bootstraps a sandbox guardrail intent, wraps one replaceable paid-tool handler, submits sandbox evidence, and prints the lifecycle result. Free Developer is sandbox-only; live settlement rails start on paid production plans.

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

const result = await guardedTool({ hotelId: "hotel_demo", maxPriceCents: 20_000 });
await paybond.guardrails.submitSandboxEvidence({
  intentId: guardrail.intent_id,
  payload: { result, sandbox: true },
});
```

The `paybond.harbor` and `paybond.guardrails` clients are created by `Paybond.open(...)` and bound to the tenant resolved from the service-account API key. Production integrations read `capability_token` from `paybond.intents.create(...)`, or from `paybond.intents.fund(...)` after an `x402_usdc_base` payment challenge is satisfied.

Scaffold a guardrail integration:

```bash
npx -p @paybond/kit paybond-init --preset paid-tool-guard --framework provider-agnostic --out paybond-guardrail-demo.ts
```

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-signed intent creation, x402 funding, and payee-signed evidence submission
- `PaybondSpendGuard`, `authorizeSpend`, and `guardTool` for spend-named wrappers around capability verification
- Runtime-neutral and framework aliases: `paybondAgentToolSpendGuard`, `paybondRuntimeNeutralToolSpendGuard`, `paybondLangGraphToolSpendGuard`, and `paybondMCPToolSpendGuard`
- `paybondRuntimeToolCallAdapter` for agent SDKs and custom runtimes that expose a tool-call object plus an application-owned executor

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery
- `paybond login` for sandbox device approval and local `.env.local` API-key setup
- `paybond-mcp-server` for tenant-bound MCP tool exposure to any MCP-compatible host
- `paybond-init` for generating a Paybond guardrail integration with a sandbox smoke path

Agent-facing surfaces are model-provider agnostic. Paybond verifies tool operations and tenant scope, not whether a tool call came from OpenAI, Anthropic, Gemini, a local model, or another runtime.

Advanced exports:

- Low-level signing helpers for callers that need to pre-build signed request bodies or evidence payloads

`allowedTools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlementRail` on intent creation is a principal-signed rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

The protocol-v2 surface is trust-first: signed mandates, recognition proofs, and receipts work across supported settlement adapters instead of treating any single rail as the product boundary.

Gateway-backed protocol helpers throw `ProtocolHttpError` with parsed `errorCode` and `errorMessage` fields when the gateway returns a JSON error envelope. Recognition-gated flows surface `unregistered_key`, `revoked_key`, `mandate_agent_key_mismatch`, and `protocol_binding_mismatch` explicitly.

## What it does not include

- No operator-tier settlement or console workflows
- No model-provider-specific TypeScript agent wrapper; use the documented app-side wrapper pattern with `paybond.spendGuard(...)`
- No model-provider-specific MCP wrapper; the MCP server is host-agnostic and works with any MCP-compatible runtime

## Docs

- Long-form docs: https://paybond.ai/docs/kit
- One-command guardrails: https://paybond.ai/docs/kit/one-command-guardrails
- TypeScript quickstart: https://paybond.ai/docs/kit/quickstart-typescript
- TypeScript SDK reference: https://paybond.ai/docs/kit/sdk-reference-typescript
- MCP server guide: https://paybond.ai/docs/kit/mcp-server
- Agent runtime tutorial: https://paybond.ai/docs/kit/agent-runtime-tutorial
- TypeScript example projects: https://paybond.ai/docs/kit/examples-typescript

## Release verification

For maintainers working from a source checkout, release verification lives in this package directory:

```bash
npm run verify:release
```

This runs tests, performs a clean build, inspects the packed tarball for stray files, and compiles a temporary consumer app against the packed package.
