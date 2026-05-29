# `@paybond/kit`

Paybond Kit for TypeScript is the npm package for tenant-bound Paybond integrations. It opens hosted Gateway sessions, verifies capability tokens, signs intent and evidence payloads, uses Stripe Connect or x402 / USDC-on-Base settlement rails, and reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data.

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

Minimal environment for the quick start:

```bash
export PAYBOND_API_KEY="paybond_sk_sandbox_..."
```

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

## What the package includes

Core SDK:

- `Paybond.open(...)` for API-key-only, tenant-derived hosted sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `paybond.signal` and `paybond.fraud` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-signed intent creation, x402 funding, and payee-signed evidence submission

Gateway and trust helpers:

- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads and signed portfolio artifacts
- `GatewayFraudClient` and `ServiceAccountFraudSession` for tenant-scoped fraud assessments, review queues, review events, metrics, and release-gate config
- Protocol-v2 helpers for mandate verification, replay-safe recognition proof verification, receipt reads, and A2A discovery
- `paybond-mcp-server` for tenant-bound MCP tool exposure to any MCP-compatible host

Agent-facing surfaces are model-provider agnostic. Paybond verifies tool operations and tenant scope, not whether a tool call came from OpenAI, Anthropic, Gemini, a local model, or another runtime.

Advanced exports:

- Low-level signing helpers for callers that need to pre-build signed request bodies or evidence payloads

`allowedTools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlementRail` on intent creation is a principal-signed rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

The protocol-v2 surface is trust-first: signed mandates, recognition proofs, and receipts work across supported settlement adapters instead of treating any single rail as the product boundary.

Gateway-backed protocol helpers throw `ProtocolHttpError` with parsed `errorCode` and `errorMessage` fields when the gateway returns a JSON error envelope. Recognition-gated flows surface `unregistered_key`, `revoked_key`, `mandate_agent_key_mismatch`, and `protocol_binding_mismatch` explicitly.

## What it does not include

- No operator-tier settlement or console workflows
- No model-provider-specific TypeScript agent wrapper; use the documented app-side wrapper pattern with `PaybondCapabilityBinding`
- No model-provider-specific MCP wrapper; the MCP server is host-agnostic and works with any MCP-compatible runtime

## Docs

- Long-form docs: https://paybond.ai/docs/kit
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
