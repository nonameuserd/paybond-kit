# `@paybond/kit`

Paybond Kit for TypeScript provides a tenant-bound Harbor client, gateway-backed service-account sessions, capability verification, canonical signing helpers for intent creation and evidence submission, x402 / USDC-on-Base intent funding helpers, tenant-scoped ledger provenance reads, and tenant-scoped Signal analytics and reputation reads.

Install the public package with:

```bash
npm install @paybond/kit
```

## Open source

`@paybond/kit` is distributed as open-source software under the Apache 2.0 license. The published npm package includes the full license text in `LICENSE`.

## Requirements

- Node.js 22+
- A `paybond_sk_...` service-account API key
- Reachable Gateway and Harbor base URLs

## Tenant isolation

Every session is bound to the tenant realm echoed by gateway-authenticated service-account introspection and Harbor access exchange flows.

- Do not pass tenant ids by hand for normal SDK usage.
- Construct one `Paybond` session per tenant/service account.
- Treat any tenant or intent echo mismatch from Harbor as a severity-zero defect.

## Quick start

```ts
import { Paybond } from "@paybond/kit";

const paybond = await Paybond.open({
  gatewayBaseUrl: "https://gateway.example.com",
  apiKey: process.env.PAYBOND_API_KEY!,
  harborBaseUrl: "https://harbor.example.com",
});

try {
  const verified = await paybond.harbor.verifyCapability({
    intentId: process.env.PAYBOND_INTENT_ID!,
    token: process.env.PAYBOND_CAPABILITY!,
    operation: "payments.capture",
    requestedSpendCents: 18_700,
  });

  if (!verified.allow) {
    throw new Error(`verify denied: ${verified.code ?? "deny"} ${verified.message ?? ""}`);
  }
} finally {
  await paybond.aclose();
}
```

## What the package includes

- `Paybond.open(...)` for gateway-authenticated, tenant-derived Harbor sessions
- `HarborClient` for capability verification, intent creation, x402 funding, evidence submission, and ledger reads
- `GatewaySignalClient` and `ServiceAccountSignalSession` for tenant-scoped Signal reads
- `paybond.signal` on `Paybond` sessions opened from one service-account API key
- `PaybondIntents` helpers for principal-signed intent creation, x402 funding, and payee-signed evidence submission
- Low-level signing helpers exported for advanced callers

`allowedTools` values are your own tool or operation names, not a Paybond-owned catalog. Harbor enforces string matching against whatever names you chose when creating the intent.

`settlementRail` on intent creation is only a rail request. Stripe destinations and x402 receive addresses stay tenant-owned server-side config and are never supplied by the SDK caller.

## What it does not include

- No operator-tier settlement or console workflows

## Docs

- Long-form docs: `docs/kit/`
- Agents SDK tutorial: `docs/kit/openai-agents.md`
- TypeScript quickstart: `docs/kit/quickstart-typescript.md`
- TypeScript SDK reference: `docs/kit/sdk-reference-typescript.md`
- Example app: `examples/paybond-kit-typescript/`
- OpenAI Agents example: `examples/paybond-kit-openai-agents-typescript/`

## Release verification

From `kit/ts`:

```bash
npm run verify:release
```

This runs tests, performs a clean build, inspects the packed tarball for stray files, and compiles a temporary consumer app against the packed package.
