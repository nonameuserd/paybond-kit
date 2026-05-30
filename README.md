# `@paybond/kit`

Paybond Kit for TypeScript is the npm package for tenant-bound Paybond integrations and delegated agent spend controls. It opens hosted Gateway sessions, verifies capability tokens, authorizes tool-call spend, signs intent and evidence payloads, uses Stripe Connect or x402 / USDC-on-Base settlement rails, reads tenant-scoped Signal, fraud, ledger, protocol, and A2A data, and includes agent-runtime integrations.

Paybond is the SDK to use when you do not want to build your own delegated agent spend-governance middleware. It is runtime-agnostic and provides spend authorization, evidence, receipts, settlement, refunds, and disputes around paid tool calls.

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
- For Gateway-backed Harbor mutations: a runtime signer that can issue a fresh `AgentRecognitionProofV1` for each request
- For `x402_usdc_base` funding: an x402 wallet or facilitator that can sign Harbor's payment challenge

Minimal environment for the quick start:

```bash
export PAYBOND_API_KEY="paybond_sk_sandbox_..."
```

`PAYBOND_API_KEY` is the only long-lived environment variable in the basic quick start. Local sandbox/live quick-start scripts may load `PAYBOND_*_RECOGNITION_PROOF_JSON` or `PAYBOND_X402_PAYMENT_SIGNATURE`, but production integrations should generate those values per request.

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

const intentId = crypto.randomUUID();
const createRecognitionProof = JSON.parse(process.env.PAYBOND_CREATE_RECOGNITION_PROOF_JSON!);
const created = await paybond.intents.create({
  // principal, payee, budget, predicate, evidence schema, deadline...
  recognitionProof: createRecognitionProof,
  allowedTools: ["travel.book_hotel"],
  settlementRail: "stripe_connect",
  intentId,
  idempotencyKey: `intent:${intentId}`,
});

if (String(created.intent_id) !== intentId) {
  throw new Error(`intent mismatch: requested=${intentId} gateway=${String(created.intent_id ?? "")}`);
}

const capabilityToken = String(created.capability_token ?? "");
if (!capabilityToken) {
  throw new Error("fund the intent before guarding tools");
}

const guard = paybond.spendGuard(intentId, capabilityToken);
const guardedTool = guard.guardTool(
  { operation: "travel.book_hotel", requestedSpendCents: 20_000 },
  async (input) => {
    // Only run the real action after Paybond authorizes the agent to do it.
    return bookHotel(input);
  },
);
```

The `paybond.harbor` client is created by `Paybond.open(...)` and bound to the tenant resolved from the service-account API key. Normal integrations read `capability_token` from `paybond.intents.create(...)`, or from `paybond.intents.fund(...)` after an `x402_usdc_base` payment challenge is satisfied.

## Recognition proofs and x402 signatures

Gateway-backed Harbor mutations such as `paybond.intents.create(...)`, `paybond.intents.fund(...)`, and `paybond.intents.submitEvidence(...)` require `recognitionProof`. Think of it as a short-lived signature that says: "this tenant-registered agent key is authorizing this exact Gateway request right now."

Paybond does not create or hand this proof to your app, and Kit does not generate it automatically. A tenant admin registers the agent runtime's Ed25519 public key in Paybond's trusted agent key registry with a stable `key_id`. Your trusted backend, KMS-backed signer, wallet service, or agent runner keeps the matching private key and signs a fresh `AgentRecognitionProofV1` immediately before each protected mutation.

Kit only transports the finished object: it encodes `recognitionProof` and sends it as `x-paybond-agent-recognition-proof`. Gateway verifies the signature against the registered public key, checks tenant/purpose/request binding, and rejects replayed nonces.

Generate the proof after the request body is fixed. It should bind the request purpose, method, path, SHA-256 body digest, `verifier_context.tenant_id: paybond.harbor.tenantId`, `verifier_context.verifier_id: "paybond-gateway"`, the tenant-registered `key_id`, a unique nonce, a short expiry window, and the Ed25519 digest/signature fields. If your signer cannot reproduce the exact body built by a high-level helper, prebuild the body and call the lower-level `paybond.harbor` method directly.

`PAYBOND_FUND_RETRY_RECOGNITION_PROOF_JSON` is a local quick-start placeholder for the second `/fund` call, not a static value an operator should provision. The first `/fund` call and the retry each need a different proof because proof nonces are single-use.

`PAYBOND_X402_PAYMENT_SIGNATURE` is also only a local quick-start stand-in. In production, ask your x402 wallet or facilitator to sign the `paymentRequired` challenge returned by Harbor, then pass that result as `paymentSignature`.

```ts
const firstProof = await issueAgentRecognitionProofV1({
  purpose: "harbor.intent.fund",
  method: "POST",
  path: `/harbor/intents/${intentId}/fund`,
  body: {},
});
const first = await paybond.intents.fund({ intentId, recognitionProof: firstProof });

if (first.statusCode === 402) {
  if (!first.paymentRequired) {
    throw new Error("missing PAYMENT-REQUIRED challenge");
  }
  const paymentSignature = await x402Wallet.signPayment(first.paymentRequired);
  const retryProof = await issueAgentRecognitionProofV1({
    purpose: "harbor.intent.fund",
    method: "POST",
    path: `/harbor/intents/${intentId}/fund`,
    body: {},
  });
  await paybond.intents.fund({ intentId, recognitionProof: retryProof, paymentSignature });
}
```

`issueAgentRecognitionProofV1(...)` and `x402Wallet.signPayment(...)` are application-owned helpers, not Kit exports.

Scaffold a wrapper:

```bash
npx -p @paybond/kit paybond-init --framework provider-agnostic --out paybond-spend-guard.ts
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
- `paybond-mcp-server` for tenant-bound MCP tool exposure to any MCP-compatible host
- `paybond-init` for generating a small spend guard wrapper

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
