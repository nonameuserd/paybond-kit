# paybond-commerce-checkout-agent

Multi-provider shopping agent using `@paybond/kit/commerce` — one `commerce.checkout` tool routes across Shopify, Stripe, and Zinc (sandbox) adapters while Paybond stays the authorize → prove → release → receipt layer.

## Quickstart (60 seconds)

```bash
paybond init --template commerce-checkout-agent
cd <your-project-dir>   # or scaffold into the current directory with --force
cp .env.example .env.local
paybond login
npm install
npm run smoke
```

Python twin: `paybond init --template commerce-checkout-agent --language python`

Or clone the published template:

```bash
git clone https://github.com/nonameuserd/paybond-commerce-checkout-agent.git
cd paybond-commerce-checkout-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke
```

## Run the demo

```bash
npm start
```

The demo instruments `commerce.checkout` with Shopify + Stripe mock executors and Zinc sandbox (no live network). Session `tenantId` / `intentId` are set from the sandbox bind — never from tool args.

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **shopping** (`commerce.checkout` + `cost_and_completion`).

## Docs

- [Multi-provider commerce checkout](https://paybond.ai/docs/kit/commerce-checkout)
- [Guide: multi-provider checkout](https://paybond.ai/guides/multi-provider-commerce-checkout)
- [Shopify-only helper](https://paybond.ai/guides/protect-shopify-payments-from-agents) — prefer when you only ever check out on Shopify
