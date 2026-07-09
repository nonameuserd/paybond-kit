# paybond-stripe-agent-demo

Stripe commerce agent (generic TypeScript). Clone, log in to Paybond sandbox, and run smoke in under a minute. Uses `buildPaybondStripeMetadata` and `mapStripeToolResultToEvidence` from `@paybond/kit`.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-stripe-agent-demo.git
cd paybond-stripe-agent-demo
cp .env.example .env.local
paybond login
npm install
npm run smoke
```

Offline mock charges work with no Stripe secret — this is the default and needs zero configuration.

### Optional Stripe test-mode charge (per-tenant, sandbox-only)

`STRIPE_SECRET_KEY` is a **per-tenant, sandbox-only** setting, not a plain global env var:

- Set it **only when your Paybond tenant/session is on sandbox**. The handler reads the server-derived session environment (gateway principal) and uses the key only when that environment is `sandbox`.
- In a **live** (or unconfirmed) session the template **never** forwards the key to Stripe. If a secret is set while the session is not sandbox, it **fails closed** with an explanatory error rather than charging.
- The key must be a Stripe **TEST** key (`sk_test_...`). Live keys (`sk_live_...`) are **rejected** (fail closed).
- Stripe metadata (`tenant_id`, `paybond_intent_id`) is bound from the authenticated Paybond session only — never from client input.

When set correctly, the key exercises a Stripe test-mode PaymentIntent create + confirm; otherwise the deterministic offline mock runs.

## Run the demo

```bash
npm run build
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **stripe-commerce** (`payments.charge_customer` + `stripe_charge` evidence).

Regenerate from preset:

```bash
paybond policy init --preset stripe-commerce --out paybond.policy.yaml
```

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
- [Protect Stripe payments from agents](https://docs.paybond.ai/guides/protect-stripe-payments-from-agents)
