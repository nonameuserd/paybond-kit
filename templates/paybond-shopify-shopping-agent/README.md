# paybond-shopify-shopping-agent

Shopify shopping agent (UCP + Kit binding). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-shopify-shopping-agent.git
cd paybond-shopify-shopping-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation commerce.checkout --requested-spend-cents 4500 --result-body '{"status":"completed","cost_cents":4500,"order_id":"gid://shopify/Order/123","shop":"paybond-agent-commerce-dev.myshopify.com"}' --format json
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **shopping**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
