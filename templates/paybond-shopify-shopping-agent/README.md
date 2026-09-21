# paybond-shopify-shopping-agent

Shopify shopping agent (UCP and Kit binding). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-shopify-shopping-agent.git
cd paybond-shopify-shopping-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **shopping**.

## Docs

- [Agent quickstart](https://paybond.ai/docs/kit/quickstart-agent)
- [Agent middleware](https://paybond.ai/docs/kit/agent-middleware)
