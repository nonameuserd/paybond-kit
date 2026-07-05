# paybond-mastra-travel-agent

Travel booking agent (Mastra). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-mastra-travel-agent.git
cd paybond-mastra-travel-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation travel.book_hotel --requested-spend-cents 18700 --result-body '{"status":"completed","cost_cents":18700}' --format json
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **travel**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
