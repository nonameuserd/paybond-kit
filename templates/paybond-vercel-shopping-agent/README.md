# paybond-vercel-shopping-agent

Shopping checkout agent (Vercel AI). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-vercel-shopping-agent.git
cd paybond-vercel-shopping-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation commerce.checkout --requested-spend-cents 4500 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":4500}' --format json
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
