# paybond-procurement-agent

Procurement agent (generic TypeScript). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-procurement-agent.git
cd paybond-procurement-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation procurement.submit_po --requested-spend-cents 12000 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":12000}' --format json
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **custom**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
