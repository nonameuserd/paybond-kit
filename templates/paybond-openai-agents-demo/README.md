# paybond-openai-agents-demo

SaaS provisioning agent (OpenAI Agents). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-openai-agents-demo.git
cd paybond-openai-agents-demo
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation saas.provision_seat --requested-spend-cents 2900 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":2900}' --format json
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **saas**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
