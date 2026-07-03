# paybond-invoice-agent

Invoice processing agent (Python LangGraph). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-invoice-agent.git
cd paybond-invoice-agent
cp .env.example .env.local
paybond-kit-login
pip install -r requirements.txt
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation saas.provision_seat --requested-spend-cents 2900 --result-body '{"status":"completed","cost_cents":2900}' --format json
```

## Run the demo

```bash
python app.py
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **saas**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
