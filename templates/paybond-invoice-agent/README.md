# paybond-invoice-agent

Invoice processing agent (Python LangGraph). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-invoice-agent.git
cd paybond-invoice-agent
cp .env.example .env.local
paybond-kit-login
uv sync   # or: pip install -e .
paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation saas.provision_seat --requested-spend-cents 2900 --result-body '{"status":"completed","cost_cents":2900}' --format json
```

Install is a normal Python project (`pyproject.toml`). The `paybond` CLI ships with `paybond-kit` — no Node/`package.json` required.

## Run the demo

```bash
python app.py   # or: paybond-template-demo
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **saas**.

## Docs

- [Agent quickstart](https://paybond.ai/docs/kit/quickstart-agent)
- [Agent middleware](https://paybond.ai/docs/kit/agent-middleware)
