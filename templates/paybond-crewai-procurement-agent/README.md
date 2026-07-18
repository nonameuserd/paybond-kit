# paybond-crewai-procurement-agent

Procurement crew (CrewAI + Paybond spend gates). Clone, log in to Paybond sandbox, and run smoke in under a minute.

**Sandbox demo only.** Spend for `procurement.submit_po` is priced from `catalog.py` (SKU × quantity) — the agent must not invent `amount_cents`.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-crewai-procurement-agent.git
cd paybond-crewai-procurement-agent
cp .env.example .env.local
paybond login
pip install -r requirements.txt
npm run smoke
```

## Run the demo

```bash
python app.py          # approve — LAP-14 @ $120 from catalog
python app.py --deny   # deny — RACK-1U @ $500 (over intent budget; tool never runs)
```

## What this crew shows

| Path | What happens |
| --- | --- |
| **Approve** | Harbor verifies catalog-derived spend → `procurement.submit_po` runs → auto-evidence |
| **Deny** | Over-budget SKU → tool body never runs |
| **Approval hold** | Operator approves in the tenant console, then retry with `approvalToken` |

Live CrewAI kickoff (needs an LLM key):

```bash
export OPENAI_API_KEY=sk-...
python crew.py
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled intent budget: **$250**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
- [CrewAI adapter](https://docs.paybond.ai/kit/crewai)
- [CrewAI spend controls guide](https://docs.paybond.ai/guides/crewai-spend-controls)

## License

Apache-2.0
