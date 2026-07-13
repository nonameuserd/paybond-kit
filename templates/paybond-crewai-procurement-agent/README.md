# paybond-crewai-procurement-agent

Procurement crew (CrewAI + Paybond spend gates). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-crewai-procurement-agent.git
cd paybond-crewai-procurement-agent
cp .env.example .env.local
paybond-kit-login
pip install -r requirements.txt
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation procurement.submit_po --requested-spend-cents 12000 --result-body '{"status":"completed","cost_cents":12000}' --format json
```

## Run the demo

```bash
python app.py
```

## What this crew shows

Paybond wraps CrewAI `@tool` / `BaseTool` handlers at the execution boundary:

| Path | What happens |
| --- | --- |
| **Approve** | Harbor verifies spend → `procurement.submit_po` runs → auto-evidence |
| **Deny** | Over-budget / hard deny → tool body never runs (error string returned) |
| **Approval hold** | Operator approves in the tenant console, then retry with `approvalToken` |

No-LLM Harbor smoke:

```bash
python app.py          # approve (~$120)
python app.py --deny   # over-budget deny
```

CrewAI adapter smoke (optional):

```bash
paybond agent demo crewai smoke \
  --operation procurement.submit_po \
  --requested-spend-cents 12000 \
  --evidence-preset cost_and_completion \
  --format json
```

Live CrewAI kickoff (needs an LLM key):

```bash
export OPENAI_API_KEY=sk-...
python crew.py
```

## CrewAI Marketplace

This repo is structured for [marketplace.crewai.com](https://marketplace.crewai.com) listing:

- Clear spend-gate story on a procurement PO tool
- Sandbox-first quickstart (`paybond login`)
- Apache-2.0 license

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **custom**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
- [CrewAI adapter](https://docs.paybond.ai/kit/crewai)
- [CrewAI spend controls guide](https://docs.paybond.ai/guides/crewai-spend-controls)
