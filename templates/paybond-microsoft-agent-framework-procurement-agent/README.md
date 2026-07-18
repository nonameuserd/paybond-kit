# paybond-microsoft-agent-framework-procurement-agent

Procurement agent ([Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/) + Paybond spend gates). Clone, log in to the Paybond sandbox, and run the Harbor smoke in under a minute.

Standalone counterpart to the pattern discussed in [microsoft/agent-framework#7078](https://github.com/microsoft/agent-framework/issues/7078) (closed as not planned for the upstream samples tree). **Sandbox demo only** — not a production payment product.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-microsoft-agent-framework-procurement-agent.git
cd paybond-microsoft-agent-framework-procurement-agent
cp .env.example .env.local
paybond login
pip install -r requirements.txt
npm run smoke
```

## Run the demo (no LLM required)

```bash
python app.py          # approve — LAP-14 @ $120 from catalog
python app.py --deny   # deny — RACK-1U @ $500 (over intent budget; tool never runs)
```

## Design choices

| Concern | How this repo handles it |
| --- | --- |
| Agent invents the dollar amount | **No.** `procurement.submit_po(sku, quantity)` prices from `catalog.py`. Harbor’s spend resolver uses the same catalog lookup before the tool body runs. |
| Separate path outside MAF function approval | Intentional for an *external* spend-authorization layer. Framework HITL and Harbor spend are different layers. |
| Looks production-ready because money is involved | Explicitly a **sandbox** quickstart. |

## What this shows

| Path | What happens |
| --- | --- |
| **Approve** | Harbor verifies catalog-derived spend → `procurement.submit_po` runs → auto-evidence |
| **Deny** | Over-budget SKU → tool body never runs (error string returned to the model) |
| **Approval hold** | Operator approves in the tenant console, then retry with `approvalToken` |

## Live agent kickoff (needs an LLM)

```bash
az login
python agent.py
```

## Policy

Local `paybond.policy.yaml` matches the CrewAI procurement starter (`procurement.submit_po`, $250 intent budget). Edit freely.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
- [Microsoft Agent Framework adapter](https://docs.paybond.ai/kit/microsoft-agent-framework)

## License

Apache-2.0
