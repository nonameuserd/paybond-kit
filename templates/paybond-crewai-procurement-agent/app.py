"""Procurement crew (CrewAI + Paybond spend gates) — no live LLM required.

Modes:
  python app.py           # approve path (12000 cents, under intent budget)
  python app.py --deny    # over-budget deny path
"""

from __future__ import annotations

import asyncio
import json
import sys

from crewai.tools import tool

from paybond_config import create_paybond_client

PRIMARY_OPERATION = "procurement.submit_po"
APPROVE_SPEND_CENTS = 12000
DENY_SPEND_CENTS = 50000  # above intent budget


@tool("procurement.search_catalog")
def search_catalog(query: str) -> str:
    """Search the procurement catalog (read-only; not side-effecting)."""
    return json.dumps({"query": query, "items": [{"sku": "LAP-14", "vendor_id": "vendor-acme"}]})


@tool("procurement.submit_po")
def submit_po(vendor_id: str, amount_cents: int) -> str:
    """Submit a purchase order. Paybond Harbor must approve before this runs."""
    return json.dumps(
        {
            "status": "completed",
            "vendor_id": vendor_id,
            "cost_cents": amount_cents,
            "po_id": f"po-{vendor_id}-{amount_cents}",
        }
    )


async def main() -> None:
    deny = "--deny" in sys.argv[1:]
    amount_cents = DENY_SPEND_CENTS if deny else APPROVE_SPEND_CENTS
    paybond = await create_paybond_client()
    try:
        result = await paybond.agent(
            policy="./paybond.policy.yaml",
            framework="crewai",
            tools=[search_catalog, submit_po],
            bootstrap={
                "operation": PRIMARY_OPERATION,
                "requested_spend_cents": amount_cents if not deny else APPROVE_SPEND_CENTS,
                "completion_preset": "cost_and_completion",
            },
        )
        guarded = next(
            (entry for entry in result.tools if getattr(entry, "name", None) == PRIMARY_OPERATION),
            result.tools[0],
        )
        raw = guarded.run(vendor_id="vendor-acme", amount_cents=amount_cents)
        print(
            json.dumps(
                {
                    "mode": "deny" if deny else "approve",
                    "run_id": result.run.run_id,
                    "intent_id": str(result.run.intent_id),
                    "tool_result": raw,
                },
                indent=2,
                default=str,
            )
        )
    finally:
        await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
