"""Procurement crew (CrewAI + Paybond spend gates) — no live LLM required.

Modes:
  python app.py           # approve path (LAP-14 @ $120 from catalog)
  python app.py --deny    # over-budget deny (RACK-1U @ $500 — tool body never runs)

Cost is not chosen by the agent: Harbor prices the call from ``catalog`` via the
spend resolver (SKU × quantity) before ``procurement.submit_po`` runs.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from crewai.tools import tool

from catalog import lookup, search, spend_cents_for
from paybond_config import create_paybond_client
from paybond_wiring import PRIMARY_OPERATION, bind_procurement_run, crewai_config_for_run


@tool("procurement.search_catalog")
def search_catalog(query: str) -> str:
    """Search the procurement catalog (read-only; not side-effecting)."""
    return json.dumps({"query": query, "items": search(query)})


@tool("procurement.submit_po")
def submit_po(sku: str, quantity: int = 1) -> str:
    """Submit a PO. Unit price comes from the catalog — callers do not pass dollars."""
    item = lookup(sku)
    cost_cents = spend_cents_for(sku, quantity)
    return json.dumps(
        {
            "status": "completed",
            "sku": item["sku"],
            "vendor_id": item["vendor_id"],
            "quantity": quantity,
            "cost_cents": cost_cents,
            "po_id": f"po-{item['sku']}-x{quantity}",
        }
    )


async def main() -> None:
    """Bind a sandbox run, then invoke the guarded ``procurement.submit_po`` tool."""
    deny = "--deny" in sys.argv[1:]
    sku = "RACK-1U" if deny else "LAP-14"
    quantity = 1

    paybond = await create_paybond_client()
    try:
        run = await bind_procurement_run(paybond)
        config = crewai_config_for_run(run, [search_catalog, submit_po])
        guarded = next(
            (
                entry
                for entry in config.tools
                if getattr(entry, "name", None) == PRIMARY_OPERATION
            ),
            config.tools[0],
        )
        raw: Any = guarded.run(sku=sku, quantity=quantity)
        denied = isinstance(raw, str) and "Paybond" in raw and (
            "denied" in raw.lower() or "approval" in raw.lower()
        )
        print(
            json.dumps(
                {
                    "mode": "deny" if deny else "approve",
                    "sku": sku,
                    "catalog_unit_cents": lookup(sku)["unit_cents"],
                    "run_id": run.run_id,
                    "tenant_id": run.tenant_id,
                    "intent_id": str(run.intent_id),
                    "authorized": not denied,
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
