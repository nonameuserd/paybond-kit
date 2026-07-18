"""Procurement agent (Microsoft Agent Framework + Paybond spend gates) — no live LLM.

Drives the function-middleware body that gates a paid tool, against a synthetic
tool-call context, so you can prove authorize → execute → evidence (and deny)
without spending LLM tokens.

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
from types import SimpleNamespace
from typing import Any

from paybond_kit.microsoft_agent_framework import process_paybond_function_invocation

from catalog import lookup, spend_cents_for
from paybond_config import create_paybond_client
from paybond_wiring import PRIMARY_OPERATION, bind_procurement_run


def search_catalog(query: str) -> dict[str, Any]:
    """Search the procurement catalog (read-only; not side-effecting)."""
    from catalog import search

    return {"query": query, "items": search(query)}


# Tool name must match policy / Harbor operation (same as CrewAI starter).
search_catalog.__name__ = "procurement.search_catalog"
search_catalog.__qualname__ = "procurement.search_catalog"


def submit_po(sku: str, quantity: int = 1) -> dict[str, Any]:
    """Submit a PO. Unit price comes from the catalog — callers do not pass dollars."""
    item = lookup(sku)
    cost_cents = spend_cents_for(sku, quantity)
    return {
        "status": "completed",
        "sku": item["sku"],
        "vendor_id": item["vendor_id"],
        "quantity": quantity,
        "cost_cents": cost_cents,
        "po_id": f"po-{item['sku']}-x{quantity}",
    }


submit_po.__name__ = "procurement.submit_po"
submit_po.__qualname__ = "procurement.submit_po"


async def main() -> None:
    """Bind a sandbox run, then push one synthetic ``procurement.submit_po`` call through the gate."""
    deny = "--deny" in sys.argv[1:]
    sku = "RACK-1U" if deny else "LAP-14"
    quantity = 1

    paybond = await create_paybond_client()
    try:
        run = await bind_procurement_run(paybond)

        executed = False

        async def call_next() -> None:
            """Stand-in for the Agent Framework invoking the real tool body."""
            nonlocal executed
            executed = True
            context.result = submit_po(sku=sku, quantity=quantity)

        context = SimpleNamespace(
            function=SimpleNamespace(name=PRIMARY_OPERATION),
            arguments={"sku": sku, "quantity": quantity},
            metadata={"call_id": f"maf-demo-{sku}"},
            result=None,
        )

        await process_paybond_function_invocation(run, context, call_next)

        tool_result: Any = context.result
        denied = isinstance(tool_result, str) and tool_result.startswith("Paybond capability")

        print(
            json.dumps(
                {
                    "mode": "deny" if deny else "approve",
                    "sku": sku,
                    "catalog_unit_cents": lookup(sku)["unit_cents"],
                    "run_id": run.run_id,
                    "tenant_id": run.tenant_id,
                    "intent_id": str(run.intent_id),
                    "tool_executed": executed,
                    "authorized": not denied,
                    "tool_result": tool_result,
                },
                indent=2,
                default=str,
            )
        )
    finally:
        await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
