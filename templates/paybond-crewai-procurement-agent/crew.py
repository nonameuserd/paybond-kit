"""CrewAI procurement crew with Paybond spend gates on tool calls.

Requires OPENAI_API_KEY (or your CrewAI LLM provider env) for a live kickoff.
For Harbor authorize + evidence without an LLM, use `python app.py` instead.

Cost is catalog-backed: the model picks a SKU, not a dollar amount.
"""

from __future__ import annotations

import asyncio
import json
import os

from crewai import Agent, Crew, Process, Task
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
    """Submit a purchase order. Price comes from the catalog, not from the model."""
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


async def build_crew() -> Crew:
    paybond = await create_paybond_client()
    run = await bind_procurement_run(paybond)
    config = crewai_config_for_run(run, [search_catalog, submit_po])
    guarded_tools = config.tools

    buyer = Agent(
        role="Procurement buyer",
        goal="Find a catalog item and submit a purchase order within policy limits",
        backstory=(
            "You buy hardware for an engineering team. Call procurement.submit_po with "
            "sku and quantity only — never invent a dollar amount."
        ),
        tools=guarded_tools,
        verbose=True,
        allow_delegation=False,
    )
    reviewer = Agent(
        role="Spend reviewer",
        goal="Confirm the PO stays under the Harbor budget and summarize the receipt",
        backstory="You enforce corporate spend controls and call out denials or approval holds.",
        verbose=True,
        allow_delegation=False,
    )

    find_item = Task(
        description=(
            "Search the catalog for a 14-inch laptop. "
            f"Then submit a PO for one unit of SKU LAP-14 using {PRIMARY_OPERATION}."
        ),
        expected_output="JSON PO confirmation or a clear Paybond deny/hold message",
        agent=buyer,
    )
    review = Task(
        description=(
            "Review the buyer result. If Paybond denied or held spend, explain why. "
            "If approved, summarize sku, vendor_id, cost_cents, and po_id."
        ),
        expected_output="Short spend-control summary for an operator",
        agent=reviewer,
        context=[find_item],
    )

    crew = Crew(
        agents=[buyer, reviewer],
        tasks=[find_item, review],
        process=Process.sequential,
        verbose=True,
    )
    crew._paybond_client = paybond  # type: ignore[attr-defined]
    return crew


async def main() -> None:
    if not os.environ.get("OPENAI_API_KEY", "").strip():
        raise SystemExit(
            "OPENAI_API_KEY is required for crew kickoff. "
            "Use `python app.py` for a no-LLM Harbor smoke, or set your LLM key."
        )
    crew = await build_crew()
    try:
        output = crew.kickoff()
        print(output)
    finally:
        paybond = getattr(crew, "_paybond_client", None)
        if paybond is not None:
            await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
