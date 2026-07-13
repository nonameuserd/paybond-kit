"""CrewAI procurement crew with Paybond spend gates on tool calls.

Requires OPENAI_API_KEY (or your CrewAI LLM provider env) for a live kickoff.
For Harbor authorize + evidence without an LLM, use `python app.py` instead.
"""

from __future__ import annotations

import asyncio
import json
import os

from crewai import Agent, Crew, Process, Task
from crewai.tools import tool

from paybond_config import create_paybond_client


@tool("procurement.search_catalog")
def search_catalog(query: str) -> str:
    """Search the procurement catalog (read-only; not side-effecting)."""
    return json.dumps(
        {
            "query": query,
            "items": [
                {"sku": "LAP-14", "vendor_id": "vendor-acme", "unit_cents": 12000},
                {"sku": "MON-27", "vendor_id": "vendor-north", "unit_cents": 8900},
            ],
        }
    )


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


async def build_crew() -> Crew:
    paybond = await create_paybond_client()
    result = await paybond.agent(
        policy="./paybond.policy.yaml",
        framework="crewai",
        tools=[search_catalog, submit_po],
    )
    guarded_tools = result.tools

    buyer = Agent(
        role="Procurement buyer",
        goal="Find a catalog item and submit a purchase order within policy limits",
        backstory="You buy hardware for an engineering team and never exceed approved spend.",
        tools=guarded_tools,
        verbose=True,
        allow_delegation=False,
    )
    reviewer = Agent(
        role="Spend reviewer",
        goal="Confirm the PO amount stays under the Harbor budget and summarize the receipt",
        backstory="You enforce corporate spend controls and call out denials or approval holds.",
        verbose=True,
        allow_delegation=False,
    )

    find_item = Task(
        description=(
            "Search the catalog for a 14-inch laptop. "
            "Then submit a PO for vendor-acme at 12000 cents using procurement.submit_po."
        ),
        expected_output="JSON PO confirmation or a clear Paybond deny/hold message",
        agent=buyer,
    )
    review = Task(
        description=(
            "Review the buyer result. If Paybond denied or held spend, explain why. "
            "If approved, summarize vendor_id, cost_cents, and po_id."
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
    # Keep the Paybond client alive for the crew lifetime via closure.
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
