"""Bind a sandbox run whose spend resolver prices tools from ``catalog``, not the LLM.

Cost is a function of the tool (SKU → catalog unit price × quantity), not an
``amount_cents`` the agent invents — matching the intent of Harbor preflight.
"""

from __future__ import annotations

from typing import Any

from paybond_kit import Paybond
from paybond_kit.agent.registry import create_paybond_tool_registry
from paybond_kit.agent.run import PaybondAgentRun
from paybond_kit.microsoft_agent_framework import (
    create_paybond_microsoft_agent_framework_config,
)

from catalog import spend_cents_for

PRIMARY_OPERATION = "procurement.submit_po"
# Fund the sandbox intent for the happy-path laptop PO ($120).
BOOTSTRAP_SPEND_CENTS = 12_000


def _spend_from_catalog(args: object) -> int:
    """Harbor preflight: resolve spend from SKU/qty before the tool body runs."""
    if not isinstance(args, dict):
        raise TypeError("procurement.submit_po arguments must be a mapping")
    sku = str(args["sku"])
    quantity = int(args.get("quantity", 1))
    return spend_cents_for(sku, quantity)


def _evidence_from_tool_result(result: object, _ctx: object) -> dict[str, Any]:
    """Normalize JSON-string or dict tool results for cost_and_completion evidence."""
    import json

    payload: Any = result
    if isinstance(result, str):
        payload = json.loads(result)
    if not isinstance(payload, dict):
        raise TypeError("procurement.submit_po must return a JSON object")
    return {"status": payload.get("status"), "cost_cents": payload.get("cost_cents")}


def create_procurement_registry() -> Any:
    """Registry where ``procurement.submit_po`` spend is derived from the catalog."""
    return create_paybond_tool_registry(
        {
            "default_deny": True,
            "side_effecting": {
                PRIMARY_OPERATION: {
                    "operation": PRIMARY_OPERATION,
                    "evidence_preset": "cost_and_completion",
                    "spend_cents": _spend_from_catalog,
                    "evidence_mapper": _evidence_from_tool_result,
                }
            },
        }
    )


async def bind_procurement_run(paybond: Paybond) -> PaybondAgentRun:
    """Open a sandbox agent run with catalog-backed spend resolution."""
    return await paybond.agent_run.bind(
        {
            "bootstrap": {
                "kind": "sandbox",
                "operation": PRIMARY_OPERATION,
                "requested_spend_cents": BOOTSTRAP_SPEND_CENTS,
                "completion_preset": "cost_and_completion",
            },
            "registry": create_procurement_registry(),
        }
    )


def maf_config_for_run(run: PaybondAgentRun, tools: list[Any]) -> Any:
    """Passthrough tools + required function middleware for Agent Framework."""
    return create_paybond_microsoft_agent_framework_config(run, tools)
