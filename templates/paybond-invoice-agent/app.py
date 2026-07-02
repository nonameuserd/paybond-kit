"""Invoice processing agent (Python LangGraph) — LangGraph sandbox demo (no live LLM)."""

from __future__ import annotations

import asyncio
import json

from paybond_config import create_paybond_client
from paybond_kit.langgraph_sandbox_demo import run_langgraph_sandbox_demo


async def main() -> None:
    paybond = await create_paybond_client()
    try:
        demo = await run_langgraph_sandbox_demo(
            paybond,
            operation="saas.provision_seat",
            requested_spend_cents=2900,
            evidence_preset="cost_and_completion",
        )
        print(json.dumps(demo, indent=2, default=str))
    finally:
        await paybond.aclose()


if __name__ == "__main__":
    asyncio.run(main())
