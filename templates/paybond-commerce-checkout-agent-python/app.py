"""Multi-provider commerce.checkout agent — Shopify + Stripe + Zinc (sandbox).

Uses ``instrument_commerce_checkout`` from ``paybond_kit.commerce``.
No live LLM or live merchant network required for the sandbox smoke path.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import TypedDict, cast

from paybond_config import create_paybond_client
from paybond_kit.commerce import (
    ShopifyCommerceCheckoutExecutor,
    StripeCommerceCheckoutExecuteInput,
    create_shopify_commerce_provider,
    create_stripe_commerce_provider,
    create_zinc_commerce_provider,
    instrument_commerce_checkout,
)
from paybond_kit.commerce.providers.stripe import StripeCommerceCheckoutExecutorResult
from paybond_kit.shopify.types import ShopifyCheckoutExecuteInput, ShopifyCheckoutToolResult

PRIMARY_OPERATION = "commerce.checkout"
REQUESTED_SPEND_CENTS = 4500


class GenericToolCall(TypedDict):
    tool_name: str
    tool_call_id: str
    arguments: object


class GenericToolResult(TypedDict, total=False):
    authorization: object
    evidence: object
    tool_result: object


class GenericTool(TypedDict):
    name: str
    execute: Callable[[GenericToolCall], Awaitable[GenericToolResult]]


async def main() -> None:
    paybond = await create_paybond_client()
    try:
        async def execute_shopify(
            input_payload: ShopifyCheckoutExecuteInput,
        ) -> ShopifyCheckoutToolResult:
            return {
                "status": "completed",
                "cost_cents": int(input_payload.get("amount_cents") or 0),
                "order_id": "gid://shopify/Order/demo",
                "shop": str(input_payload.get("shop_domain") or ""),
            }

        shopify_execute_checkout: ShopifyCommerceCheckoutExecutor = execute_shopify
        shopify = create_shopify_commerce_provider(execute_checkout=shopify_execute_checkout)

        async def execute_stripe(
            input_payload: StripeCommerceCheckoutExecuteInput,
        ) -> StripeCommerceCheckoutExecutorResult:
            return {
                "status": "completed",
                "cost_cents": input_payload["amount_cents"],
                "payment_intent_id": "pi_demo_sandbox",
            }

        stripe = create_stripe_commerce_provider(execute_checkout=execute_stripe)

        # Offline mock — no Zinc credentials or Gateway buy-proxy.
        zinc = create_zinc_commerce_provider(
            mode="sandbox",
            sandbox_order_id_prefix="zinc_sandbox_",
        )

        instrumented, binding_ref = await instrument_commerce_checkout(
            paybond,
            policy="./paybond.policy.yaml",
            providers={"shopify": shopify, "stripe": stripe, "zinc": zinc},
            default_provider="zinc",
            sandbox=True,
        )

        if not hasattr(instrumented, "run"):
            raise RuntimeError("expected sandbox-bound runtime; pass sandbox=True")

        # Tenant / intent from Paybond session bind — never from tool args.
        binding_ref["tenant_id"] = instrumented.run.tenant_id
        binding_ref["intent_id"] = str(instrumented.run.intent_id)

        tools = cast(list[GenericTool], instrumented.tools)
        tool = next((entry for entry in tools if entry["name"] == PRIMARY_OPERATION), None)
        if tool is None:
            raise RuntimeError(f"missing tool {PRIMARY_OPERATION}")

        result = await tool["execute"](
            {
                "tool_name": PRIMARY_OPERATION,
                "tool_call_id": "demo-1",
                "arguments": {
                    "provider": "zinc",
                    "amount_cents": REQUESTED_SPEND_CENTS,
                    "zinc": {
                        "retailer": "amazon",
                        "products": [
                            {
                                "product_id": "B00SMOKE",
                                "quantity": 1,
                                "price_cents": REQUESTED_SPEND_CENTS,
                            }
                        ],
                        "max_price_cents": 10000,
                    },
                },
            }
        )

        print(
            json.dumps(
                {
                    "run_id": instrumented.run.run_id,
                    "intent_id": str(instrumented.run.intent_id),
                    "tenant_id": instrumented.run.tenant_id,
                    "authorization": result.get("authorization"),
                    "evidence": result.get("evidence"),
                    "tool_result": result.get("tool_result"),
                },
                indent=2,
                default=str,
            )
        )
    finally:
        await paybond.aclose()


def cli_main() -> None:
    """Console entry for the ``commerce-checkout-demo`` project script."""
    asyncio.run(main())


if __name__ == "__main__":
    cli_main()
