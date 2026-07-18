"""Authoritative procurement catalog — unit prices live here, not in the LLM.

Spend for ``procurement.submit_po`` is derived from SKU (+ quantity) via this module.
The agent may choose *which* SKU to buy; it must not invent a dollar amount.
"""

from __future__ import annotations

from typing import TypedDict


class CatalogItem(TypedDict):
    sku: str
    vendor_id: str
    unit_cents: int
    name: str


CATALOG: dict[str, CatalogItem] = {
    "LAP-14": {
        "sku": "LAP-14",
        "vendor_id": "vendor-acme",
        "unit_cents": 12_000,
        "name": "14-inch laptop",
    },
    "MON-27": {
        "sku": "MON-27",
        "vendor_id": "vendor-north",
        "unit_cents": 8_900,
        "name": "27-inch monitor",
    },
    # Intentionally above the sample intent budget ($250) — used by `python app.py --deny`.
    "RACK-1U": {
        "sku": "RACK-1U",
        "vendor_id": "vendor-acme",
        "unit_cents": 50_000,
        "name": "1U rack server",
    },
}


def lookup(sku: str) -> CatalogItem:
    """Return the catalog row for ``sku``.

    :raises KeyError: if the SKU is unknown (callers should not invent prices).
    """
    key = sku.strip()
    item = CATALOG.get(key)
    if item is None:
        raise KeyError(f"unknown catalog sku: {sku!r}")
    return item


def spend_cents_for(sku: str, quantity: int = 1) -> int:
    """Compute authorized spend for a PO from catalog price × quantity."""
    if quantity < 1:
        raise ValueError("quantity must be >= 1")
    return lookup(sku)["unit_cents"] * quantity


def search(query: str) -> list[CatalogItem]:
    """Simple substring search over SKU and name (demo-quality)."""
    needle = query.strip().lower()
    if not needle:
        return list(CATALOG.values())
    return [
        item
        for item in CATALOG.values()
        if needle in item["sku"].lower() or needle in item["name"].lower()
    ]
