"""Shared Paybond sandbox client setup for the Microsoft Agent Framework demo.

Loads ``PAYBOND_API_KEY`` from the environment (or ``.env.local``) and opens a
sandbox-scoped :class:`paybond_kit.Paybond` client. No secrets are hard-coded and
no tenant identifiers are ever invented client-side — tenant context is derived
entirely from the authenticated Paybond credential.
"""

from __future__ import annotations

import os
from pathlib import Path

from paybond_kit import Paybond


def _read_env_value(body: str, key: str) -> str | None:
    """Parse a single ``KEY=value`` (or ``export KEY=value``) line from an env file body."""
    for raw_line in body.splitlines():
        line = raw_line.strip()
        for prefix in (f"export {key}=", f"{key}="):
            if line.startswith(prefix):
                value = line[len(prefix) :].strip()
                if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                    value = value[1:-1]
                return value.strip() or None
    return None


def load_paybond_env_file(env_file: str = ".env.local") -> None:
    """Populate ``PAYBOND_API_KEY`` from ``env_file`` when it is not already set."""
    if os.environ.get("PAYBOND_API_KEY", "").strip():
        return
    path = Path(env_file)
    try:
        body = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return
    api_key = _read_env_value(body, "PAYBOND_API_KEY")
    if api_key:
        os.environ["PAYBOND_API_KEY"] = api_key


async def create_paybond_client() -> Paybond:
    """Open a sandbox-scoped Paybond client using the local API key.

    :raises RuntimeError: if no ``PAYBOND_API_KEY`` is available. Run ``paybond login``
        (or ``paybond-kit-login``) to provision a sandbox key first.
    :returns: an open :class:`paybond_kit.Paybond` client bound to the sandbox environment.
    """
    load_paybond_env_file(".env.local")
    api_key = os.environ.get("PAYBOND_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("PAYBOND_API_KEY is required; run paybond login")
    return await Paybond.open(
        api_key=api_key,
        gateway_base_url=(
            os.environ.get("PAYBOND_GATEWAY_URL")
            or os.environ.get("PAYBOND_GATEWAY_BASE_URL")
            or "https://api.paybond.ai"
        ),
        expected_environment="sandbox",
    )
