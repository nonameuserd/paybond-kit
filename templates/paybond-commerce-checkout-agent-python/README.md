# paybond-commerce-checkout-agent-python

Multi-provider shopping agent using `paybond_kit.commerce` — one `commerce.checkout` tool routes across Shopify, Stripe, and Zinc (sandbox) adapters while Paybond stays the authorize → prove → release → receipt layer.

## Quickstart (60 seconds)

```bash
paybond init --template commerce-checkout-agent --language python
# From the Python Kit CLI, language defaults to python for this template:
#   paybond init --template commerce-checkout-agent
cd <your-project-dir>   # or scaffold into the current directory with --force
cp .env.example .env.local
paybond login

# Preferred (modern packaging):
uv sync
# Or: pip install -e .

# Sandbox smoke (CLI ships with paybond-kit — pure Python path, no Node):
paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation commerce.checkout --requested-spend-cents 4500 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":4500,"provider":"zinc","order_id":"zinc_sandbox_ord_amazon_B00SMOKE"}' --format json
```

Or clone the published template:

```bash
git clone https://github.com/nonameuserd/paybond-commerce-checkout-agent-python.git
cd paybond-commerce-checkout-agent-python
cp .env.example .env.local
paybond-kit-login
uv sync   # or: pip install -e .
python app.py
# equivalent: commerce-checkout-demo  (console script from pyproject.toml)
```

## Install

This is a normal installable Python project (`pyproject.toml`):

```bash
uv sync
# or
pip install -e .
```

`paybond-kit` provides the `paybond` / `paybond-kit-login` CLI used for login and sandbox smoke.

## Run the demo

```bash
python app.py
# or after install:
commerce-checkout-demo
# with uv:
uv run python app.py
```

The demo instruments `commerce.checkout` with Shopify + Stripe mock executors and Zinc sandbox (no live merchant network). Session `tenant_id` / `intent_id` are set from the sandbox bind — never from tool args.

## Sandbox smoke

The smoke uses the language-agnostic Paybond CLI (installed with `paybond-kit`):

```bash
paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation commerce.checkout --requested-spend-cents 4500 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":4500,"provider":"zinc","order_id":"zinc_sandbox_ord_amazon_B00SMOKE"}' --format json
```

No `package.json` / Node is required for the Python template.

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **shopping** (`commerce.checkout` and `cost_and_completion`).

## Docs

- [Multi-provider commerce checkout](https://paybond.ai/docs/kit/commerce-checkout)
- [Guide: multi-provider checkout](https://paybond.ai/guides/multi-provider-commerce-checkout)
- [Shopify-only helper](https://paybond.ai/guides/protect-shopify-payments-from-agents) — prefer when you only ever check out on Shopify
