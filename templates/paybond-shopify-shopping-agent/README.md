# Paybond Shopify shopping agent

Guard-first Shopify checkout demo using `instrumentShopifyCheckout` from `@paybond/kit`.

## Quick start

```bash
paybond login
npm install
npm run build
npm start
```

## Smoke (no Shopify credentials)

```bash
npm run smoke
```

## UCP profile

Register Paybond's agent profile in the Shopify Developer Dashboard:

`https://paybond.ai/.well-known/ucp/profile.json`

## Binding contract

`instrumentShopifyCheckout` injects `paybond_intent_id` and `tenant_id` into `note_attributes` on every checkout call. Tenant scope comes from the Paybond session after bind — never from client input.
