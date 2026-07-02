# paybond-mcp-coding-agent

MCP coding agent (read-only + one paid tool). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-mcp-coding-agent.git
cd paybond-mcp-coding-agent
cp .env.example .env.local
paybond login
npm install
npm run smoke   # or: paybond agent sandbox smoke --policy-file paybond.policy.yaml --operation deploy.preview --requested-spend-cents 500 --evidence-preset cost_and_completion --result-body '{"status":"completed","cost_cents":500}' --format json
```

## Run the demo

```bash
npm start
```

## MCP host wiring

```bash
paybond login
paybond mcp install --host claude --tool-policy spend-write
paybond mcp verify-config --host claude
```

Read-only tools pass through; side-effecting tools require Harbor authorization.

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **custom**.

## Docs

- [Agent quickstart](https://docs.paybond.ai/kit/quickstart-agent)
- [Agent middleware](https://docs.paybond.ai/kit/agent-middleware)
