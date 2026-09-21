# paybond-aws-operator

AWS operator agent (generic TypeScript). Clone, log in to Paybond sandbox, and run smoke in under a minute.

## Quickstart (60 seconds)

```bash
git clone https://github.com/nonameuserd/paybond-aws-operator.git
cd paybond-aws-operator
cp .env.example .env.local
paybond login
npm install
npm run smoke
```

## Run the demo

```bash
npm start
```

## Policy

Local `paybond.policy.yaml` is yours to edit. Bundled preset: **aws**.

## Docs

- [Agent quickstart](https://paybond.ai/docs/kit/quickstart-agent)
- [Agent middleware](https://paybond.ai/docs/kit/agent-middleware)
