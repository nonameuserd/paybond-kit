#!/usr/bin/env bash
# Publish starter templates to github.com/nonameuserd as public template repositories.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TEMPLATES="$ROOT/templates"
LICENSE_SRC="$ROOT/kit/ts/LICENSE"
OWNER="nonameuserd"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

manifest="$ROOT/kit/ts/templates/manifest.json"

echo "==> verifying @paybond/kit package-lock integrity against npm"
node "$ROOT/kit/ts/scripts/verify-template-lock-integrity.mjs" \
  --templates-dir="$TEMPLATES"

repos=$(node -e "
const m = require('$manifest');
for (const t of m.templates) {
  const desc = t.title.replace(/\"/g, '\\\\\"');
  console.log(t.repo + '|' + desc);
}
")

publish_existing_repo() {
  local repo="$1"
  local description="$2"
  local dir="$3"
  local workdir
  workdir="$(mktemp -d)"

  echo "    repo exists — syncing onto main"
  git clone --depth 1 "git@github.com:$OWNER/$repo.git" "$workdir"
  rsync -a --delete --exclude .git "$dir/" "$workdir/"
  pushd "$workdir" >/dev/null
  git add -A
  if git diff --staged --quiet; then
    echo "    no changes to publish"
  else
    git commit -m "$(cat <<EOF
Sync Paybond starter template.

${description}. Node 22 CI with package-lock.json and npm ci smoke workflow.
EOF
)"
    git push origin main
  fi
  popd >/dev/null
  rm -rf "$workdir"
}

publish_new_repo() {
  local repo="$1"
  local description="$2"
  local dir="$3"
  local workdir
  workdir="$(mktemp -d)"

  rsync -a --exclude .git "$dir/" "$workdir/"
  pushd "$workdir" >/dev/null
  git init -b main
  git add -A
  git commit -m "$(cat <<EOF
Initial Paybond starter template.

${description}. Clone, paybond login, and npm run smoke in under a minute.
EOF
)"
  gh repo create "$OWNER/$repo" \
    --public \
    --description "$description — Paybond agent spend controls starter template." \
    --source=. \
    --remote=origin \
    --push
  popd >/dev/null
  rm -rf "$workdir"
}

while IFS='|' read -r repo description; do
  dir="$TEMPLATES/$repo"
  if [[ ! -d "$dir" ]]; then
    echo "skip missing directory: $repo" >&2
    continue
  fi

  echo "==> publishing $OWNER/$repo"
  cp "$LICENSE_SRC" "$dir/LICENSE"
  rm -rf "$dir/.git"

  if gh repo view "$OWNER/$repo" >/dev/null 2>&1; then
    publish_existing_repo "$repo" "$description" "$dir"
  else
    publish_new_repo "$repo" "$description" "$dir"
  fi

  gh api "repos/$OWNER/$repo" -X PATCH -f is_template=true >/dev/null
  gh repo edit "$OWNER/$repo" \
    --add-topic paybond \
    --add-topic agents \
    --add-topic agent-spend-controls 2>/dev/null || true

  echo "    https://github.com/$OWNER/$repo"
done <<< "$repos"

echo "Done. Published template repositories under https://github.com/$OWNER"
