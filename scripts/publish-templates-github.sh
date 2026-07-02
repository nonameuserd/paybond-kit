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
repos=$(node -e "
const m = require('$manifest');
for (const t of m.templates) {
  const desc = t.title.replace(/\"/g, '\\\\\"');
  console.log(t.repo + '|' + desc);
}
")

while IFS='|' read -r repo description; do
  dir="$TEMPLATES/$repo"
  if [[ ! -d "$dir" ]]; then
    echo "skip missing directory: $repo" >&2
    continue
  fi

  echo "==> publishing $OWNER/$repo"
  cp "$LICENSE_SRC" "$dir/LICENSE"

  pushd "$dir" >/dev/null
  rm -rf .git
  git init -b main
  git add -A
  git commit -m "$(cat <<EOF
Initial Paybond starter template.

${description}. Clone, paybond login, and npm run smoke in under a minute.
EOF
)"

  if gh repo view "$OWNER/$repo" >/dev/null 2>&1; then
    echo "    repo exists — pushing updates to main"
    git remote add origin "git@github.com:$OWNER/$repo.git" 2>/dev/null || git remote set-url origin "git@github.com:$OWNER/$repo.git"
    git push -u origin main
  else
    gh repo create "$OWNER/$repo" \
      --public \
      --description "$description — Paybond agent spend controls starter template." \
      --source=. \
      --remote=origin \
      --push
  fi

  gh api "repos/$OWNER/$repo" -X PATCH -f is_template=true >/dev/null
  gh repo edit "$OWNER/$repo" \
    --add-topic paybond \
    --add-topic agents \
    --add-topic agent-spend-controls 2>/dev/null || true

  popd >/dev/null
  echo "    https://github.com/$OWNER/$repo"
done <<< "$repos"

echo "Done. Published template repositories under https://github.com/$OWNER"
