#!/usr/bin/env bash
# Decide whether a CI run needs the full suite.
# Prints "code=true" unless every file changed since <base> is documentation
# (*.md, docs/**, LICENSE), in which case it prints "code=false". Anything it
# can't determine — no base (new branch, manual run), a base that isn't in the
# clone, an empty diff — prints "code=true", so the suite runs.
#
# Usage: scripts/ci-changes.sh <base-sha>   (the checkout must have history)
set -euo pipefail

base="${1:-}"

run_all() {
  echo "ci-changes: $1 — running the full suite" >&2
  echo "code=true"
  exit 0
}

if [ -z "$base" ] || [ "$base" = "0000000000000000000000000000000000000000" ]; then
  run_all "no base commit to compare against"
fi
if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  run_all "base ${base} is not in this clone"
fi

changed="$(git diff --name-only "$base" HEAD)"
if [ -z "$changed" ]; then
  run_all "no changed files between ${base} and HEAD"
fi

while IFS= read -r path; do
  case "$path" in
    *.md | docs/* | LICENSE | LICENSE.*) ;;
    *) run_all "${path} is not documentation" ;;
  esac
done <<< "$changed"

echo "ci-changes: only documentation changed — skipping the build and test jobs" >&2
echo "code=false"
