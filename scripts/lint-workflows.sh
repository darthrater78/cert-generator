#!/usr/bin/env bash
# Lints .github/workflows/** with actionlint.
#
# Uses an actionlint already on PATH if one is installed (e.g. via brew/scoop
# for local development on macOS/Windows). Otherwise downloads the pinned
# Linux amd64 release and verifies its checksum before running it -- the same
# thing .github/workflows/lint-workflows.yml calls in CI, so there's one
# source of truth for the version and the checksum.
#
# Usage: scripts/lint-workflows.sh
set -euo pipefail

# Bumped by hand; checksum copied from the release's own *_checksums.txt, not
# computed after the fact, so a tampered or substituted binary is refused
# rather than silently trusted.
ACTIONLINT_VERSION=1.7.12
ACTIONLINT_SHA256=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8

cd "$(dirname "$0")/.."

if command -v actionlint >/dev/null 2>&1; then
  exec actionlint -color
fi

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "No actionlint on PATH, and the pinned download here is Linux amd64 only." >&2
  echo "Install actionlint yourself: https://github.com/rhysd/actionlint#quick-start" >&2
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

curl -fsSL -o "$workdir/actionlint.tar.gz" \
  "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"
echo "${ACTIONLINT_SHA256}  $workdir/actionlint.tar.gz" | sha256sum -c -
tar xzf "$workdir/actionlint.tar.gz" -C "$workdir" actionlint

"$workdir/actionlint" -color
