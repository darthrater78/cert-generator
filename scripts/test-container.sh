#!/usr/bin/env bash
# Smoke-test a built image: it serves the login page and stops promptly on SIGTERM.
# Usage: scripts/test-container.sh <image> [docker|podman]
set -euo pipefail

image="${1:?usage: $0 <image> [docker|podman]}"
engine="${2:-docker}"
name="cert-generator-smoke-$$"
port=15123

cleanup() { "$engine" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$engine" run -d --name "$name" -p "127.0.0.1:${port}:5000" -e SECRET_KEY=smoke "$image" >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${port}/setup" 2>/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS -o /dev/null "http://127.0.0.1:${port}/setup"
echo "serving: ok"

curl -fsS "http://127.0.0.1:${port}/static/app.js" | grep -q "UI_ACTIONS"
echo "static assets: ok"

start=$(date +%s)
"$engine" stop -t 10 "$name" >/dev/null
elapsed=$(( $(date +%s) - start ))
exit_code=$("$engine" inspect -f '{{.State.ExitCode}}' "$name")
echo "stopped in ${elapsed}s with exit code ${exit_code}"
if [ "$elapsed" -ge 5 ] || [ "$exit_code" != "0" ]; then
  echo "::error::container did not shut down cleanly on SIGTERM"
  exit 1
fi
