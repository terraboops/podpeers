#!/usr/bin/env bash
# Drive the web UI (`podpeers serve`) in headless Chrome against a fixture
# capture with pods, services, nodes and an outside address: every peer must
# be shown in the right group, both views must work, the page must raise no
# errors, and the GraphQL console must answer exactly what `podpeers query`
# answers. Unit tests cannot see any of this: the layout runs in the browser.
#
#   hack/check-ui.sh                  check
#   RENDER_OUT=dir hack/check-ui.sh   also keep screenshots to look at
#
# Locally, set PUPPETEER_EXECUTABLE_PATH to an installed Chrome (and
# PUPPETEER_SKIP_DOWNLOAD=1) to skip the browser download.
set -euo pipefail
cd "$(dirname "$0")/.."
PUPPETEER_VERSION="${PUPPETEER_VERSION:-24.10.0}"
PORT="${UI_PORT:-18181}"
CAPTURE=hack/ui/capture.json
QUERY='{ pods(status: "observed") { id peers(direction: "inbound") { id kind } } }'
work="$(mktemp -d)"
srv=""
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$work"' EXIT

go build -o "$work/podpeers" ./cmd/podpeers
"$work/podpeers" serve -addr "127.0.0.1:$PORT" "$CAPTURE" 2>"$work/serve.log" &
srv=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/" >/dev/null && break; sleep 0.2; done
want="$("$work/podpeers" query "$CAPTURE" "$QUERY")"

cp hack/ui/check.mjs "$work/"
(cd "$work" && npm init -y >/dev/null && npm install --silent --no-audit --no-fund "puppeteer@$PUPPETEER_VERSION" >/dev/null)
shots=""
if [ -n "${RENDER_OUT:-}" ]; then mkdir -p "$RENDER_OUT"; shots="$(cd "$RENDER_OUT" && pwd)"; fi
(cd "$work" && node check.mjs "http://127.0.0.1:$PORT/" "$QUERY" "$want" $shots)
