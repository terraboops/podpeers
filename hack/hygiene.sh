#!/usr/bin/env bash
# Public-repo hygiene gate: tracked files must not contain IP addresses outside
# the documentation/loopback ranges, kubeconfig credentials, or private keys.
# Real environments must never leak into this repo.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
files=$(git ls-files | grep -vE '^(go\.sum|LICENSE)$')

ips=$(echo "$files" | xargs grep -nHoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null \
  | grep -vE ':(192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+|127\.[0-9.]+|0\.0\.0\.0)$' || true)
if [ -n "$ips" ]; then echo "non-documentation IPv4 addresses:"; echo "$ips"; fail=1; fi

secrets=$(echo "$files" | xargs grep -nHE '(client-key-data|client-certificate-data|certificate-authority-data|BEGIN [A-Z ]*PRIVATE KEY|token: [A-Za-z0-9_.-]{20,})' 2>/dev/null \
  | grep -v '^hack/hygiene.sh:' || true)
if [ -n "$secrets" ]; then echo "credential-looking content:"; echo "$secrets"; fail=1; fi

[ "$fail" = 0 ] && echo "hygiene: ok"
exit "$fail"
