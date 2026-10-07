#!/usr/bin/env bash
# Render every ```mermaid block in the repo's tracked Markdown with the official
# mermaid CLI, the same library GitHub uses to draw them. A diagram that does
# not parse fails the check, instead of showing readers a red "Unable to
# render rich display" box on github.com.
#
#   hack/check-docs.sh                 check
#   RENDER_OUT=dir hack/check-docs.sh  also keep PNGs to look at
#
# Locally, point PUPPETEER_EXECUTABLE_PATH at an installed Chrome to skip the
# browser download.
set -euo pipefail
cd "$(dirname "$0")/.."
MMDC_VERSION="${MMDC_VERSION:-11.4.2}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cat >"$work/puppeteer.json" <<JSON
{"args": ["--no-sandbox", "--disable-setuid-sandbox"]$( [ -n "${PUPPETEER_EXECUTABLE_PATH:-}" ] && printf ', "executablePath": "%s"' "$PUPPETEER_EXECUTABLE_PATH")}
JSON

n=0
for md in $(git ls-files '*.md'); do
  # Split the file's mermaid blocks into numbered .mmd files.
  awk -v out="$work/$(echo "$md" | tr '/' '_')" '
    /^```mermaid[[:space:]]*$/ { inblk=1; i++; f=out "." i ".mmd"; next }
    inblk && /^```[[:space:]]*$/ { inblk=0; close(f); next }
    inblk { print > f }
  ' "$md"
done

fail=0
for f in "$work"/*.mmd; do
  [ -e "$f" ] || continue
  n=$((n+1))
  name="$(basename "$f" .mmd)"
  out="$work/$name.png"
  if npx -y "@mermaid-js/mermaid-cli@$MMDC_VERSION" -q -p "$work/puppeteer.json" \
       -i "$f" -o "$out" -b white -w 1200 >"$work/$name.log" 2>&1; then
    echo "ok    $name"
    if [ -n "${RENDER_OUT:-}" ]; then mkdir -p "$RENDER_OUT"; cp "$out" "$RENDER_OUT/"; fi
  else
    echo "FAIL  $name"; sed 's/^/      /' "$work/$name.log" | head -20; fail=1
  fi
done
echo "mermaid diagrams checked: $n"
exit "$fail"
