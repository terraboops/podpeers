#!/usr/bin/env bash
# Public-repo hygiene gate: tracked files must not contain IP addresses outside
# the documentation/loopback ranges, kubeconfig credentials, or private keys.
# Real environments must never leak into this repo.
#
#   hack/hygiene.sh             the current tree
#   hack/hygiene.sh --history   every version of every file ever committed,
#                               images included: deleting a leak from the tree
#                               does not delete it from a public history
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
if [ "${1:-}" = --history ]; then
  # Blobs already public that a history rewrite would be needed to remove.
  # Rewriting public history is the operator's decision, so each is listed
  # with what it is, and nothing else is let through.
  known="$(grep -oE '^[0-9a-f]{40}' hack/hygiene-history-known.txt 2>/dev/null || true)"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  git rev-list --all --objects | while read -r sha path; do
    [ -n "$path" ] && [ "$(git cat-file -t "$sha")" = blob ] || continue
    case "$path" in go.sum|LICENSE|hack/hygiene.sh) continue ;; esac
    echo "$known" | grep -qx "$sha" && continue
    git cat-file -p "$sha" >"$work/blob"
    case "$path" in
      *.gif|*.png|*.jpg|*.jpeg)
        ext="${path##*.}"; mv "$work/blob" "$work/img.$ext"
        "$0" "$work/img.$ext" </dev/null >"$work/out" 2>&1 || { echo "$path (blob $sha):"; cat "$work/out"; echo x >>"$work/failed"; } ;;
      *)
        if grep -qI . "$work/blob" 2>/dev/null; then
          hit=$( { grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "$work/blob" \
              | grep -vE '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.|0\.0\.0\.0$)' ;
            grep -oE '(client-key-data|client-certificate-data|certificate-authority-data|BEGIN [A-Z ]*PRIVATE KEY|token: [A-Za-z0-9_.-]{20,})' "$work/blob" ; } | sort -u || true)
          if [ -n "$hit" ]; then echo "$path (blob $sha): $hit"; echo x >>"$work/failed"; fi
        fi ;;
    esac
  done
  if git log --all --format=%B | grep -E '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
      | grep -vE '^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.|0\.0\.0\.0$)'; then
    echo "non-documentation IPv4 in a commit message"; echo x >>"$work/failed"
  fi
  [ -e "$work/failed" ] && exit 1
  echo "hygiene: history ok ($(git rev-list --all --objects | wc -l | tr -d ' ') objects; $(echo "$known" | grep -c . || true) known blob(s) listed in hack/hygiene-history-known.txt)"
  exit 0
fi
files=$(git ls-files | grep -vE '^(go\.sum|LICENSE)$')

ips=$(echo "$files" | xargs grep -nHoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' 2>/dev/null \
  | grep -vE ':(192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+|127\.[0-9.]+|0\.0\.0\.0)$' || true)
if [ -n "$ips" ]; then echo "non-documentation IPv4 addresses:"; echo "$ips"; fail=1; fi

secrets=$(echo "$files" | xargs grep -nHE '(client-key-data|client-certificate-data|certificate-authority-data|BEGIN [A-Z ]*PRIVATE KEY|token: [A-Za-z0-9_.-]{20,})' 2>/dev/null \
  | grep -v '^hack/hygiene.sh:' || true)
if [ -n "$secrets" ]; then echo "credential-looking content:"; echo "$secrets"; fail=1; fi

# Images: text inside a GIF or PNG is invisible to grep, so OCR every frame
# (2 per second) and apply the same IP rule. A demo recording once showed a
# local cluster's pod IP this way. CI installs tesseract and ffmpeg; locally
# the check is skipped with a warning if they are missing, or forced with
# HYGIENE_IMAGES=1. Extra image files can be passed as arguments.
images="$(echo "$files" | grep -iE '\.(gif|png|jpe?g)$' || true)"
[ $# -gt 0 ] && images="$*"
if [ -n "$images" ]; then
  if command -v tesseract >/dev/null && command -v ffmpeg >/dev/null; then
    ocr="$(mktemp -d)"
    for img in $images; do
      rm -f "$ocr"/*.png
      ffmpeg -v error -i "$img" -vf "fps=2,scale=iw*2:-1" "$ocr/f%04d.png" 2>/dev/null \
        || ffmpeg -v error -i "$img" -vf "scale=iw*2:-1" "$ocr/f0001.png"
      hits=$(for f in "$ocr"/*.png; do tesseract "$f" - 2>/dev/null; done \
        | grep -oE '\b[0-9]{1,3}[.,][0-9]{1,3}[.,][0-9]{1,3}[.,][0-9]{1,3}\b' \
        | grep -vE '^(192[.,]0[.,]2[.,]|198[.,]51[.,]100[.,]|203[.,]0[.,]113[.,]|127[.,]|0[.,]0[.,]0[.,]0)' | sort -u || true)
      if [ -n "$hits" ]; then echo "non-documentation IPv4 rendered in $img:"; echo "$hits"; fail=1; fi
    done
    rm -rf "$ocr"
    echo "hygiene: OCR-checked $(echo "$images" | wc -w | tr -d ' ') image(s)"
  elif [ "${HYGIENE_IMAGES:-}" = 1 ]; then
    echo "HYGIENE_IMAGES=1 but tesseract/ffmpeg are not installed"; fail=1
  else
    echo "hygiene: WARNING: tesseract/ffmpeg not installed; images were NOT checked"
  fi
fi

[ "$fail" = 0 ] && echo "hygiene: ok"
exit "$fail"
