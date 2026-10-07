#!/usr/bin/env bash
# Records docs/demo.gif against the throwaway local e2e cluster:
#   scene 1 (vhs)      podpeers capture, podpeers serve
#   scene 2 (Firefox)  the web UI on that capture
#   scene 3 (vhs)      podpeers suggest, kubectl apply
# Needs: make e2e-cluster, vhs, ffmpeg, Firefox + geckodriver, python3 selenium.
set -euo pipefail
cd "$(dirname "$0")/../.."
KCFG=.e2e/kubeconfig
CTX=k3d-podpeers-e2e
[ "$(kubectl --kubeconfig "$KCFG" config current-context)" = "$CTX" ] || { echo "refusing: $KCFG is not the local e2e cluster" >&2; exit 1; }
k() { kubectl --kubeconfig "$KCFG" --context "$CTX" "$@"; }

make build >/dev/null
k apply -f docs/demo/app.yaml >/dev/null
k delete networkpolicy -n storefront --all >/dev/null
k delete networkpolicy -n payments --all >/dev/null
k rollout status -n storefront deploy --timeout 3m >/dev/null
k rollout status -n payments deploy --timeout 3m >/dev/null
sleep 5
rm -rf .e2e/demo && mkdir -p .e2e/demo/browser

vhs docs/demo/capture.tape >/dev/null
./bin/podpeers serve -addr 127.0.0.1:8080 .e2e/demo/peers.json 2>/dev/null &
SERVE=$!
trap 'kill $SERVE 2>/dev/null || true' EXIT
sleep 1
python3 docs/demo/browser.py http://127.0.0.1:8080/ .e2e/demo/browser
kill $SERVE
vhs docs/demo/suggest.tape >/dev/null
# Leave the demo cluster as it was.
k delete -f .e2e/demo/policies.yaml --ignore-not-found >/dev/null

ffmpeg -v error -y -framerate 10 -i .e2e/demo/browser/frame-%05d.png -pix_fmt yuv420p -vf "scale=1280:820" .e2e/demo/browser.mp4
ffmpeg -v error -y -i .e2e/demo/capture.mp4 -i .e2e/demo/browser.mp4 -i .e2e/demo/suggest.mp4 \
  -filter_complex "[0:v]fps=10,scale=1280:820,setsar=1[a];[1:v]fps=10,scale=1280:820,setsar=1[b];[2:v]fps=10,scale=1280:820,setsar=1[c];[a][b][c]concat=n=3:v=1:a=0,scale=1100:-1:flags=lanczos,split[x][y];[x]palettegen=max_colors=128[p];[y][p]paletteuse=dither=bayer:bayer_scale=4" \
  docs/demo.gif
echo "docs/demo.gif: $(du -h docs/demo.gif | cut -f1), $(ffprobe -v error -show_entries format=duration -of csv=p=0 docs/demo.gif)s"
