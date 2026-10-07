#!/usr/bin/env bash
# Create (or delete) the throwaway local k3d cluster used by the end-to-end tests.
#
# Safety: the cluster's kubeconfig is written to ./.e2e/kubeconfig and NEVER merged
# into ~/.kube/config, and the current context is never switched. Everything the
# e2e suite does goes through that isolated file, so the operator's default
# context cannot be touched by accident.
set -euo pipefail

CLUSTER="${PODPEERS_E2E_CLUSTER:-podpeers-e2e}"
API_PORT="${PODPEERS_E2E_API_PORT:-6551}"
K3S_IMAGE="${PODPEERS_E2E_K3S_IMAGE:-rancher/k3s:v1.31.5-k3s1}"
DEBUG_IMAGE="${PODPEERS_E2E_DEBUG_IMAGE:-busybox:1.36}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KCFG="$ROOT/.e2e/kubeconfig"

up() {
  mkdir -p "$ROOT/.e2e"
  if ! k3d cluster list -o json | grep -q "\"name\":\"$CLUSTER\""; then
    k3d cluster create "$CLUSTER" \
      --image "$K3S_IMAGE" \
      --servers 1 --agents 0 --no-lb \
      --api-port "127.0.0.1:$API_PORT" \
      --k3s-arg '--disable=traefik@server:0' \
      --k3s-arg '--disable=servicelb@server:0' \
      --k3s-arg '--disable=metrics-server@server:0' \
      --kubeconfig-update-default=false \
      --kubeconfig-switch-context=false \
      --wait
  fi
  k3d kubeconfig get "$CLUSTER" > "$KCFG"
  chmod 600 "$KCFG"
  # Make the workload and debug images available without the node pulling them.
  # (k3d image import trips over multi-arch digests on some docker setups; pull in-node instead)
  docker exec "k3d-$CLUSTER-server-0" crictl pull "docker.io/library/$DEBUG_IMAGE" >/dev/null
  local ctx
  ctx="$(kubectl --kubeconfig "$KCFG" config current-context)"
  if [[ "$ctx" != "k3d-$CLUSTER" ]]; then
    echo "refusing: isolated kubeconfig has unexpected context '$ctx'" >&2
    exit 1
  fi
  kubectl --kubeconfig "$KCFG" wait --for=condition=Ready node --all --timeout=120s
  echo "cluster ready; KUBECONFIG=$KCFG context=$ctx"
}

down() {
  k3d cluster delete "$CLUSTER"
  rm -f "$KCFG"
}

case "${1:-up}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 [up|down]" >&2; exit 2 ;;
esac
