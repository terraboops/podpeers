#!/usr/bin/env bash
# Prove the tests have teeth. Each hack/mutants/*.patch breaks the protection
# behind one negative case (brief section 5) or the safety guard. For each one
# this applies the patch to a scratch git worktree of the current tree and runs
# the tests that should catch it. A mutant is KILLED only if those tests FAIL
# and their output matches the patch's expect pattern, i.e. they fail for the
# right reason. A mutant that survives, or is killed for an unexpected reason,
# fails this script.
#
#   hack/mutants.sh            unit tests only (fast; runs in CI)
#   hack/mutants.sh --e2e      also the real-cluster e2e tests (needs make e2e-cluster)
#   hack/mutants.sh --e2e 03   only mutants whose name contains "03"
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
E2E=0
if [ "${1:-}" = "--e2e" ]; then E2E=1; shift; fi
FILTER="${1:-}"
LOGS="$ROOT/.e2e/mutants"
mkdir -p "$LOGS"

if [ "$E2E" = 1 ]; then
  ctx="$(kubectl --kubeconfig "$ROOT/.e2e/kubeconfig" config current-context 2>/dev/null || true)"
  if [ "$ctx" != "k3d-podpeers-e2e" ]; then
    echo "refusing: .e2e/kubeconfig is not the local e2e cluster (run make e2e-cluster)" >&2
    exit 1
  fi
fi

# Snapshot the working tree as git would commit it (uncommitted edits and new
# files included, .gitignore honoured) via a throwaway index.
idx="$(mktemp)"
cp "$(git rev-parse --git-path index)" "$idx"
GIT_INDEX_FILE="$idx" git add -A
SNAP="$(git commit-tree "$(GIT_INDEX_FILE="$idx" git write-tree)" -p HEAD -m "mutants snapshot")"
rm -f "$idx"

field() { sed -n "s/^# $1: //p" "$2"; }

# e2e_tops prints the top-level e2e test each selected mutant relies on.
e2e_tops() {
  local p
  for p in hack/mutants/*.patch; do
    if [[ "$(basename "$p")" == *"$FILTER"* ]]; then field e2e-run "$p" | cut -d/ -f1; fi
  done
}

newtree() {
  local wt
  wt="$(mktemp -d)/wt"
  git worktree add -q --detach "$wt" "$SNAP"
  echo "$wt"
}

# check NAME KIND DIR EXPECT CMD...: run CMD in DIR, classify the result.
check() {
  local name="$1" kind="$2" dir="$3" expect="$4"; shift 4
  local log="$LOGS/$name-$kind.log"
  (cd "$dir" && "$@") >"$log" 2>&1
  local code=$?
  if [ "$code" = 0 ]; then
    echo "SURVIVED"
  elif grep -Eq -- "$expect" "$log"; then
    echo "killed"
  else
    echo "UNEXPECTED"
  fi
}

fail=0
rows=""

echo "baseline: the selected tests must pass on the unmutated tree"
base="$(newtree)"
if ! (cd "$base" && go test -count=1 ./internal/... ./cmd/... ./test/skillscript/) >"$LOGS/baseline-unit.log" 2>&1; then
  echo "baseline unit tests FAIL; a mutant failing them would prove nothing (see $LOGS/baseline-unit.log)" >&2
  git worktree remove --force "$base"; exit 1
fi
if [ "$E2E" = 1 ]; then
  # The top-level e2e tests the selected mutants rely on must pass unmutated.
  tops="$(e2e_tops | sort -u | paste -sd'|' -)"
  if ! (cd "$base" && PODPEERS_E2E_KUBECONFIG="$ROOT/.e2e/kubeconfig" PODPEERS_E2E_OUT="$base/.e2e-out" \
        go test -tags e2e -count=1 -v -timeout 20m -run "^($tops)\$" ./test/e2e/) >"$LOGS/baseline-e2e.log" 2>&1; then
    echo "baseline e2e FAILS; see $LOGS/baseline-e2e.log" >&2
    git worktree remove --force "$base"; exit 1
  fi
fi
git worktree remove --force "$base"
echo "baseline: pass"

for p in hack/mutants/*.patch; do
  name="$(basename "$p" .patch)"
  case "$name" in *"$FILTER"*) ;; *) continue ;; esac
  wt="$(newtree)"
  if ! git -C "$wt" apply "$ROOT/$p"; then
    echo "$name: patch no longer applies; update it to the current code" >&2
    git worktree remove --force "$wt"; fail=1; continue
  fi
  if ! (cd "$wt" && go build ./... && go vet -tags e2e ./test/e2e/) >"$LOGS/$name-build.log" 2>&1; then
    echo "$name: mutant does not compile; see $LOGS/$name-build.log" >&2
    git worktree remove --force "$wt"; fail=1; continue
  fi
  # shellcheck disable=SC2046
  u="$(check "$name" unit "$wt" "$(field unit-expect "$p")" go test -count=1 -run "$(field unit-run "$p")" $(field unit-pkg "$p"))"
  e="skipped"
  if [ "$E2E" = 1 ]; then
    e="$(check "$name" e2e "$wt" "$(field e2e-expect "$p")" env PODPEERS_E2E_KUBECONFIG="$ROOT/.e2e/kubeconfig" \
          PODPEERS_E2E_OUT="$wt/.e2e-out" go test -tags e2e -count=1 -v -timeout 15m -run "$(field e2e-run "$p")" ./test/e2e/)"
  fi
  git worktree remove --force "$wt"
  for r in "$u" "$e"; do
    case "$r" in SURVIVED|UNEXPECTED) fail=1 ;; esac
  done
  rows="$rows$(printf '%-24s unit: %-10s e2e: %-10s %s' "$name" "$u" "$e" "$(sed -n 's/^# Mutant [^:]*: breaks the protection for "\(.*\)"\./\1/p' "$p")")
"
  printf '%-24s unit: %-10s e2e: %s\n' "$name" "$u" "$e"
done

echo
echo "mutant                   result per suite    protection"
printf '%s' "$rows"
echo "logs: $LOGS"
if [ "$fail" = 0 ]; then echo "all mutants killed, each for the expected reason"; fi
exit "$fail"
