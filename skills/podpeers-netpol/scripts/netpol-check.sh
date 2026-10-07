#!/usr/bin/env bash
# netpol-check.sh - the mechanical half of the podpeers-netpol skill.
#
#   baseline  capture a Helm release's traffic while `helm test` runs, then
#             write NetworkPolicy suggestions for it
#   verify    apply a policy, restart the release's workloads so every
#             connection is made under it, re-run `helm test` under a second
#             capture, and diff against the baseline: OK, BROKEN (why), or
#             INCONCLUSIVE
#   rollback  delete the policy again
#
# Every cluster call names --context explicitly, and the script stops before
# touching anything unless `podpeers check-context` accepts that context
# (local kind/k3d clusters only, unless --allow-context names it).
#
# Exit codes: 0 OK, 1 usage/runtime error, 2 context refused,
#             4 BROKEN (traffic blocked or lost), 5 BROKEN (helm test failed),
#             6 baseline unusable (helm test already failing without a policy),
#             7 INCONCLUSIVE (flows only seen on connections older than the policy).
set -euo pipefail

PODPEERS="${PODPEERS:-podpeers}"
RELEASE="" NS="" CONTEXT="" KCFG="${KUBECONFIG:-}" SELECTOR="" ALLOW=""
DURATION="40s" INTERVAL="1s" OUT="./podpeers-netpol" POLICY="" BASELINE=""
SETTLE=8 WARMUP=8 ROLLBACK_ON_FAIL=0 RESTART=1 APPLY=1 OUT_SET=0

die() { echo "netpol-check: $*" >&2; exit 1; }
say() { echo "netpol-check: $*" >&2; }

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'EOF'

Usage:
  netpol-check.sh baseline --release R --namespace NS --context CTX [options]
  netpol-check.sh verify   --release R --namespace NS --context CTX --policy policy.yaml --baseline baseline.json [options]
  netpol-check.sh verify   --release R --namespace NS --context CTX --no-apply --baseline baseline.json [options]
  netpol-check.sh rollback --namespace NS --context CTX --policy policy.yaml [options]

Options:
  --kubeconfig PATH       kubeconfig (default: $KUBECONFIG)
  --selector SEL          pods to observe (default: app.kubernetes.io/instance=<release>)
  --duration D            capture window (default 40s; use much longer for real workloads)
  --interval I            sample interval (default 1s)
  --out DIR               where captures, policy and verdict go (default ./podpeers-netpol;
                          for verify, the --baseline file's directory)
  --settle SECONDS        wait after applying a policy before verifying (default 8)
  --allow-context NAME    pass through to podpeers for a deliberately approved non-local cluster
  --rollback-on-fail      delete the policy again if verify says BROKEN
  --no-apply              verify the policy that is ALREADY in the cluster (e.g. shipped by the
                          chart) instead of applying --policy; --policy is then not needed
  --no-restart            do not restart the release's workloads after applying the policy
                          (established connections are not re-checked by CNIs, so verify
                          may then only be able to say INCONCLUSIVE)
EOF
}

[ $# -ge 1 ] || { usage; exit 1; }
CMD="$1"; shift
while [ $# -gt 0 ]; do
  case "$1" in
    --release) RELEASE="$2"; shift 2 ;;
    --namespace|-n) NS="$2"; shift 2 ;;
    --context) CONTEXT="$2"; shift 2 ;;
    --kubeconfig) KCFG="$2"; shift 2 ;;
    --selector|-l) SELECTOR="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --out) OUT="$2"; OUT_SET=1; shift 2 ;;
    --policy) POLICY="$2"; shift 2 ;;
    --baseline) BASELINE="$2"; shift 2 ;;
    --settle) SETTLE="$2"; shift 2 ;;
    --allow-context) ALLOW="$2"; shift 2 ;;
    --rollback-on-fail) ROLLBACK_ON_FAIL=1; shift ;;
    --no-restart) RESTART=0; shift ;;
    --no-apply) APPLY=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$CONTEXT" ] || die "--context is required: this script never relies on the current context"
[ -n "$NS" ] || die "--namespace is required"
[ -n "$SELECTOR" ] || SELECTOR="app.kubernetes.io/instance=${RELEASE}"

# Common arguments, built so empty values are simply omitted (bash 3 safe).
K=(--context "$CONTEXT"); H=(--kube-context "$CONTEXT"); P=(--context "$CONTEXT")
if [ -n "$KCFG" ]; then K+=(--kubeconfig "$KCFG"); H+=(--kubeconfig "$KCFG"); P+=(--kubeconfig "$KCFG"); fi
if [ -n "$ALLOW" ]; then P+=(--allow-context "$ALLOW"); fi

kc() { kubectl "${K[@]}" "$@"; }
# Helm 4 rejects some global flags before the subcommand, so put them after it.
hl() { local sub="$1"; shift; helm "$sub" "${H[@]}" "$@"; }

guard() {
  if ! "$PODPEERS" check-context "${P[@]}" >/dev/null; then
    say "podpeers refused context '$CONTEXT'; nothing was touched."
    exit 2
  fi
}

# Refuse first: before any other check, file read or cluster call, for every
# subcommand.
guard

# capture_with_test OUTFILE TESTLOG: capture the release while `helm test`
# runs inside the window. Sets TEST_OK=1/0 and CAPTURE_CODE.
capture_with_test() {
  local out="$1" log="$2" pid
  "$PODPEERS" capture "${P[@]}" -n "$NS" -l "$SELECTOR" \
    --duration "$DURATION" --interval "$INTERVAL" -o "$out" --summary none 2>"$out.log" &
  pid=$!
  sleep "$WARMUP"   # let the samplers start, so the test's connections are seen
  # --logs keeps the test pods' output, so retries show up even when it passes.
  if hl test "$RELEASE" -n "$NS" --timeout 2m --logs >"$log" 2>&1; then TEST_OK=1; else TEST_OK=0; fi
  CAPTURE_CODE=0
  wait "$pid" || CAPTURE_CODE=$?
  case "$CAPTURE_CODE" in
    0) ;;
    3) say "capture is partial (some pods could not be observed); see $out.log" ;;
    *) cat "$out.log" >&2; die "capture failed (exit $CAPTURE_CODE)" ;;
  esac
}

case "$CMD" in
  baseline)
    [ -n "$RELEASE" ] || die "--release is required"
    mkdir -p "$OUT"
    say "baseline: capturing $SELECTOR in $NS for $DURATION while 'helm test $RELEASE' runs"
    capture_with_test "$OUT/baseline.json" "$OUT/baseline-helm-test.log"
    if [ "$TEST_OK" != 1 ]; then
      cat "$OUT/baseline-helm-test.log" >&2
      say "helm test FAILS without any new policy; a later failure would prove nothing. Fix the release first."
      exit 6
    fi
    "$PODPEERS" suggest -n "$NS" -o "$OUT/policy.yaml" "$OUT/baseline.json"
    "$PODPEERS" suggest -n "$NS" -format json -o "$OUT/policy.json" "$OUT/baseline.json" 2>/dev/null
    "$PODPEERS" render -format text "$OUT/baseline.json" >"$OUT/baseline.txt"
    say "baseline OK: helm test passed while observed"
    say "  capture:     $OUT/baseline.json  (report: $OUT/baseline.txt)"
    say "  suggestions: $OUT/policy.yaml    (reasoning + NOT COVERED as comments; $OUT/policy.json)"
    ;;

  verify)
    [ -n "$RELEASE" ] || die "--release is required"
    [ -f "$BASELINE" ] || die "--baseline file not found: $BASELINE"
    [ "$OUT_SET" = 1 ] || OUT="$(dirname "$BASELINE")"
    mkdir -p "$OUT"
    if [ "$APPLY" = 1 ]; then
      [ -f "$POLICY" ] || die "--policy file not found: $POLICY (or use --no-apply to verify the policy already in the cluster)"
      say "verify: server-side dry run of $POLICY"
      kc apply -n "$NS" --dry-run=server -f "$POLICY" >/dev/null
      kc apply -n "$NS" -f "$POLICY"
      say "waiting ${SETTLE}s for the CNI to program the policy"
      sleep "$SETTLE"
    else
      [ "$ROLLBACK_ON_FAIL" = 0 ] || die "--rollback-on-fail needs --policy: with --no-apply there is nothing this script applied to roll back"
      say "verify: --no-apply, checking the NetworkPolicies already in $NS:"
      kc get networkpolicy -n "$NS" -o name >&2
    fi
    # The policy is in force from here: any pod not on this list can only
    # have connected under it. (Pod identity, not timestamps: immune to clock
    # skew between this machine and the cluster.)
    { kc get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}' 2>/dev/null \
      || kc get pods -n "$NS" -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'; } >"$OUT/pods-at-change.txt"
    if [ "$RESTART" = 1 ]; then
      # CNIs only evaluate a policy when a connection is opened; connections
      # established before it keep working. Restart so every client reconnects
      # under the policy, which also exercises start-up connections.
      say "restarting workloads matching $SELECTOR so every connection is made under the policy"
      for kind in deployment statefulset daemonset; do
        for obj in $(kc get "$kind" -n "$NS" -l "$SELECTOR" -o name); do
          kc rollout restart -n "$NS" "$obj" >/dev/null
          kc rollout status -n "$NS" "$obj" --timeout 5m >/dev/null
        done
      done
    fi
    capture_with_test "$OUT/after.json" "$OUT/after-helm-test.log"
    DIFF_CODE=0
    "$PODPEERS" diff -existing-pods "$OUT/pods-at-change.txt" "$BASELINE" "$OUT/after.json" >"$OUT/diff.txt" || DIFF_CODE=$?
    case "$DIFF_CODE" in 0|4|5) ;; *) die "diff failed (exit $DIFF_CODE)" ;; esac

    VERDICT="OK" CODE=0
    if [ "$TEST_OK" != 1 ]; then
      VERDICT="BROKEN: helm test failed with the policy in place" CODE=5
    elif [ "$DIFF_CODE" = 4 ]; then
      VERDICT="BROKEN: helm test passed, but traffic the app relied on is now blocked or missing" CODE=4
    elif [ "$DIFF_CODE" = 5 ]; then
      VERDICT="INCONCLUSIVE: helm test passed, but some flows were only seen on connections opened before the policy" CODE=7
    fi
    {
      echo "verdict: $VERDICT"
      if [ "$APPLY" = 1 ]; then echo "policy:  $POLICY"; else echo "policy:  already in the cluster (--no-apply)"; fi
      echo "helm test: $([ "$TEST_OK" = 1 ] && echo passed || echo FAILED) (log, including the test pods' output: $OUT/after-helm-test.log)"
      echo
      echo "traffic diff (baseline -> with policy):"
      cat "$OUT/diff.txt"
    } | tee "$OUT/verdict.txt"
    if [ "$CODE" != 0 ] && [ "$ROLLBACK_ON_FAIL" = 1 ]; then
      say "rolling back $POLICY"
      kc delete -n "$NS" -f "$POLICY" --ignore-not-found
    fi
    exit "$CODE"
    ;;

  rollback)
    [ -f "$POLICY" ] || die "--policy file not found: $POLICY"
    kc delete -n "$NS" -f "$POLICY" --ignore-not-found
    ;;

  *) usage; exit 1 ;;
esac
