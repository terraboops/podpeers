---
name: podpeers-netpol
description: Add or tighten Kubernetes NetworkPolicy for a Helm release using traffic podpeers actually observed, then prove the app still works with the policy in place (helm test + before/after traffic diff) and detect when a policy breaks something. Use when asked to "add network policies", "lock down traffic", "write a NetworkPolicy for this chart", "check whether this policy breaks the app", or to turn podpeers suggestions into applied, verified policy.
---

# podpeers-netpol: from observed traffic to a verified NetworkPolicy

You are turning **observed** traffic into NetworkPolicy and **proving** the
application still works with it. The loop is:

```
baseline capture (helm test running)  ->  suggestions  ->  review with the user
      ->  apply  ->  verify (restart + helm test + capture + diff)  ->  OK / BROKEN / INCONCLUSIVE
      ->  fix or roll back  ->  ship it in the chart and verify that too
```

`scripts/netpol-check.sh` (next to this file) does the mechanical steps. Your
job is the judgement: reading the reasoning and gaps, telling the user what the
policy will cost them, and deciding what a failure means.

## Safety rules (not negotiable)

1. **Never run this against a cluster the user has not chosen for it.** Pass
   the context explicitly on *every* command that talks to a cluster (offline
   ones such as `helm template` are marked below), and the kubeconfig file too when
   the cluster lives in its own file (kind and k3d clusters often do):
   `--context <ctx> --kubeconfig <path>` for podpeers, kubectl and the script;
   `--kube-context <ctx> --kubeconfig <path>` for helm, **after** the helm
   subcommand (Helm 4 rejects some flags before it). Without `--kubeconfig`,
   `$KUBECONFIG` (or `~/.kube/config`) is used and `<ctx>` must exist there;
   never rely on its current context. Run `podpeers check-context --context
   <ctx> [--kubeconfig <path>]` first: podpeers refuses anything but a local
   kind/k3d cluster by default.
2. **Never add `--allow-context` yourself.** It exists for a human to name a
   non-local cluster they have deliberately chosen. If the only available
   context is non-local, stop and ask; suggest a local kind/k3d copy of the
   release instead.
3. Capture adds an ephemeral debug container to every pod the selector
   matches. Say so before the first capture. Kubernetes cannot remove
   ephemeral containers: a terminated `podpeers-…` entry stays in each probed
   pod's spec until the pod is replaced (verify's restart replaces them).
4. Applying a NetworkPolicy changes live traffic. Show the policy (and its
   NOT COVERED list) to the user and get a yes before `verify`, unless they
   have already said to go ahead for this cluster.

## Step 1: preconditions

- **podpeers.** Install it with
  `go install github.com/terraboops/podpeers/cmd/podpeers@latest`, or in a
  checkout of the podpeers repo run `make build` (binary at `bin/podpeers`).
  `go install` puts the binary in `$GOBIN` (default `~/go/bin`), which may not
  be on `PATH`. The script runs `$PODPEERS` if set, otherwise `podpeers` from
  `PATH`. Check with `podpeers version`. `kubectl` and `helm` must be on `PATH` as well.
- **The release exists:**
  `helm status <release> -n <ns> --kube-context <ctx> [--kubeconfig <path>]`.
- **Which pods to observe.** The script selects
  `app.kubernetes.io/instance=<release>` (the standard Helm label). If the
  chart does not set it, pass `--selector <label selector>` to every script
  command; otherwise the capture matches no pods. Check:
  `kubectl get pods -n <ns> -l app.kubernetes.io/instance=<release> --context <ctx> [--kubeconfig <path>]`
  must list the release's pods.
- **The chart has a meaningful `helm test`**: `helm get hooks <release> -n <ns>
  --kube-context <ctx> [--kubeconfig <path>]` shows its test pods
  (`helm.sh/hook: test`). If it has none, say so: without
  it, verification rests on the traffic diff alone. Offer to write one that
  exercises the app's front door, holds its connection for a few seconds, and
  retries with a bounded `timeout`, like
  `examples/shop/templates/tests/smoke.yaml` in the podpeers repo.
- **The CNI enforces NetworkPolicy**, or a "verified" policy proves nothing.
  kind's default CNI does not; Calico and Cilium do; k3s/k3d do *unless*
  started with `--disable-network-policy`. Check rather than assume: on k3s,
  `kubectl get node <node> -o jsonpath='{.metadata.annotations.k3s\.io/node-args}'`
  must not contain `--disable-network-policy`. Anywhere, the definitive test
  (it creates and deletes a scratch namespace, so ask the user first) is a
  connection that works, then fails under a deny-all policy. Add
  `--context <ctx> [--kubeconfig <path>]` to each command, written out, not
  hidden in a shell variable (zsh will not split it):
  ```bash
  kubectl create namespace netpol-enforcement-check
  kubectl run target -n netpol-enforcement-check --image=busybox:1.36 --labels=app=target --command -- nc -lk -p 8080 -e cat
  kubectl wait -n netpol-enforcement-check --for=condition=Ready pod/target
  IP=$(kubectl get pod target -n netpol-enforcement-check -o jsonpath='{.status.podIP}')
  # run twice: before and after the deny-all; expect REACHABLE, then BLOCKED
  kubectl run probe -n netpol-enforcement-check --image=busybox:1.36 --restart=Never --rm -i --quiet --command -- \
    sh -c "sleep 10; timeout 5 nc -z -w 3 $IP 8080 && echo REACHABLE || echo BLOCKED"
  printf 'apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata: {name: deny-all}\nspec: {podSelector: {}, policyTypes: [Ingress]}\n' \
    | kubectl apply -n netpol-enforcement-check -f -
  kubectl delete namespace netpol-enforcement-check
  ```
  REACHABLE both times means the CNI does not enforce policy.

## Step 2: baseline

```bash
scripts/netpol-check.sh baseline --release <rel> --namespace <ns> --context <ctx> \
  [--kubeconfig <path>] [--selector <sel>] [--duration 40s] [--interval 1s] [--out ./netpol]
```

`--duration` defaults to 40s, which is only enough for demos and CI. For a
real workload, capture across its busiest and rarest operations (deploys,
cron jobs, failover), with **real traffic flowing** (see Step 3). The
suggestions say what they did not cover; believe them.

This captures the release while `helm test` runs inside the window. That
matters: the test pod is a new client, and if its traffic is not observed, the
suggested policy will (correctly) block it and the test will fail. It writes,
to `--out` (default `./podpeers-netpol`):

- `baseline.json`: the capture (`podpeers render -format html -o baseline.html baseline.json`
  to look at it; `baseline.txt` is a text report; `baseline.json.log` is the
  capture's own log, and `baseline-helm-test.log` the test run with its pods' output)
- `policy.yaml`: apply-ready suggestions; reasoning and gaps are YAML comments
- `policy.json`: the same, structured: `{window, gaps, suggestions: [{workload,
  policy, reasons, gaps, refused}]}` (or use the MCP `suggest_policies` tool)

Exit 6 means `helm test` already fails **without** any new policy. Stop: a
later failure would prove nothing.

## Step 3: review the suggestions with the user

Read `policy.yaml` (or `policy.json`) and present, per workload:

- **What it allows**: each rule and its evidence ("web -> api tcp/9000, 3
  connections, open at window end").
- **NOT COVERED**: relay these verbatim; they are the point. In particular:
  - **`ENTRY POINT WARNING`** lines, which come first: every client seen on
    that port had already completed (the helm test pod, a Job). If it is the
    app's front door, the policy admits *only the test* and shuts out real
    users and the ingress controller, while `verify` still says OK because
    the test is the one allowed client. Never apply such a policy outside a
    demo without asking the user who the real clients are; add them as rules
    commented "not observed", or capture again under real traffic;
  - *the egress the workload would LOSE* (idle dependencies, external
    addresses, the Kubernetes API if it uses its service account, DNS when
    the workload has no egress at all);
  - *ports it listens on with no observed client* (health checks, metrics
    scrapers), which become closed;
  - *UDP listeners*: an unconnected UDP socket (DNS, QUIC, syslog) records
    no peer, so its clients were invisible from that side; unless they were
    captured from their own side, the policy drops all UDP to that port;
  - *window/interval limits*: short connections and weekly jobs are invisible
    (the report's "could not see" list states this capture's numbers; see
    `docs/method.md` in the podpeers repo);
  - rules marked **ASSUMED** (DNS), which were not observed.
- **Even without a warning, look at every ingress rule on the app's entry
  point** and ask: are these all the real clients? A quiet window sees only
  what happened in it.
- **Refused workloads** (`NO POLICY SUGGESTED`): too little evidence. Do not
  hand-write a guess for them; capture longer, or ask the user.
- Half-open (`SYN_SENT`) attempts are never turned into allow rules. If any
  appear, something may already be blocking that traffic. Point it out.

Edit the YAML only with the user's agreement (e.g. add a known weekly job's
egress). Every hand-added rule should get a comment saying it was not observed.

## Step 4: apply and verify

```bash
scripts/netpol-check.sh verify --release <rel> --namespace <ns> --context <ctx> [--kubeconfig <path>] \
  --policy ./netpol/policy.yaml --baseline ./netpol/baseline.json [--out ./netpol] [--rollback-on-fail]
```

This dry-runs and applies the policy and waits for the CNI to program it. Then
it **rollout-restarts the release's workloads**, runs a second capture with
`helm test` inside it, and diffs against the baseline. Results go next to the
baseline unless `--out` says otherwise: `verdict.txt`, `diff.txt`,
`after.json`, and `after-helm-test.log`, which includes the test pods' own
output.

The restart is essential. CNIs check a policy only when a connection is
opened, so a connection pool, gRPC channel or database connection established
*before* the policy keeps working under a policy that would block it. Without
the restart, a policy that will break the app on its next restart can verify
"OK". This was observed for real while building this skill. Use `--no-restart`
only if restarting is unacceptable; expect INCONCLUSIVE.

| exit | verdict | what it means |
|------|---------|---------------|
| 0 | OK | helm test passed **and** no flow was blocked or lost |
| 5 | BROKEN: helm test failed | the user-visible path is broken; read `after-helm-test.log` and `diff.txt` |
| 4 | BROKEN: helm test passed, traffic blocked/lost | the test does not exercise what broke; the diff names the flow |
| 7 | INCONCLUSIVE | some flows were only seen on connections older than the policy (`preexisting` lines): the policy was never exercised for them. Restart those workloads and verify again. Never report this as OK |
| 2 | context refused | nothing was touched |

**On OK, still read `after-helm-test.log`.** If the test only passed after a
retry ("attempt 1 got no answer"), you are probably seeing the new-pod race
described in Step 5: confirm it there, then tell the user, because their real
clients that connect once at startup without retrying have the same exposure.
(`punt!` and `Terminated` lines come from busybox `nc` being killed by the
test's `timeout`; on their own they mean one attempt timed out, not that the
test failed. The test's exit status and its own messages decide.)

## Step 5: telling that a policy broke something

Use all three signals; any one is enough to call it broken:

1. **`helm test` fails** with the policy and passed in the baseline.
2. **`blocked` lines in the diff.** A flow that never completes a handshake
   after the change (`SYN_SENT`, or refused) is the fingerprint of a
   NetworkPolicy drop. This is the strongest evidence, and it catches
   breakage that `helm test` misses (exit 4).
3. **`lost` lines**: a flow seen repeatedly in the baseline and absent
   afterwards, while its observer was still being observed. Weaker: it may
   just have been idle. Recapture with a longer window before concluding.

`unverifiable` lines mean the pod that saw the flow was not observed the
second time. `preexisting` lines mean the flow was only seen on connections
opened before the policy. `glimpsed` lines are one short connection caught by
luck in the baseline (typically a DNS lookup). None of these says anything
about whether the policy allows the flow.

**Rule out the new-pod race before blaming the policy.** CNIs program a
policy's allow-list for a *newly created* pod asynchronously. A client pod
that connects in its first second (a `helm test` pod, a Job, a freshly
scaled replica) can be dropped even by a correct policy. On k3s's embedded
kube-router this was observed as a connection that completed its handshake
and then hung, so the traffic diff showed nothing while `helm test` timed out.
To tell the two apart:

- **Read the test log's attempts.** A race fails the *first* attempt and then
  passes, on every run; a real block fails *every* attempt. (Re-running
  `helm test` alone proves nothing when the test retries internally, as the
  recommended one does: race and block both look the same from outside.)
- **Confirm with a probe pod** that has the test pod's labels, connects
  immediately, then again after 10s. Race: blocked immediately, reachable
  after 10s. Block: blocked both times. Run it *between* captures (it carries
  the release's labels, so a running capture would pick it up), and delete it
  afterwards. The pod is deleted with an explicit `kubectl delete` rather than
  `kubectl run --rm`: some agent sandboxes refuse `--rm` next to a
  `sh -c` script. Add `--context <ctx> [--kubeconfig <path>]` to every
  command, written out. Pick the probe that matches the app:
  ```bash
  LABELS=$(kubectl get pod <test-pod> -n <ns> --show-labels --no-headers | awk '{print $NF}')

  # TCP echo server (like the example app): a reply means reachable
  kubectl run netpol-race-probe -n <ns> --image=busybox:1.36 --restart=Never -i --quiet \
    --labels "$LABELS" --command -- sh -c 'try() { r=$( (echo ping; sleep 1) | timeout 4 nc -w 2 <service>.<ns>.svc.cluster.local <port>); [ -n "$r" ] && echo "$1: REACHABLE" || echo "$1: BLOCKED"; }; try immediately; sleep 10; try after-10s'

  # HTTP app: ANY HTTP response, including 404 or 401, means the network
  # path is open; only "refused" or "timed out" means blocked
  kubectl run netpol-race-probe -n <ns> --image=busybox:1.36 --restart=Never -i --quiet \
    --labels "$LABELS" --command -- sh -c 'URL=http://<service>.<ns>.svc.cluster.local:<port>/; try() { out=$(wget -q -O /dev/null -T 4 "$URL" 2>&1); case "$?:$out" in 0:*) echo "$1: REACHABLE";; *"server returned error"*) echo "$1: REACHABLE (${out#wget: })";; *) echo "$1: BLOCKED (${out#wget: })";; esac; }; try immediately; sleep 10; try after-10s'

  kubectl delete pod netpol-race-probe -n <ns>
  ```
  (Do not judge an HTTP probe by whether a body came back: a reachable app
  answering 404 on `/` returns no body.)

The fix for a race is in the *test*, not the policy: retry with a bounded
`timeout` (see `examples/shop/templates/tests/smoke.yaml`).

When it is broken, name the flow, find which policy and direction should have
allowed it (`podpeers query`, MCP `peers`), and either add the missing rule
(with the user) and re-run `verify`, or roll back:

```bash
scripts/netpol-check.sh rollback --namespace <ns> --context <ctx> [--kubeconfig <path>] --policy ./netpol/policy.yaml
```

Never leave a BROKEN policy applied without telling the user.

## Step 6: hand-off into the chart

Once `verify` is OK, offer to put the policy into the chart so it ships with
the release and `helm test` keeps guarding it:

1. Add `templates/networkpolicy.yaml`, gated by `.Values.networkPolicy.enabled`.
   Ask the user what the default should be: `false` lets existing installs
   opt in; `true` ships it everywhere. Replace hard-coded labels with the
   chart's label helpers and the namespace with `{{ .Release.Namespace }}`;
   keep the NOT COVERED notes as comments; keep `helm test` able to reach what
   it tests (its pod is a client too). Its labels must come from the same
   helpers as the policy's selectors: render the chart under another release
   name and namespace (`helm template other <chart> -n elsewhere --set networkPolicy.enabled=true`)
   and check the test pod still matches the policy's `from` selector.
2. **Name the templated policies differently from the `podpeers-<workload>`
   ones `verify` applied** (e.g. `{{ .Release.Name }}-web`). Same names make
   `helm upgrade` fail: Helm will not adopt objects it did not create.
3. Check the template renders exactly what was verified. `helm template` is
   offline; the `kubectl create --dry-run=client` used to normalise both
   files takes the usual `--context`/`--kubeconfig`. Comments, names, key
   order and the order of the policies differ, so compare the normalised,
   sorted `spec`s (`-s` matters: kubectl prints one JSON object per policy):
   ```bash
   specs() { kubectl create --dry-run=client -o json -f "$1" \
     | jq -S -s '[.[] | (.items // [.])[] | {spec}] | sort_by(.spec.podSelector | tostring)'; }
   helm template <rel> <chart> -n <ns> --set networkPolicy.enabled=true -s templates/networkpolicy.yaml > rendered.yaml
   diff <(specs ./netpol/policy.yaml) <(specs rendered.yaml) && echo SPECS IDENTICAL
   ```
4. Upgrade the release with the policy enabled, then **remove the
   kubectl-applied copies**, or you are left with duplicates (rollback deletes
   only the `podpeers-*` objects in that file):
   ```bash
   helm upgrade <rel> <chart> -n <ns> --kube-context <ctx> [--kubeconfig <path>] --reuse-values \
     --set networkPolicy.enabled=true --wait
   scripts/netpol-check.sh rollback --namespace <ns> --context <ctx> [--kubeconfig <path>] --policy ./netpol/policy.yaml
   ```
   If the chart's default is `false`, warn the user: a later `helm upgrade`
   that passes *any* values (`--set`/`-f`) without `--reuse-values` resets
   `networkPolicy.enabled` to `false` and silently removes the policy. (An
   upgrade that passes no values at all keeps the previous ones.)
5. Verify what the chart now ships, without applying anything:
   ```bash
   scripts/netpol-check.sh verify --release <rel> --namespace <ns> --context <ctx> [--kubeconfig <path>] \
     --no-apply --baseline ./netpol/baseline.json --out ./netpol/chart
   ```
   Same verdicts as Step 4. Like every verify, it restarts the workloads (adding
   kubectl's `restartedAt` annotation to their pod templates, outside Helm)
   and leaves terminated `podpeers-…` ephemeral containers in the new pods
   until they are next replaced. Tell the user. The ephemeral containers go
   with the next rollout; the annotation stays (Helm leaves fields it did not
   set), which is harmless: it is exactly what `kubectl rollout restart` adds.

## Querying directly (MCP)

`podpeers mcp <capture.json>` serves the capture to an agent over stdio:
`summary`, `list_pods`, `peers`, `query` (GraphQL), `suggest_policies` and
`diff_captures`. It is read-only and has no capture tool, so captures stay a
deliberate CLI step under the context guard. Register it with, for example:

```bash
claude mcp add podpeers -- podpeers mcp /abs/path/netpol/baseline.json
```
