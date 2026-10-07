---
name: podpeers-netpol
description: Add or tighten Kubernetes NetworkPolicy for a Helm release using traffic podpeers actually observed, then prove the app still works with the policy in place (helm test + before/after traffic diff) and detect when a policy breaks something. Use when asked to "add network policies", "lock down traffic", "write a NetworkPolicy for this chart", "check whether this policy breaks the app", or to turn podpeers suggestions into applied, verified policy.
---

# podpeers-netpol: from observed traffic to a verified NetworkPolicy

You are turning **observed** traffic into NetworkPolicy and **proving** the
application still works with it. The loop is:

```
baseline capture (helm test running)  ->  suggestions  ->  review with the user
      ->  apply  ->  verify (helm test + capture + diff)  ->  OK, or BROKEN + why  ->  fix or roll back
```

`scripts/netpol-check.sh` (next to this file) does the mechanical steps. Your
job is the judgement: reading the reasoning and gaps, telling the user what the
policy will cost them, and deciding what a failure means.

## Safety rules (not negotiable)

1. **Never run this against a cluster the user has not chosen for it.** Always
   pass `--context` explicitly; never rely on the current context. Run
   `podpeers check-context --context <ctx>` first. podpeers refuses anything
   but a local kind/k3d cluster by default.
2. **Never add `--allow-context` yourself.** It exists for a human to name a
   non-local cluster they have deliberately chosen. If the only available
   context is non-local, stop and ask; suggest a local kind/k3d copy of the
   release instead.
3. Capture adds an ephemeral debug container to every pod the selector
   matches. Say so before the first capture in a session.
4. Applying a NetworkPolicy changes live traffic. Show the policy (and its
   NOT COVERED list) to the user and get a yes before `verify`, unless they
   have already said to go ahead for this cluster.

## Step 1: preconditions

- `podpeers version`, `kubectl`, and `helm` are on PATH, and the release
  exists: `helm status <release> -n <ns> --kube-context <ctx>`.
- The chart **has a meaningful `helm test`**. If it does not, say so: without
  it, verification rests on the traffic diff alone. Offer to write one that
  exercises the app's front door and holds its connection for a few seconds,
  like `examples/shop/templates/tests/smoke.yaml` in the podpeers repo does.
- The CNI enforces NetworkPolicy (kind's default CNI does not; k3s/k3d does;
  Calico and Cilium do). If it does not, a "verified" policy proves nothing.
  Say so.

## Step 2: baseline

```bash
scripts/netpol-check.sh baseline --release <rel> --namespace <ns> --context <ctx> \
  [--kubeconfig <path>] [--duration 10m] [--interval 1s] [--out ./netpol]
```

This captures the release while `helm test` runs inside the window. That
matters: the test pod is a new client, and if its traffic is not observed, the
suggested policy will (correctly) block it and the test will fail. The script
then writes:

- `baseline.json`: the capture (`podpeers render -format html` to look at it)
- `policy.yaml`: apply-ready suggestions; reasoning and gaps are YAML comments
- `policy.json`: the same, structured (or use the MCP `suggest_policies` tool)

Exit 6 means `helm test` already fails **without** any new policy. Stop: a
later failure would prove nothing.

**Window length.** The default (40s) is only enough for demos and CI. For a
real workload, capture across its busiest and rarest operations (deploys,
cron jobs, failover). The suggestions say what they did not cover; believe
them.

## Step 3: review the suggestions with the user

Read `policy.yaml` (or `policy.json`) and present, per workload:

- **What it allows**: each rule and its evidence ("web -> api tcp/9000, 3
  connections, open at window end").
- **NOT COVERED**: relay these verbatim; they are the point. In particular:
  - *the egress the workload would LOSE* (idle dependencies, external
    addresses, the Kubernetes API if it uses its service account);
  - *ports it listens on with no observed client* (health checks, metrics
    scrapers), which become closed;
  - *window/interval limits*: short connections and weekly jobs are invisible;
  - rules marked **ASSUMED** (DNS), which were not observed.
- **Refused workloads** (`NO POLICY SUGGESTED`): too little evidence. Do not
  hand-write a guess for them; capture longer, or ask the user.
- Half-open (`SYN_SENT`) attempts are never turned into allow rules. If any
  appear, something may already be blocking that traffic. Point it out.

Edit the YAML only with the user's agreement (e.g. add a known weekly job's
egress). Every hand-added rule should get a comment saying it was not observed.

## Step 4: apply and verify

```bash
scripts/netpol-check.sh verify --release <rel> --namespace <ns> --context <ctx> \
  --policy ./netpol/policy.yaml --baseline ./netpol/baseline.json [--rollback-on-fail]
```

This dry-runs and applies the policy, waits for the CNI to program it, then runs
a second capture with `helm test` inside it, and diffs against the baseline.
`verdict.txt` holds the result.

| exit | verdict | what it means |
|------|---------|---------------|
| 0 | OK | helm test passed **and** no flow was blocked or lost |
| 5 | BROKEN: helm test failed | the user-visible path is broken; read `after-helm-test.log` and `diff.txt` |
| 4 | BROKEN: helm test passed, traffic blocked/lost | the test does not exercise what broke; the diff names the flow |
| 2 | context refused | nothing was touched |

## Step 5: telling that a policy broke something

Use all three signals; any one is enough to call it broken:

1. **`helm test` fails** with the policy and passed in the baseline.
2. **`blocked` lines in the diff.** A flow that only ever reached `SYN_SENT`
   after the change is the fingerprint of a NetworkPolicy drop. This is the
   strongest evidence, and it catches breakage that `helm test` misses
   (exit 4).
3. **`lost` lines**: a flow seen in the baseline and absent afterwards, while
   its observer was still being observed. Weaker: it may just have been idle.
   Recapture with a longer window before concluding.

`unverifiable` lines mean the pod that saw the flow was not observed the
second time. They say nothing either way.

**Rule out the new-pod race before blaming the policy.** CNIs program a
policy's allow-list for a *newly created* pod asynchronously. A client pod
that connects in its first second (a `helm test` pod, a Job, a freshly
scaled replica) can be dropped even by a correct policy. On k3s's embedded
kube-router this was observed as a connection that completed its handshake
and then hung, so the traffic diff showed nothing while `helm test` timed out.
To tell the two apart:

- re-run `helm test` once. A race passes the second time; a real block fails
  again;
- or run a throwaway pod with the test pod's labels that sleeps ~10s before
  connecting. If that works and the immediate attempt does not, it is the race.

The fix for a race is in the *test*, not the policy: retry with a bounded
`timeout` (see `examples/shop/templates/tests/smoke.yaml`). Tell the user,
because their real clients that connect at startup have the same exposure.

When it is broken, name the flow, find which policy and direction should have
allowed it (`podpeers query`, MCP `peers`), and either add the missing rule
(with the user) and re-run `verify`, or roll back:

```bash
scripts/netpol-check.sh rollback --namespace <ns> --context <ctx> --policy ./netpol/policy.yaml
```

Never leave a BROKEN policy applied without telling the user.

## Step 6: hand-off into the chart

Once `verify` is OK, offer to put the policy into the chart so it ships with
the release and `helm test` keeps guarding it:

- `templates/networkpolicy.yaml`, gated by `values.networkPolicy.enabled`;
- replace hard-coded labels with the chart's label helpers, and the namespace
  with `{{ .Release.Namespace }}`;
- keep the NOT COVERED notes as comments in the template;
- keep `helm test` able to reach what it tests: its pod is a client too.

## Querying directly (MCP)

`podpeers mcp <capture.json>` serves the capture to an agent over stdio:
`summary`, `list_pods`, `peers`, `query` (GraphQL), `suggest_policies` and
`diff_captures`. It is read-only and has no capture tool, so captures stay a
deliberate CLI step under the context guard. Register it with, for example:

```bash
claude mcp add podpeers -- podpeers mcp /abs/path/netpol/baseline.json
```
