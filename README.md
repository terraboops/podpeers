# podpeers

Map the network peers of every pod in a cluster from **observed sockets**, and
turn what you saw into **NetworkPolicy you can verify**, without flow logs.

You have a running cluster with no NetworkPolicy and want to add some without
breaking anything. The usual answer is a flow-log pipeline (CNI flow logs,
Hubble, VPC logs). podpeers gets the same evidence with only your kubectl
credentials:

1. For every pod a label selector matches, it adds a short-lived **ephemeral
   debug container**.
2. That container shares the pod's network namespace and samples
   `/proc/net/{tcp,tcp6,udp,udp6}` (the data behind `netstat -tun`) every few
   seconds for the measurement window, then exits on its own.
3. podpeers reads the samples back from the container logs and builds a peer
   graph. Remote addresses are resolved to pods, services, nodes or external
   addresses; direction comes from the pod's listening ports; and each edge
   records whether it stayed open, closed during the window, or never
   completed a handshake (the fingerprint of a policy drop).

Nothing is installed in the cluster: no DaemonSet, no agent, no privileged
sidecar. The debug container runs as `nobody` with every capability dropped,
so it is admitted under the `restricted` Pod Security Standard.

## Safety: it refuses your production cluster

podpeers modifies every pod a selector matches, so pointing it at the wrong
context is a real incident. **By default it refuses any context that is not a
local cluster.** Two gates run before any pod is touched:

1. **Pre-flight, from the kubeconfig alone (no network):** the context name
   must be one a local tool writes (`kind-*`, `k3d-*`, `minikube`,
   `docker-desktop`, …) **and** its API server must be on loopback.
2. **After connecting, read-only:** every node must carry a kind or k3s
   provider ID. This catches a loopback tunnel to a cloud cluster.

The only way past either gate is `--allow-context=<the exact context name>`.
That makes the operator type the name of the cluster they are about to modify.
A mismatched name is a refusal, not a fallback. Exit code 2 means refused. The
unit suite proves a refusal makes **zero** API requests; the e2e suite proves
it on a real cluster and checks that no pod was modified.

Captures also require a label selector, so there is no "probe everything"
default.

## Install

```bash
go install github.com/terraboops/podpeers/cmd/podpeers@latest
```

## Use

```bash
# observe (local cluster): 10 minutes, a sample every 2s
podpeers capture -n shop -l 'app.kubernetes.io/part-of=shop' --duration 10m --interval 2s -o peers.json

podpeers render -format text peers.json          # report
podpeers render -format html -o peers.html peers.json   # interactive graph, self-contained
podpeers render -format dot peers.json | dot -Tsvg > peers.svg

podpeers query peers.json '{ pod(id: "shop/api-0") { peers(direction: "inbound") { id kind } } }'
podpeers serve peers.json                        # graph + GraphQL console on 127.0.0.1:8080

podpeers suggest -n shop peers.json > policy.yaml   # NetworkPolicy suggestions
podpeers diff before.json after.json              # did a policy break anything?
podpeers mcp peers.json                           # MCP server on stdio, for agents
```

Exit codes: `0` ok · `1` error · `2` refused by the safety guard · `3`
capture written but some pods could not be observed · `4` diff found blocked
or lost traffic.

### What a capture reports

```
pp-app/api  [observed]
  listening: tcp/9000
  DIR  PEER             KIND  PORT      CONNS  STATE
  <-   pp-app/brief     pod   tcp/9000  1      closed in window
  <-   pp-app/excluded  pod   tcp/9000  1      open
  <-   pp-app/web       pod   tcp/9000  1      open

pp-app/loner  [observed]
  no peers observed

pp-app/pending  [skipped: pod phase is Pending, not Running]
```

(Real output from the e2e suite. `excluded` was never probed; it appears
because `api` saw it.)

## NetworkPolicy suggestions

`podpeers suggest` emits, per observed workload (Deployment, StatefulSet, …,
grouped through owner references so replicas share one policy), a
**ready-to-apply** NetworkPolicy that permits the observed traffic and nothing
else. Every rule carries its reasoning as YAML comments:

```yaml
# WHY each rule exists:
#   egress[0] allows pods behind service pp-helm/shop-api (…component=api…) on tcp/api
#       shop-web-… -> svc/pp-helm/shop-api tcp/80: 6 connection(s), seen in 26 sample(s),
#       open at window end (service port 80 -> target port api)
#   egress[1] allows cluster DNS (pods k8s-app=kube-dns in kube-system) on udp/53, tcp/53
#       ASSUMED, not observed: DNS lookups are short UDP exchanges that socket sampling
#       rarely catches, and the observed outbound connections used names
#
# NOT COVERED by this observation:
#   - Egress is now limited to the rules above. The workload would LOSE: …
```

- Traffic to a Service is translated to the Service's pod selector and its
  **target port** (named ports included), because policy is evaluated after
  DNAT.
- Cross-namespace peers get a `namespaceSelector` on
  `kubernetes.io/metadata.name`.
- Every suggestion lists what it does **not** cover: the window and the
  sampling interval; the egress the workload would lose; ports it listens on
  with no observed client; peers that cannot be expressed (no labels,
  selectorless Services, the API server); single-IP rules that will go stale;
  and pods of the workload that were not observed.
- **It refuses rather than guesses** when the evidence is too thin: no pod of
  the workload observed, too few samples, no stable labels to select by,
  hostNetwork pods, or no traffic at all. A quiet window is not proof of
  isolation. (`--allow-empty` emits deny-all deliberately.)
- Connections that never completed a handshake are never turned into allow
  rules.

## Query interface: why GraphQL

A capture is a small, typed, read-only graph loaded from one file. GraphQL
runs in-process with no server to operate. TinkerPop would need Gremlin
Server (a JVM service) and a graph store. GraphQL also has an introspectable
schema, and its nested selections (`pod → edges → peer → pod → seenBy`)
express the one- and two-hop questions that NetworkPolicy work asks. The cost
is arbitrary-depth path search (Gremlin's `repeat()`), which per-hop policy
does not need.

Root fields: `window`, `pods(namespace, status, label)`, `pod(id | namespace,
name)`, `edges(direction, peerKind, protocol, port, open)`, `peers`,
`services`. `Pod.seenBy` gives the edges observed on *other* pods that point
at this one, which is the only evidence for pods you did not probe.

## MCP mode

`podpeers mcp peers.json` speaks the Model Context Protocol over stdio. It
offers six tools: `summary`, `list_pods`, `peers`, `query` (GraphQL),
`suggest_policies`, and `diff_captures`. The capture file is re-read on every
call. **The MCP server is read-only and has no capture tool.** Launching debug
containers stays a deliberate, guarded CLI action that an agent cannot
trigger through a tool call.

```bash
claude mcp add podpeers -- podpeers mcp /abs/path/peers.json
```

## Claude Code skill: from suggestion to verified policy

[`skills/podpeers-netpol`](skills/podpeers-netpol/SKILL.md) is a Claude Code
skill. This repo is also a Claude Code plugin (`.claude-plugin/`). The skill
carries the workflow for adding policy to a **Helm release** and proving the
app still works:

```
baseline capture while `helm test` runs → suggestions → review → apply
  → verify: `helm test` + second capture + diff → OK / BROKEN (why) → fix or roll back
```

Its script, `scripts/netpol-check.sh`, does the mechanical part and returns a
verdict:

- `0`: OK.
- `5`: `helm test` failed.
- `4`: `helm test` passed but traffic the app relied on is now blocked. The
  diff caught a break the test cannot see.

The e2e suite runs this exact script against a real Helm release. It shows
the good policy passing, an unobserved client being blocked, and **both kinds
of broken policy being caught**.

Two things the skill teaches that were learnt by running it for real:

- Run `helm test` *inside* the baseline window. The test pod is a client too,
  and if its traffic is not observed, the policy will correctly block it.
- CNIs program allow-lists for a *new* pod asynchronously. A test pod that
  connects in its first second can be dropped by a correct policy (on k3s's
  kube-router this hangs after the handshake). Make tests retry with a bounded
  `timeout`, and re-run once before blaming the policy.

## Testing

```bash
make test   # unit tests (race detector), run in CI
make e2e    # creates a throwaway single-node k3d cluster, runs the real-cluster suite
make e2e-down
```

The **e2e suite** never touches your kubeconfig. `hack/e2e-cluster.sh` writes
the cluster's kubeconfig to `.e2e/kubeconfig`, and the suite refuses to run
unless that file's context is exactly the cluster it created. It deploys
workloads whose connections are known in advance, runs the real binary, and
asserts that the reported edges match **exactly**. Named cases:

| case | how | asserted |
|---|---|---|
| known peers | `web→api`, cross-namespace `gateway→web` via Services | exact edge sets, both ends |
| pod with no peers | `loner` runs `sleep` | observed, zero edges; `suggest` refuses it |
| connection that closes during the window | the test kills `brief`'s client mid-window | `closed` on both ends |
| pod the selector excludes | `excluded` lacks the label | not probed, no ephemeral container, still resolved as `api`'s peer |
| pending pod | unschedulable `nodeSelector` | skipped, untouched |
| debug container cannot start | unpullable image | fails within `--start-timeout` with `ErrImagePull`, exit 3 |
| namespace you may not modify | ServiceAccount that may read but not add ephemeral containers | per-pod `forbidden` naming `pods/ephemeralcontainers`, pod untouched |
| namespace you may not read | same SA, no access | clean failure at listing, exit 1 |
| non-local context | the same real cluster under a non-local context name | refused (exit 2), no pod modified; `--allow-context` accepted |
| suggestions | real capture | right workloads get policies, thin ones refused, API server dry-run accepts all |
| MCP | the binary over stdio | peers and suggestions answered from the real capture |
| skill workflow | `examples/shop` Helm release | baseline, good policy OK, intruder blocked, egress break caught by diff (helm test passes), ingress break caught by helm test, rollback, refusal |

CI runs the unit suite and the e2e suite (on a k3d cluster on the runner) on
every push.

## Known limits

- **Sampling, not capture.** A connection that opens and closes between two
  samples is invisible. Short-lived HTTP calls are the usual victims, although
  the closing side's `TIME_WAIT` (60s) often makes them visible. Use a shorter
  `--interval` and a longer `--duration`.
- **Ephemeral containers cannot be removed.** The Kubernetes API has no delete
  for them, so a terminated `podpeers-<run>` entry stays in each probed pod's
  status until the pod is replaced. The sampler itself exits at the end of the
  window, even if podpeers is interrupted.
- **No process names.** podpeers reports sockets, not owning processes
  (`netstat -p`). That would need process-namespace targeting and root in the
  debug container.
- **hostNetwork pods are skipped**: their sockets are the node's.
- Byte order is assumed little-endian (amd64/arm64 nodes).
- Peers in namespaces your credentials cannot list resolve as plain addresses.
- Enforcement semantics, including kubelet probes and new-pod timing, depend
  on your CNI.

## Licence

MIT
