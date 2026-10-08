# How podpeers sees traffic, and what it cannot see

podpeers does not capture packets. It **samples the kernel's socket tables**
from inside each selected pod and infers peers from the sockets it finds. That
choice is what lets it work without flow logs, agents or privileges, and it is
also the source of every blind spot below. A NetworkPolicy built from a
capture is only as complete as what the capture could see. Assume a capture is
complete and you will write a policy that breaks your cluster: the failure this
project exists to prevent.

Every capture states these limits with its own numbers (`limits` in the JSON,
"WHAT THIS CAPTURE COULD NOT SEE" in the report, a panel in the web UI,
`limits` in GraphQL, and the report-level gaps of `podpeers suggest`).

## The mechanism

For every pod the selector matches, podpeers adds an ephemeral debug
container. Containers in a pod share one network namespace, so the debug
container's `/proc/net/{tcp,tcp6,udp,udp6}` are the pod's socket tables. Every
`--interval` it reads all four with one `cat`, plus its clock from
`/proc/uptime`, until `--duration` has passed, then exits on its own. A
capture takes `duration ÷ interval + 1` samples per pod (60s at 5s is 13).

All four tables are read, so IPv4, IPv6 and UDP sockets are all captured.
Remote addresses are resolved against every pod IP (both families on
dual-stack clusters), every Service ClusterIP and every node address in the
cluster. Nothing depends on which node a pod runs on: cross-node traffic is
seen like any other (the end-to-end suite asserts this on a two-node cluster).

## What it cannot see

### 1. Anything between two samples, partly mitigated for TCP

A socket is seen only if it exists at the instant of a sample. What saves TCP
is `TIME_WAIT`: when a connection is closed normally, **the side that closed
first** keeps a `TIME_WAIT` entry for 60 seconds (a fixed Linux constant).
podpeers counts `TIME_WAIT` as evidence of a completed connection, so if that
side was sampled, even a connection lasting milliseconds is seen.

This was measured on a real cluster: one connection lasting milliseconds left
a `TIME_WAIT` entry on the client (which closed first) that was still there 5
seconds later and gone 65 seconds later. The server, which closed second,
showed nothing even 5 seconds later.

So the TCP memory is about 60s, **but only on the closing side.** It is lost
when:

- the closing side was not sampled (it was outside the selector);
- the connection was reset (`RST`) instead of closed: no `TIME_WAIT`;
- connection churn is high enough that the kernel drops or reuses `TIME_WAIT`
  entries early (`net.ipv4.tcp_max_tw_buckets`, `tcp_tw_reuse`).

Then the connection is seen only if it was open at a sample.

**UDP has no `TIME_WAIT`.** A UDP flow is visible only while a socket for it
exists at a sample instant. For UDP the interval *is* the memory.

### 2. Unconnected UDP has no peer

`/proc/net/udp` shows a remote address only for a **connected** UDP socket.
Most UDP servers (DNS servers, QUIC, syslog) use one unconnected socket for
every client: the table shows their local port and no peer, however much
traffic arrives. The end-to-end suite demonstrates this with busybox `dnsd`: a
client sends a datagram every second, and the server's table still shows
`0.0.0.0:5354`, no peer. Who talked to such a server can only be learned from
the client's side, and only if the client connected its socket. Many clients
do; a client that sends without connecting is invisible on both sides. This is
a property of the kernel interface, not a podpeers bug.

So capture the clients too. A client's connected socket names the server
(or its Service), and `podpeers suggest` uses that as the server's ingress
evidence: the server's policy admits the client, and the reasoning says the
rule rests on the client's side only. An early version ignored it: it refused
to write any policy for such a server ("no traffic at all was observed")
while the capture held the client's record of sending to it every second.
The end-to-end suite applies the policy and proves it with real datagrams:
the captured client gets through, a stranger does not. `podpeers suggest`
still names any unconnected UDP listener none of whose clients was
captured: a policy built from the capture drops all UDP to those ports.

### The DNS rule

DNS lookups are sub-second UDP exchanges that sampling rarely catches, so
`podpeers suggest` adds DNS egress whenever a workload makes outbound
connections (`--dns auto`), marked ASSUMED. The rule allows udp/53 and tcp/53
to the cluster DNS pods (`k8s-app=kube-dns` in `kube-system`) and nowhere
else. Measured with the rule applied: lookups through the cluster DNS work
over both protocols, while a query to any other DNS server on udp/53 and the
DNS pod's metrics port are blocked. With only that rule removed, a lookup gets
no answer and fails after the resolver's 5-second timeout ("connection timed
out; no servers could be reached"): every connection by name fails, and
connections by address keep working. `--dns never` leaves it out and says so.

### 3. Services hide the pod behind them, on the client side

Through a ClusterIP, kube-proxy rewrites the destination after the socket is
created, so the client's socket shows the Service's virtual IP. The client
side therefore names a **service**, not the pod that answered. The server's
side names the client pod, if the server was sampled. `podpeers suggest`
translates a Service peer to the Service's pod selector and target port. A
Service with no selector (manual endpoints, ExternalName, the API server)
cannot be followed and is reported as a gap.

### 4. No history

`/proc/net` describes the present. A connection that ended before the window
began left nothing to read, and so did anything that happens daily, weekly, on
deploy or on failover outside the window.

### 5. Only the selected pods

A connection is seen only from the pods the selector matched. If one end was
outside the selector, only the matched end's view exists, and the `TIME_WAIT`
memory may be on the other end. If neither end was matched, the connection is
not seen at all.

## Node traffic does not come from the node's IP

A process on a node (a host-network pod, the kubelet) that reaches a pod on
**another** node arrives from the node's address on the pod network, not
from its InternalIP. With flannel (k3s's default) that is the first address
of the node's pod range, the VXLAN interface. Measured on a two-node cluster:
a host-network client on the agent node reached a pod on the server node from
the `.0` address of the agent's pod range, not from the agent's node IP (a
different network altogether). A rule allowing the node by its IP would not
admit that traffic.

podpeers resolves an address inside a node's pod range (`spec.podCIDRs`) that
no pod held to that node, marked "pod network", and writes the rule for the
address it actually saw. `podpeers suggest` says what that address is. The
end-to-end suite applies such a rule and shows it admits the node's traffic,
and that removing it blocks that traffic. One caution: a pod that existed only
between podpeers' two inventories also leaves an unknown address in a pod
range, and is reported as the node.

## Busy pods and log size

Each sample is written to the debug container's log: about 155 bytes per
socket per sample (a pod holding 350 sockets writes about 55KB per sample).
The kubelet rotates container logs at 10Mi by default, so a busy pod's log
rotates within minutes. At the 1s default, any pod with more than about 225
sockets passes 10Mi within a 5-minute window. A log read only at the end
would have lost everything before the rotation; an early version did exactly
that and failed the pod outright.

podpeers therefore **follows each sampler's log while the capture runs** and
parses it as it arrives, so rotation loses nothing. The end-to-end suite
proves it on a pod whose log rotates mid-capture: 301 of 301 samples. If a
stream breaks, podpeers falls back to reading what is left. Every sample line
carries its own time anchor, so the surviving samples are still usable. The
pod is reported as observed but **not complete**, with the reason ("only the
latest samples survived").

## Choosing the window and the interval

**The window matters far more than the interval.** A peer contacted once an
hour is missed by a 60-second window at *any* interval. Going from a 1-minute
window to a 10-minute one buys more than going from 5s to 100ms. For a policy
you intend to enforce, capture across the workload's busiest and rarest
operations; `podpeers suggest` warns when the window is shorter than
`--min-window` (default 24h).

**The interval matters less than it looks for TCP**, because of `TIME_WAIT`
on the closing side (above). **For UDP it is the whole story**: a shorter
interval directly catches more short UDP exchanges.

**Shorter intervals cost CPU on the pods' nodes.** Each sample starts two
processes in the debug container (one `cat`, one `sleep`). Measured with the
kubelet's per-container CPU accounting (k3s, arm64, an idle pod, 70s captures):

| sampler | interval | CPU per probed pod | samples in 70s (expected) |
|---|---|---|---|
| v1 (until 678eadb: `date` + 4 `cat` per sample) | 5s | 1.3 millicores | 15 (15) |
| v1 | 1s | 10.3 millicores | 70 (71) |
| current | **1s (default)** | **6.2 millicores** | 71 (71) |
| current | 200ms | 27.4 millicores | 351 (351) |
| current | 100ms | 55.7 millicores (5.6% of one core) | 701 (701) |

So about **6ms of CPU per sample**, per probed pod, on that pod's node.
Multiply by the number of pods a selector matches. podpeers prints the cost
whenever `--interval` is under 1s and refuses anything under 100ms. Samples
are scheduled on a fixed grid (an earlier version slept a fixed interval after
each sample and fell 6% behind at 100ms). Timestamps come from `/proc/uptime`,
so they resolve to 10ms, and the interval must be a whole number of 10ms.

The defaults are `--duration 5m` and `--interval 1s`:

- **5 minutes** long enough to see most steady-state traffic without making an
  interactive run unbearable; use much longer for anything you will enforce.
- **1 second**: a TCP connection open for longer than about a second is
  always seen; a shorter one is seen through `TIME_WAIT` when its closing
  side was sampled, and otherwise only with a probability of roughly its
  lifetime divided by the interval. UDP gets a 1-second memory. The cost is
  about 6 millicores of CPU per probed pod (measured).
- **Sub-second** is available (`--interval 200ms`) when UDP traffic matters
  more than node CPU. It is not the default.
