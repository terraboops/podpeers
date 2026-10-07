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

`podpeers suggest` names unconnected UDP listeners explicitly: unless their
clients were captured from the client side, a policy built from the capture
drops all UDP to those ports.

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
processes in the debug container (one `cat`, one `sleep`). At 1s that is 2 per
second per pod; at 100ms, 20 per second per pod, on every probed pod's node.
podpeers prints that cost whenever `--interval` is under 1s and refuses
anything under 100ms. Timestamps come from `/proc/uptime`, so they resolve to
10ms.

The defaults are `--duration 5m` and `--interval 1s`:

- **5 minutes** long enough to see most steady-state traffic without making an
  interactive run unbearable; use much longer for anything you will enforce.
- **1 second**: a TCP connection open for longer than about a second is
  always seen; a shorter one is seen through `TIME_WAIT` when its closing
  side was sampled, and otherwise only with a probability of roughly its
  lifetime divided by the interval. UDP gets a 1-second memory. The cost is
  2 process starts per second per pod.
- **Sub-second** is available (`--interval 200ms`) when UDP traffic matters
  more than node CPU. It is not the default.
