package graph

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/terraboops/podpeers/internal/procnet"
)

// All addresses are documentation ranges; all names are invented.
var (
	t0  = time.Unix(1700000000, 0).UTC()
	inv = Inventory{
		Pods: []Pod{
			{Namespace: "shop", Name: "api", IP: "192.0.2.10"},
			{Namespace: "shop", Name: "web", IP: "192.0.2.11"},
			{Namespace: "edge", Name: "gateway", IP: "192.0.2.12"},
			{Namespace: "kube-system", Name: "agent", IP: "198.51.100.1", HostNetwork: true},
		},
		Services: []Service{
			{Namespace: "shop", Name: "api", ClusterIPs: []string{"192.0.2.200"}},
			{Namespace: "shop", Name: "unused", ClusterIPs: []string{"192.0.2.201"}},
		},
		Nodes: []Node{{Name: "node-a", IPs: []string{"198.51.100.1"}}},
	}
)

func sock(proto procnet.Protocol, local, remote string, st procnet.State) procnet.Socket {
	return procnet.Socket{Protocol: proto, Local: netip.MustParseAddrPort(local), Remote: netip.MustParseAddrPort(remote), State: st}
}

func listen(port string) procnet.Socket {
	return sock(procnet.TCP, "0.0.0.0:"+port, "0.0.0.0:0", procnet.Listen)
}

func sample(sec int, socks ...procnet.Socket) procnet.Sample {
	return procnet.Sample{Time: t0.Add(time.Duration(sec) * time.Second), Sockets: socks}
}

func TestResolver(t *testing.T) {
	r := NewResolver(inv)
	cases := map[string]Peer{
		"192.0.2.10":        {Kind: PeerPod, Namespace: "shop", Name: "api", IP: "192.0.2.10"},
		"::ffff:192.0.2.11": {Kind: PeerPod, Namespace: "shop", Name: "web", IP: "192.0.2.11"},
		"192.0.2.200":       {Kind: PeerService, Namespace: "shop", Name: "api", IP: "192.0.2.200"},
		"198.51.100.1":      {Kind: PeerNode, Name: "node-a", IP: "198.51.100.1"}, // hostNetwork pod resolves to node
		"203.0.113.9":       {Kind: PeerExternal, IP: "203.0.113.9"},
		"2001:db8::1":       {Kind: PeerExternal, IP: "2001:db8::1"},
	}
	for ip, want := range cases {
		if got := r.Resolve(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Resolve(%s) = %+v; want %+v", ip, got, want)
		}
	}
}

func TestPeerID(t *testing.T) {
	if (Peer{Kind: PeerPod, Namespace: "a", Name: "b"}).ID() != "a/b" ||
		(Peer{Kind: PeerService, Namespace: "a", Name: "b"}).ID() != "svc/a/b" ||
		(Peer{Kind: PeerNode, Name: "n"}).ID() != "node/n" ||
		(Peer{Kind: PeerExternal, IP: "203.0.113.1"}).ID() != "203.0.113.1" {
		t.Fatal("Peer.ID mismatch")
	}
}

func TestAnalyzeDirectionAndAggregation(t *testing.T) {
	r := NewResolver(inv)
	samples := []procnet.Sample{
		sample(0,
			listen("9000"),
			sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.11:40001", procnet.Established), // inbound from web
			sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.11:40002", procnet.Established), // second conn, same edge
			sock(procnet.TCP, "192.0.2.10:51000", "203.0.113.9:443", procnet.Established), // outbound external
			sock(procnet.TCP, "127.0.0.1:9000", "127.0.0.1:51111", procnet.Established),   // loopback: ignored
		),
		sample(5,
			listen("9000"),
			sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.11:40001", procnet.Established),
			sock(procnet.TCP, "192.0.2.10:51000", "203.0.113.9:443", procnet.TimeWait), // closing
		),
		sample(10,
			listen("9000"),
			sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.11:40001", procnet.Established),
		),
	}
	ls, es := Analyze("shop/api", samples, r)
	if len(ls) != 1 || ls[0] != (Listener{"tcp", "0.0.0.0", 9000}) {
		t.Fatalf("listeners = %+v", ls)
	}
	if len(es) != 2 {
		t.Fatalf("edges = %+v", es)
	}
	in, out := es[0], es[1]
	if in.Direction != Inbound || in.Peer.ID() != "shop/web" || in.Port != 9000 || in.Connections != 2 ||
		in.Samples != 3 || !in.Open || !in.FirstSeen.Equal(t0) || !in.LastSeen.Equal(t0.Add(10*time.Second)) {
		t.Errorf("inbound edge = %+v", in)
	}
	if out.Direction != Outbound || out.Peer.Kind != PeerExternal || out.Port != 443 || out.Connections != 1 ||
		out.Samples != 2 || out.Open || !out.LastSeen.Equal(t0.Add(5*time.Second)) {
		t.Errorf("outbound edge = %+v", out)
	}
}

func TestAnalyzeConnectionClosedButLingering(t *testing.T) {
	// A connection still present in the final sample but no longer ESTABLISHED
	// (TIME_WAIT on the side that closed) counts as closed during the window.
	r := NewResolver(inv)
	samples := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.Established)),
		sample(5, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.TimeWait)),
	}
	_, es := Analyze("shop/web", samples, r)
	if len(es) != 1 || es[0].Open || es[0].Peer.Kind != PeerService || es[0].Samples != 2 {
		t.Fatalf("edges = %+v", es)
	}
}

func TestAnalyzeNoPeers(t *testing.T) {
	r := NewResolver(inv)
	ls, es := Analyze("shop/idle", []procnet.Sample{sample(0), sample(5)}, r)
	if len(ls) != 0 || len(es) != 0 {
		t.Fatalf("idle pod produced listeners=%v edges=%v", ls, es)
	}
	ls, es = Analyze("shop/idle", nil, r)
	if len(ls) != 0 || len(es) != 0 {
		t.Fatal("no samples should produce nothing")
	}
}

func TestAnalyzeUDP(t *testing.T) {
	r := NewResolver(inv)
	samples := []procnet.Sample{sample(0,
		sock(procnet.UDP, "0.0.0.0:53", "0.0.0.0:0", procnet.Close),                  // UDP listener
		sock(procnet.UDP, "192.0.2.11:41000", "192.0.2.200:53", procnet.Established), // connected UDP client
		sock(procnet.UDP, "0.0.0.0:0", "0.0.0.0:0", procnet.Close),                   // unbound: ignored
	)}
	ls, es := Analyze("shop/web", samples, r)
	if len(ls) != 1 || ls[0].Protocol != "udp" || ls[0].Port != 53 {
		t.Fatalf("listeners = %+v", ls)
	}
	if len(es) != 1 || es[0].Direction != Outbound || es[0].Protocol != "udp" || es[0].Port != 53 || !es[0].Open {
		t.Fatalf("edges = %+v", es)
	}
}

func TestAnalyzeListenerOnlyMatchesSameProtocol(t *testing.T) {
	// A UDP listener on 53 must not make a TCP connection from local port 53 inbound.
	r := NewResolver(inv)
	samples := []procnet.Sample{sample(0,
		sock(procnet.UDP, "0.0.0.0:53", "0.0.0.0:0", procnet.Close),
		sock(procnet.TCP, "192.0.2.11:53", "192.0.2.10:9000", procnet.Established),
	)}
	_, es := Analyze("shop/web", samples, r)
	if len(es) != 1 || es[0].Direction != Outbound || es[0].Port != 9000 {
		t.Fatalf("edges = %+v", es)
	}
}

func TestAnalyzeListenerSeenInAnySample(t *testing.T) {
	// The listener only appears in sample 2; the earlier connection on that port
	// is still inbound because direction is decided with the whole window.
	r := NewResolver(inv)
	samples := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.11:40001", procnet.Established)),
		sample(5, listen("9000")),
	}
	_, es := Analyze("shop/api", samples, r)
	if len(es) != 1 || es[0].Direction != Inbound || es[0].Open {
		t.Fatalf("edges = %+v", es)
	}
}

func TestBuild(t *testing.T) {
	targets := []Pod{
		{Namespace: "shop", Name: "api", IP: "192.0.2.10", Probe: Probe{Status: ProbeObserved, Samples: 1, Complete: true}},
		{Namespace: "shop", Name: "stuck", Probe: Probe{Status: ProbeFailed, Reason: "ImagePullBackOff"}},
	}
	obs := []Observation{{Pod: "shop/api", Samples: []procnet.Sample{sample(0,
		listen("9000"),
		sock(procnet.TCP, "192.0.2.10:9000", "192.0.2.12:40001", procnet.Established),
		sock(procnet.TCP, "192.0.2.10:40002", "192.0.2.200:9000", procnet.Established),
	)}}}
	sel := Selector{Namespace: "shop", LabelSelector: "app"}
	win := Window{Start: t0, End: t0.Add(time.Minute), Interval: "5s"}
	res, err := Build(sel, win, inv, targets, obs)
	if err != nil {
		t.Fatal(err)
	}
	if res.Schema != Schema || res.Selector != sel || res.Window != win {
		t.Errorf("header = %+v %+v %+v", res.Schema, res.Selector, res.Window)
	}
	ids := []string{}
	for _, p := range res.Pods {
		ids = append(ids, p.ID()+":"+string(p.Probe.Status))
	}
	want := []string{"edge/gateway:not-targeted", "shop/api:observed", "shop/stuck:failed"}
	if len(ids) != len(want) {
		t.Fatalf("pods = %v", ids)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("pods = %v; want %v", ids, want)
		}
	}
	if res.Pods[1].Listening[0].Port != 9000 {
		t.Error("listener not recorded on pod")
	}
	if len(res.Services) != 1 || res.Services[0].ID() != "shop/api" {
		t.Errorf("only referenced services should be kept: %+v", res.Services)
	}
	if len(res.Edges) != 2 {
		t.Errorf("edges = %+v", res.Edges)
	}
}

func TestBuildRejectsInconsistentInput(t *testing.T) {
	win := Window{}
	dup := []Pod{{Namespace: "a", Name: "b"}, {Namespace: "a", Name: "b"}}
	if _, err := Build(Selector{}, win, inv, dup, nil); err == nil {
		t.Error("duplicate target should error")
	}
	if _, err := Build(Selector{}, win, inv, nil, []Observation{{Pod: "a/ghost"}}); err == nil {
		t.Error("observation of untargeted pod should error")
	}
}

func TestAnalyzeAttemptedOnly(t *testing.T) {
	// A client stuck in SYN_SENT across the window: tried, never connected.
	r := NewResolver(inv)
	samples := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.SynSent)),
		sample(5, sock(procnet.TCP, "192.0.2.11:40002", "192.0.2.200:9000", procnet.SynSent)),
	}
	_, es := Analyze("shop/web", samples, r)
	if len(es) != 1 || !es[0].Attempted || es[0].Open || es[0].Connections != 2 {
		t.Fatalf("edges = %+v", es)
	}
	// A connect() refused by a REJECT rule leaves the socket in CLOSE: still
	// never connected.
	rejected := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.Close)),
		sample(5, sock(procnet.TCP, "192.0.2.11:40002", "192.0.2.200:9000", procnet.SynSent)),
	}
	if _, es := Analyze("shop/web", rejected, r); !es[0].Attempted {
		t.Fatalf("rejected connects should be attempted-only: %+v", es)
	}
	// Connections closed before the window (TIME_WAIT leftovers) plus new
	// connects that never complete: still blocked now.
	mixed := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.TimeWait),
			sock(procnet.TCP, "192.0.2.11:40005", "192.0.2.200:9000", procnet.SynSent)),
		sample(5, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.TimeWait),
			sock(procnet.TCP, "192.0.2.11:40006", "192.0.2.200:9000", procnet.Close)),
	}
	if _, es := Analyze("shop/web", mixed, r); !es[0].Attempted || es[0].FailedConnections != 2 || es[0].Connections != 3 {
		t.Fatalf("TIME_WAIT leftovers must not mask new failures: %+v", es)
	}
	// Short connections only ever caught in TIME_WAIT did succeed.
	short := []procnet.Sample{sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.TimeWait))}
	if _, es := Analyze("shop/web", short, r); es[0].Attempted || es[0].FailedConnections != 0 {
		t.Fatalf("TIME_WAIT-only is a completed connection: %+v", es)
	}
	// Once any connection on the edge got through, it is not "attempted".
	samples = append(samples, sample(10, sock(procnet.TCP, "192.0.2.11:40003", "192.0.2.200:9000", procnet.Established)))
	_, es = Analyze("shop/web", samples, r)
	if es[0].Attempted || !es[0].Open {
		t.Fatalf("edges = %+v", es)
	}
}

func TestFlowsAndWorkloadID(t *testing.T) {
	r := Result{Edges: []Edge{
		{Pod: "shop/api", Direction: Inbound, Peer: Peer{Kind: PeerPod, Namespace: "shop", Name: "web"}, Port: 9000, Protocol: "tcp", Open: true},
		{Pod: "shop/web", Direction: Outbound, Peer: Peer{Kind: PeerService, Namespace: "shop", Name: "api"}, Port: 9000, Protocol: "tcp", Attempted: true},
	}}
	fs := r.Flows()
	if fs[0].From != "shop/web" || fs[0].To != "shop/api" || fs[1].From != "shop/web" || fs[1].To != "svc/shop/api" || !fs[1].Attempted {
		t.Fatalf("flows = %+v", fs)
	}
	if (Pod{Namespace: "a", Name: "p"}).WorkloadID() != "a/Pod/p" || (Pod{Namespace: "a", Name: "p", Workload: "Deployment/d"}).WorkloadID() != "a/Deployment/d" {
		t.Fatal("WorkloadID")
	}
}

func TestLoadRejectsGarbage(t *testing.T) {
	if _, err := Load(strings.NewReader("not json")); err == nil {
		t.Error("garbage should fail")
	}
	if _, err := LoadFile("/does/not/exist"); err == nil {
		t.Error("missing file should fail")
	}
}

func TestNewConnections(t *testing.T) {
	r := NewResolver(inv)
	samples := []procnet.Sample{
		sample(0, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.Established)), // predates the window
		sample(5, sock(procnet.TCP, "192.0.2.11:40001", "192.0.2.200:9000", procnet.Established),
			sock(procnet.TCP, "192.0.2.11:40002", "192.0.2.200:9000", procnet.Established)), // opened during it
	}
	_, es := Analyze("shop/web", samples, r)
	if es[0].Connections != 2 || es[0].NewConnections != 1 {
		t.Fatalf("%+v", es[0])
	}
	_, es = Analyze("shop/web", samples[:1], r)
	if es[0].NewConnections != 0 {
		t.Fatalf("a single sample has nothing new: %+v", es[0])
	}
}
