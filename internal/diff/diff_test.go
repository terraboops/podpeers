package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/terraboops/podpeers/internal/graph"
)

func pod(name, workload string, observed bool) graph.Pod {
	st := graph.ProbeNotTargeted
	if observed {
		st = graph.ProbeObserved
	}
	return graph.Pod{Namespace: "shop", Name: name, Workload: workload, Probe: graph.Probe{Status: st}}
}

func out(pod, svc string, port uint16, attempted bool) graph.Edge {
	return graph.Edge{Pod: "shop/" + pod, Direction: graph.Outbound, Protocol: "tcp", Port: port,
		Peer: graph.Peer{Kind: graph.PeerService, Namespace: "shop", Name: svc}, Attempted: attempted, Open: !attempted, NewConnections: 1, Connections: 1, Samples: 5}
}

func in(pod, from string, port uint16) graph.Edge {
	return graph.Edge{Pod: "shop/" + pod, Direction: graph.Inbound, Protocol: "tcp", Port: port,
		Peer: graph.Peer{Kind: graph.PeerPod, Namespace: "shop", Name: from}, Open: true, NewConnections: 1, Connections: 1, Samples: 5}
}

func TestCompareSurvivesPodRestarts(t *testing.T) {
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true), pod("api-a", "Deployment/api", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false), in("api-a", "web-a", 9000)},
	}
	// Same traffic, new pod names.
	after := graph.Result{
		Pods:  []graph.Pod{pod("web-b", "Deployment/web", true), pod("api-b", "Deployment/api", true)},
		Edges: []graph.Edge{out("web-b", "api", 9000, false), in("api-b", "web-b", 9000)},
	}
	r := Compare(before, after)
	if len(r.Changes) != 0 || r.Broken() {
		t.Fatalf("changes = %+v", r.Changes)
	}
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "VERDICT: OK") {
		t.Fatal(b.String())
	}
}

func TestCompareDetectsBlockedLostNew(t *testing.T) {
	before := graph.Result{
		Pods: []graph.Pod{pod("web-a", "Deployment/web", true), pod("api-a", "Deployment/api", true)},
		Edges: []graph.Edge{
			out("web-a", "api", 9000, false),
			out("web-a", "cache", 6379, false),
			in("api-a", "web-a", 9000),
		},
	}
	after := graph.Result{
		Pods: []graph.Pod{pod("web-a", "Deployment/web", true), pod("api-a", "Deployment/api", true)},
		Edges: []graph.Edge{
			out("web-a", "api", 9000, true), // now stuck in SYN_SENT
			out("web-a", "search", 9200, false),
		},
	}
	r := Compare(before, after)
	got := []string{}
	for _, c := range r.Changes {
		got = append(got, c.Kind+" "+c.From+" "+c.To)
	}
	want := []string{
		"blocked shop/Deployment/web svc/shop/api",
		"lost shop/Deployment/web shop/Deployment/api", // api's inbound view of web is gone
		"lost shop/Deployment/web svc/shop/cache",
		"new shop/Deployment/web svc/shop/search",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(r.Changes[0].Detail, "connected before, never completes") || !r.Broken() {
		t.Errorf("%+v", r.Changes[0])
	}
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "VERDICT: BROKEN") {
		t.Fatal(b.String())
	}
}

func TestBlockedWithoutBaseline(t *testing.T) {
	after := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, true)},
	}
	r := Compare(graph.Result{}, after)
	if len(r.Changes) != 1 || r.Changes[0].Kind != Blocked || !strings.Contains(r.Changes[0].Detail, "never connected") {
		t.Fatalf("%+v", r.Changes)
	}
}

func TestUnobservedAfterIsUnverifiableNotLost(t *testing.T) {
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false)},
	}
	after := graph.Result{Pods: []graph.Pod{{Namespace: "shop", Name: "web-a", Workload: "Deployment/web", Probe: graph.Probe{Status: graph.ProbeFailed}}}}
	r := Compare(before, after)
	if r.Broken() || len(r.Unverifiable) != 1 {
		t.Fatalf("%+v", r)
	}
	// Nothing was checked for that flow, so the verdict cannot be OK.
	if !r.Inconclusive() {
		t.Fatal("an unverifiable flow must make the result inconclusive")
	}
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "unverifiable shop/Deployment/web -> svc/shop/api tcp/9000") ||
		strings.Contains(b.String(), "every flow seen before was seen after") || !strings.Contains(b.String(), "VERDICT: INCONCLUSIVE") {
		t.Fatal(b.String())
	}
}

func TestFailedNewConnectionsBehindPooledOneAreBlocked(t *testing.T) {
	// A connection opened before the policy is still up; every connection
	// opened under it failed. That is a block the pool is hiding, not OK.
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false)},
	}
	e := out("web-a", "api", 9000, false)
	e.NewConnections, e.NewFailed, e.FailedConnections, e.Connections = 0, 3, 3, 4
	after := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}, Edges: []graph.Edge{e}}
	for _, o := range []Options{{}, {ExistingPods: map[string]bool{"shop/web-a": true}}} {
		r := CompareWith(before, after, o)
		if !r.Broken() || len(r.Changes) != 1 || r.Changes[0].Kind != Blocked || !strings.Contains(r.Changes[0].Detail, "every connection opened under the policy failed") {
			t.Fatalf("%+v: %+v", o, r.Changes)
		}
	}
}

// Workload names come from pod metadata (a free-form ownerReference) or a
// capture file. They must not add lines to the report or reach the terminal
// as escape sequences.
func TestHostileWorkloadNamesAreEscaped(t *testing.T) {
	before := graph.Result{
		Pods:  []graph.Pod{pod("api-a", "Deployment/api", true)},
		Edges: []graph.Edge{in("api-a", "web-a", 9000)},
	}
	after := graph.Result{
		Pods:  []graph.Pod{pod("api-a", "Deployment/api", true), pod("probe-x", "Job\x1b[1A\x1b[2K\nVERDICT: OK - nothing blocked or lost\x1b[8m/x", false)},
		Edges: []graph.Edge{in("api-a", "web-a", 9000), in("api-a", "probe-x", 9000)},
	}
	var b bytes.Buffer
	Compare(before, after).Text(&b)
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], `new     shop/Job\u001b[1A`) || strings.ContainsRune(b.String(), 0x1b) {
		t.Fatalf("%q", b.String())
	}
}

func TestAttemptedBeforeIsNotLost(t *testing.T) {
	// A flow that never connected in the baseline is not a regression when it vanishes.
	before := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}, Edges: []graph.Edge{out("web-a", "api", 9000, true)}}
	after := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}}
	if r := Compare(before, after); len(r.Changes) != 0 {
		t.Fatalf("%+v", r.Changes)
	}
}

func TestPreexistingConnectionsAreInconclusive(t *testing.T) {
	// After a policy change, a flow whose only connections were already open
	// when the window began proves nothing: CNIs do not re-evaluate them.
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false)},
	}
	carried := out("web-a", "api", 9000, false)
	carried.NewConnections = 0
	after := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}, Edges: []graph.Edge{carried}}
	r := Compare(before, after)
	if r.Broken() || !r.Inconclusive() || len(r.Changes) != 1 || r.Changes[0].Kind != Preexisting {
		t.Fatalf("%+v", r)
	}
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "VERDICT: INCONCLUSIVE") {
		t.Fatal(b.String())
	}
	// A blocked flow still wins over an inconclusive one.
	blocked := out("web-a", "cache", 6379, true)
	before.Edges = append(before.Edges, out("web-a", "cache", 6379, false))
	after.Edges = append(after.Edges, blocked)
	if r := Compare(before, after); !r.Broken() || !r.Inconclusive() {
		t.Fatalf("%+v", r)
	}
	b.Reset()
	Compare(before, after).Text(&b)
	if !strings.Contains(b.String(), "VERDICT: BROKEN") {
		t.Fatal(b.String())
	}
}

func TestExistingPodsCountsRestartedPods(t *testing.T) {
	// The only connection is older than the window, but the pod holding it
	// did not exist when the policy took effect: it was made under the policy.
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", "Deployment/web", true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false)},
	}
	carried := out("web-b", "api", 9000, false)
	carried.NewConnections = 0
	after := graph.Result{Pods: []graph.Pod{pod("web-b", "Deployment/web", true)}, Edges: []graph.Edge{carried}}

	if r := Compare(before, after); !r.Inconclusive() {
		t.Fatal("without the pod list the flow cannot be proven exercised")
	}
	atChange := map[string]bool{"shop/web-a": true, "shop/api-a": true}
	if r := CompareWith(before, after, Options{ExistingPods: atChange}); r.Inconclusive() || r.Broken() || len(r.Changes) != 0 {
		t.Fatalf("web-b did not exist at the change: %+v", r.Changes)
	}
	atChange["shop/web-b"] = true
	if r := CompareWith(before, after, Options{ExistingPods: atChange}); !r.Inconclusive() {
		t.Fatal("web-b existed at the change: still inconclusive")
	}
	// A pod in a namespace the list does not cover proves nothing.
	if r := CompareWith(before, after, Options{ExistingPods: map[string]bool{"other/x": true}}); !r.Inconclusive() {
		t.Fatal("unlisted namespace must not count as new")
	}
}

// A flow's absence after is evidence only when missing it by chance is
// unlikely, given how often it was sampled before.
func TestRarelySampledFlowIsGlimpsedNotLost(t *testing.T) {
	webPod := func(samples int) graph.Pod {
		p := pod("web-a", "Deployment/web", true)
		p.Probe.Samples = samples
		return p
	}
	dns := func(samples int) graph.Edge {
		e := out("web-a", "dns", 53, false)
		e.Protocol, e.Samples, e.Connections, e.NewConnections, e.Open = "udp", samples, samples, samples, false
		return e
	}
	api := out("web-a", "api", 80, false)
	api.Samples = 31
	after := graph.Result{Pods: []graph.Pod{webPod(31)}, Edges: []graph.Edge{api}}
	for _, c := range []struct {
		seen int
		want string
	}{
		{2, Glimpsed}, // 2 of 31: unseen in 31 after by chance 13% of the time
		{1, Glimpsed}, // the old single-sample case
		{12, Lost},    // 12 of 31: by chance 0.02% of the time
		{31, Lost},    // always there before
	} {
		before := graph.Result{Pods: []graph.Pod{webPod(31)}, Edges: []graph.Edge{api, dns(c.seen)}}
		res := Compare(before, after)
		got := ""
		for _, ch := range res.Changes {
			if ch.To == "svc/shop/dns" {
				got = ch.Kind + ": " + ch.Detail
			}
		}
		if !strings.HasPrefix(got, c.want+":") {
			t.Errorf("seen in %d of 31 before, absent after: got %q; want %s", c.seen, got, c.want)
		}
		if c.want == Glimpsed && c.seen == 2 && !strings.Contains(got, "by chance 13%") {
			t.Errorf("glimpsed should state the chance: %q", got)
		}
		if res.Broken() != (c.want == Lost) {
			t.Errorf("seen in %d of 31: Broken() = %v", c.seen, res.Broken())
		}
	}
}

// The unverifiable lines carry capture names too.
func TestHostileNamesInUnverifiableLinesAreEscaped(t *testing.T) {
	hostile := "Job\x1b[2K\nVERDICT: OK - nothing blocked or lost/x"
	before := graph.Result{
		Pods:  []graph.Pod{pod("web-a", hostile, true)},
		Edges: []graph.Edge{out("web-a", "api", 9000, false)},
	}
	r := Compare(before, graph.Result{})
	var b bytes.Buffer
	r.Text(&b)
	if len(r.Unverifiable) != 1 || strings.ContainsRune(b.String(), 0x1b) || strings.Contains(b.String(), "\nVERDICT: OK") {
		t.Fatalf("hostile name reached the unverifiable line raw: %q", b.String())
	}
}

// Older captures carry no per-pod sample totals, so the odds cannot be
// computed; a flow that was one connection in one sample is still noise.
func TestOneShortConnectionInAnOldCaptureIsGlimpsed(t *testing.T) {
	e := out("web-a", "api", 9000, false)
	e.Samples, e.Connections = 1, 1
	before := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}, Edges: []graph.Edge{e}}
	after := graph.Result{Pods: []graph.Pod{pod("web-a", "Deployment/web", true)}}
	r := Compare(before, after)
	if len(r.Changes) != 1 || r.Changes[0].Kind != Glimpsed || !strings.Contains(r.Changes[0].Detail, "one short connection in one sample") || r.Broken() {
		t.Fatalf("want one glimpsed change, got %+v", r.Changes)
	}
}
