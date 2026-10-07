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
	var b bytes.Buffer
	r.Text(&b)
	if !strings.Contains(b.String(), "unverifiable shop/Deployment/web -> svc/shop/api tcp/9000") {
		t.Fatal(b.String())
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
