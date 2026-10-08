package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"

	netv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"

	"github.com/terraboops/podpeers/internal/graph"
)

// All names are invented; addresses are documentation ranges.
var t0 = time.Unix(1700000000, 0).UTC()

func obs(ns, name, workload string, labels map[string]string) graph.Pod {
	return graph.Pod{Namespace: ns, Name: name, Workload: workload, Labels: labels,
		Probe: graph.Probe{Status: graph.ProbeObserved, Samples: 30, Complete: true}}
}

func edge(pod string, dir graph.Direction, peer graph.Peer, port uint16) graph.Edge {
	return graph.Edge{Pod: pod, Direction: dir, Peer: peer, Port: port, Protocol: "tcp", Connections: 1,
		FirstSeen: t0, LastSeen: t0.Add(time.Minute), Samples: 30, Open: true}
}

func podPeer(ns, name string) graph.Peer {
	return graph.Peer{Kind: graph.PeerPod, Namespace: ns, Name: name, IP: "192.0.2.1"}
}

func svcPeer(ns, name string) graph.Peer {
	return graph.Peer{Kind: graph.PeerService, Namespace: ns, Name: name, IP: "192.0.2.200"}
}

// shop: web (2 replicas) -> svc api:80 -> api pods :http(8080); gateway in
// another namespace -> web:8080; api -> external 203.0.113.9:443.
func shop() graph.Result {
	apiL := map[string]string{"app": "api", "tier": "back"}
	webL := func(h string) map[string]string {
		return map[string]string{"app": "web", "tier": "front", "pod-template-hash": h, "statefulset.kubernetes.io/pod-name": h}
	}
	api := obs("shop", "api-1", "Deployment/api", apiL)
	api.Listening = []graph.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080}, {Protocol: "tcp", Address: "0.0.0.0", Port: 9090}}
	web1, web2 := obs("shop", "web-a", "Deployment/web", webL("a")), obs("shop", "web-b", "Deployment/web", webL("b"))
	web1.Listening = []graph.Listener{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080}}
	gw := graph.Pod{Namespace: "edge", Name: "gateway-x", Workload: "Deployment/gateway", Labels: map[string]string{"app": "gateway"},
		Probe: graph.Probe{Status: graph.ProbeNotTargeted}}
	return graph.Result{
		Schema: graph.Schema,
		Window: graph.Window{Start: t0, End: t0.Add(10 * time.Minute), Interval: "5s"},
		Pods:   []graph.Pod{api, gw, web1, web2},
		Services: []graph.Service{{Namespace: "shop", Name: "api", Selector: map[string]string{"app": "api"},
			Ports: []graph.ServicePort{{Protocol: "tcp", Port: 80, TargetPort: "http"}}}},
		Edges: []graph.Edge{
			edge("shop/api-1", graph.Inbound, podPeer("shop", "web-a"), 8080),
			edge("shop/api-1", graph.Inbound, podPeer("shop", "web-b"), 8080),
			edge("shop/api-1", graph.Outbound, graph.Peer{Kind: graph.PeerExternal, IP: "203.0.113.9"}, 443),
			edge("shop/web-a", graph.Inbound, podPeer("edge", "gateway-x"), 8080),
			edge("shop/web-a", graph.Outbound, svcPeer("shop", "api"), 80),
			edge("shop/web-b", graph.Outbound, svcPeer("shop", "api"), 80),
		},
	}
}

func find(t *testing.T, rep Report, workload string) Suggestion {
	t.Helper()
	for _, s := range rep.Suggestions {
		if s.Workload == workload {
			return s
		}
	}
	t.Fatalf("no suggestion for %s in %+v", workload, rep.Suggestions)
	return Suggestion{}
}

func hasGap(s Suggestion, sub string) bool {
	for _, g := range s.Gaps {
		if strings.Contains(g, sub) {
			return true
		}
	}
	return false
}

func TestSuggestShop(t *testing.T) {
	rep := Suggest(shop(), Options{})
	if len(rep.Suggestions) != 2 {
		t.Fatalf("want api and web (gateway was not targeted), got %+v", rep.Suggestions)
	}

	web := find(t, rep, "Deployment/web")
	if web.Refused != "" || web.Policy == nil {
		t.Fatalf("web refused: %s", web.Refused)
	}
	// Volatile per-pod labels are dropped; the selector is what both pods share.
	if selectorString(web.Selector) != "app=web,tier=front" {
		t.Errorf("web selector = %v", web.Selector)
	}
	sp := web.Policy.Spec
	if len(sp.PolicyTypes) != 2 || sp.PodSelector.MatchLabels["app"] != "web" {
		t.Errorf("spec = %+v", sp)
	}
	// ingress[0]: gateway pods in namespace edge on 8080.
	if len(sp.Ingress) != 1 {
		t.Fatalf("ingress = %+v", sp.Ingress)
	}
	in := sp.Ingress[0].From[0]
	if in.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != "edge" || in.PodSelector.MatchLabels["app"] != "gateway" ||
		sp.Ingress[0].Ports[0].Port.IntValue() != 8080 {
		t.Errorf("ingress rule = %+v", sp.Ingress[0])
	}
	// egress[0]: service api translated to its selector and NAMED target port.
	if len(sp.Egress) != 2 {
		t.Fatalf("egress = %+v", sp.Egress)
	}
	eg := sp.Egress[0]
	if eg.To[0].PodSelector.MatchLabels["app"] != "api" || eg.To[0].NamespaceSelector != nil || eg.Ports[0].Port.String() != "http" {
		t.Errorf("service egress = %+v", eg)
	}
	// egress[1]: DNS, flagged as an assumption.
	dns := sp.Egress[1]
	if dns.To[0].PodSelector.MatchLabels["k8s-app"] != "kube-dns" || len(dns.Ports) != 2 {
		t.Errorf("dns egress = %+v", dns)
	}
	if r := web.Reasons[2]; !r.Assumed || r.Rule != "egress[1]" || !strings.Contains(r.Evidence[0], "ASSUMED") {
		t.Errorf("dns reason = %+v", r)
	}
	if r := web.Reasons[1]; len(r.Evidence) != 2 || !strings.Contains(r.Evidence[0], "service port 80 -> target port http") {
		t.Errorf("service reason should cite both pods' evidence: %+v", r)
	}
	if !hasGap(web, "LOSE") || !hasGap(web, "every address outside the cluster") || !hasGap(web, "Kubernetes API server") {
		t.Errorf("web gaps = %v", web.Gaps)
	}

	api := find(t, rep, "Deployment/api")
	sa := api.Policy.Spec
	if len(sa.Ingress) != 1 || sa.Ingress[0].From[0].PodSelector.MatchLabels["app"] != "web" || sa.Ingress[0].From[0].NamespaceSelector != nil {
		t.Errorf("api ingress = %+v", sa.Ingress)
	}
	if len(api.Reasons[0].Evidence) != 2 {
		t.Errorf("both web pods' connections should be cited: %+v", api.Reasons[0])
	}
	if sa.Egress[0].To[0].IPBlock.CIDR != "203.0.113.9/32" || sa.Egress[0].Ports[0].Port.IntValue() != 443 {
		t.Errorf("api external egress = %+v", sa.Egress)
	}
	if !hasGap(api, "tcp/9090") || !hasGap(api, "DROPPED") {
		t.Errorf("unused listener 9090 must be reported: %v", api.Gaps)
	}
	if !hasGap(api, "single address 203.0.113.9/32") {
		t.Errorf("external egress should warn about staleness: %v", api.Gaps)
	}
	if hasGap(api, "every address outside the cluster") {
		t.Error("api did contact an external address")
	}
}

func TestReportGaps(t *testing.T) {
	rep := Suggest(shop(), Options{})
	joined := strings.Join(rep.Gaps, "\n")
	for _, want := range []string{"Observation window: 10m0s", "one sample every 5s", "stay unrestricted", "shorter than 24h0m0s"} {
		if !strings.Contains(joined, want) {
			t.Errorf("report gaps missing %q:\n%s", want, joined)
		}
	}
	rep = Suggest(shop(), Options{MinWindow: time.Minute})
	if strings.Contains(strings.Join(rep.Gaps, "\n"), "The window (") {
		t.Error("long enough window should not warn")
	}
}

func TestYAMLIsApplyReady(t *testing.T) {
	y, err := Suggest(shop(), Options{}).YAML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(y, "creationTimestamp") {
		t.Error("YAML should not carry server-side fields")
	}
	docs := strings.Split(y, "\n---\n")
	var policies []netv1.NetworkPolicy
	for _, d := range docs[1:] {
		var np netv1.NetworkPolicy
		if err := yaml.UnmarshalStrict([]byte(d), &np); err != nil {
			t.Fatalf("document does not parse as a NetworkPolicy: %v\n%s", err, d)
		}
		policies = append(policies, np)
	}
	if len(policies) != 2 || policies[0].Name != "podpeers-api" || policies[1].Name != "podpeers-web" ||
		policies[0].Kind != "NetworkPolicy" || policies[0].APIVersion != "networking.k8s.io/v1" {
		t.Fatalf("policies = %+v", policies)
	}
	for _, want := range []string{"# WHY each rule exists:", "#   egress[1] allows cluster DNS", "# NOT COVERED by this observation:", "ASSUMED"} {
		if !strings.Contains(y, want) {
			t.Errorf("yaml missing %q", want)
		}
	}
	for _, line := range strings.Split(y, "\n") {
		if strings.HasPrefix(line, "#") && len(line) > 110 {
			t.Errorf("comment not wrapped: %q", line)
		}
	}
}

func TestAttemptedTrafficIsNotAllowed(t *testing.T) {
	r := shop()
	r.Edges[4].Attempted, r.Edges[4].Open = true, false
	r.Edges[5].Attempted, r.Edges[5].Open = true, false
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	for _, e := range web.Policy.Spec.Egress {
		if e.To[0].PodSelector != nil && e.To[0].PodSelector.MatchLabels["app"] == "api" {
			t.Fatal("half-open attempt must not become an allow rule")
		}
	}
	if !hasGap(web, "half-open (SYN_SENT)") {
		t.Errorf("gaps = %v", web.Gaps)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*graph.Result)
		want   string
	}{
		{"no pod observed", func(r *graph.Result) {
			r.Pods[0].Probe = graph.Probe{Status: graph.ProbeFailed, Reason: "forbidden"}
		}, "no pod of this workload was observed"},
		{"too few samples", func(r *graph.Result) { r.Pods[0].Probe.Samples = 2 }, "only 2 sample(s)"},
		{"no labels", func(r *graph.Result) { r.Pods[0].Labels = map[string]string{"pod-template-hash": "x"} }, "share no stable labels"},
		{"hostNetwork", func(r *graph.Result) { r.Pods[0].HostNetwork = true }, "hostNetwork"},
		{"no traffic", func(r *graph.Result) { *r = withoutAPITraffic(*r) }, "no traffic at all was observed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := shop()
			c.mutate(&r)
			api := find(t, Suggest(r, Options{}), "Deployment/api")
			if api.Policy != nil || !strings.Contains(api.Refused, c.want) {
				t.Fatalf("refused=%q policy=%v", api.Refused, api.Policy != nil)
			}
		})
	}
	// Refusals still render, as comments only.
	r := shop()
	r.Pods[0].Probe.Samples = 1
	y, _ := Suggest(r, Options{}).YAML()
	if !strings.Contains(y, "# NO POLICY SUGGESTED: pod api-1 has only 1 sample(s)") || strings.Contains(y, "name: podpeers-api") {
		t.Fatalf("yaml:\n%s", y)
	}
}

func TestAllowEmptyEmitsDenyAll(t *testing.T) {
	r := withoutAPITraffic(shop())
	api := find(t, Suggest(r, Options{AllowEmpty: true}), "Deployment/api")
	if api.Policy == nil || len(api.Policy.Spec.Ingress) != 0 || len(api.Policy.Spec.Egress) != 0 {
		t.Fatalf("want deny-all, got %+v", api)
	}
	if !hasGap(api, "denies ALL ingress") || !hasGap(api, "DNS") {
		t.Errorf("gaps = %v", api.Gaps)
	}
}

func TestPartialObservationIsReported(t *testing.T) {
	r := shop()
	r.Pods[3].Probe = graph.Probe{Status: graph.ProbeFailed, Reason: "ImagePullBackOff"}
	r.Pods[2].Probe.Complete = false
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	if web.Policy == nil || !hasGap(web, "web-b was not observed (ImagePullBackOff)") || !hasGap(web, "web-a's sampler did not run its whole window") {
		t.Fatalf("gaps = %v", web.Gaps)
	}
}

func TestServicesNetworkPolicyCannotFollow(t *testing.T) {
	r := shop()
	r.Services = append(r.Services,
		graph.Service{Namespace: "default", Name: "kubernetes", Ports: []graph.ServicePort{{Protocol: "tcp", Port: 443, TargetPort: "6443"}}},
		graph.Service{Namespace: "shop", Name: "noport", Selector: map[string]string{"app": "x"}})
	r.Edges = append(r.Edges,
		edge("shop/web-a", graph.Outbound, svcPeer("default", "kubernetes"), 443),
		edge("shop/web-a", graph.Outbound, svcPeer("shop", "noport"), 81),
		edge("shop/web-a", graph.Outbound, svcPeer("shop", "ghost"), 82))
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	if len(web.Policy.Spec.Egress) != 2 {
		t.Errorf("unexpressible services must not become rules: %+v", web.Policy.Spec.Egress)
	}
	for _, want := range []string{"default/kubernetes has no pod selector", "no tcp/81 port", "shop/ghost is not in the capture"} {
		if !hasGap(web, want) {
			t.Errorf("missing gap %q in %v", want, web.Gaps)
		}
	}
	if hasGap(web, "Kubernetes API server (if") {
		t.Error("API server was contacted; should not be listed as lost")
	}
}

func TestPeerWithoutLabels(t *testing.T) {
	r := shop()
	r.Pods[1].Labels = nil // gateway
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	if len(web.Policy.Spec.Ingress) != 0 || !hasGap(web, "edge/gateway-x has no stable labels") {
		t.Fatalf("ingress=%+v gaps=%v", web.Policy.Spec.Ingress, web.Gaps)
	}
}

func TestNodeAndExternalIngress(t *testing.T) {
	r := shop()
	r.Edges = append(r.Edges,
		edge("shop/api-1", graph.Inbound, graph.Peer{Kind: graph.PeerNode, Name: "node-a", IP: "198.51.100.1"}, 8080),
		edge("shop/api-1", graph.Inbound, graph.Peer{Kind: graph.PeerExternal, IP: "2001:db8::7"}, 8080),
		edge("shop/api-1", graph.Inbound, graph.Peer{Kind: graph.PeerNode, Name: "node-b", IP: "198.51.100.128", PodRange: true}, 8080),
		edge("shop/api-1", graph.Outbound, graph.Peer{Kind: graph.PeerNode, Name: "node-a", IP: "198.51.100.1"}, 7100))
	api := find(t, Suggest(r, Options{}), "Deployment/api")
	cidrs := map[string]bool{}
	for _, in := range api.Policy.Spec.Ingress {
		if in.From[0].IPBlock != nil {
			cidrs[in.From[0].IPBlock.CIDR] = true
		}
	}
	if !cidrs["198.51.100.1/32"] || !cidrs["2001:db8::7/128"] || !cidrs["198.51.100.128/32"] {
		t.Fatalf("cidrs = %v", cidrs)
	}
	if !hasGap(api, "node IPs change") || !hasGap(api, "did not resolve to any pod") {
		t.Errorf("gaps = %v", api.Gaps)
	}
	// The node's pod-network address is named as the node, and says why.
	if !hasGap(api, "Ingress from node node-b on its pod network (198.51.100.128/32)") || !hasGap(api, "no pod held it") {
		t.Errorf("pod-range node gap missing: %v", api.Gaps)
	}
	// A node is not "an external endpoint behind DNS".
	if !hasGap(api, "Egress to node node-a (198.51.100.1/32) is allowed") {
		t.Errorf("node egress gap missing: %v", api.Gaps)
	}
	for _, g := range api.Gaps {
		if strings.Contains(g, "node") && strings.Contains(g, "CDNs") {
			t.Errorf("node egress described as an external endpoint: %q", g)
		}
	}
}

func TestDNSModes(t *testing.T) {
	never := find(t, Suggest(shop(), Options{DNS: DNSNever}), "Deployment/web")
	for _, e := range never.Policy.Spec.Egress {
		if e.To[0].PodSelector.MatchLabels["k8s-app"] == "kube-dns" {
			t.Fatal("--dns=never added DNS")
		}
	}
	if !hasGap(never, "name resolution will fail") {
		t.Errorf("gaps = %v", never.Gaps)
	}
	// An ingress-only workload gets no DNS rule under auto, but does under always.
	r := shop()
	r.Edges = []graph.Edge{r.Edges[0]}
	if api := find(t, Suggest(r, Options{}), "Deployment/api"); len(api.Policy.Spec.Egress) != 0 {
		t.Errorf("auto added egress to ingress-only workload: %+v", api.Policy.Spec.Egress)
	}
	api := find(t, Suggest(r, Options{DNS: DNSAlways}), "Deployment/api")
	if len(api.Policy.Spec.Egress) != 1 {
		t.Fatalf("always should add DNS: %+v", api.Policy.Spec.Egress)
	}
	// The DNS rule reaches the cluster DNS pods only: port 53 anywhere would
	// let a workload query (or tunnel through) any DNS server.
	dns := api.Policy.Spec.Egress[0]
	to := dns.To[0]
	ok := to.IPBlock == nil && to.NamespaceSelector != nil && to.PodSelector != nil &&
		to.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == "kube-system" &&
		to.PodSelector.MatchLabels["k8s-app"] == "kube-dns" && len(dns.Ports) == 2
	if !ok {
		t.Errorf("DNS rule must reach only the cluster DNS pods on udp/53 and tcp/53; got %+v", dns)
	}
}

func TestFilters(t *testing.T) {
	if rep := Suggest(shop(), Options{Namespace: "edge"}); len(rep.Suggestions) != 0 {
		t.Error("gateway is not targeted, so namespace edge has nothing to suggest")
	}
	rep := Suggest(shop(), Options{Workload: "Deployment/api"})
	if len(rep.Suggestions) != 1 || rep.Suggestions[0].Workload != "Deployment/api" {
		t.Fatalf("%+v", rep.Suggestions)
	}
	rep = Suggest(shop(), Options{Namespace: "nope"})
	if len(rep.Suggestions) != 0 || !strings.Contains(strings.Join(rep.Gaps, " "), "nothing to suggest") {
		t.Fatal("empty scope should say so")
	}
}

func TestBarePodWorkload(t *testing.T) {
	// Captures from bare pods (no controller) have no Workload field.
	r := shop()
	r.Pods[0].Workload = ""
	s := find(t, Suggest(r, Options{}), "Pod/api-1")
	if s.Policy == nil || s.Policy.Name != "podpeers-api-1" {
		t.Fatalf("%+v", s)
	}
}

func TestPolicyName(t *testing.T) {
	if n := policyName("Deployment/Web"); n != "podpeers-web" {
		t.Error(n)
	}
	long := policyName("StatefulSet/" + strings.Repeat("a", 80))
	if len(long) > 63 || !strings.HasPrefix(long, "podpeers-aaa") {
		t.Error(long)
	}
}

func TestCommonLabels(t *testing.T) {
	got := commonLabels([]graph.Pod{
		{Labels: map[string]string{"app": "x", "v": "1", "job-name": "j-1"}},
		{Labels: map[string]string{"app": "x", "v": "2", "job-name": "j-2"}},
	})
	if selectorString(got) != "app=x" {
		t.Fatalf("%v", got)
	}
	if commonLabels(nil) != nil || selectorString(nil) != "{}" {
		t.Fatal("empty")
	}
}

func TestObservedDNSIsWidenedNotDuplicated(t *testing.T) {
	r := shop()
	r.Services = append(r.Services, graph.Service{Namespace: "kube-system", Name: "kube-dns",
		Selector: map[string]string{"k8s-app": "kube-dns"}, Ports: []graph.ServicePort{{Protocol: "udp", Port: 53, TargetPort: "53"}}})
	dns := edge("shop/web-a", graph.Outbound, svcPeer("kube-system", "kube-dns"), 53)
	dns.Protocol = "udp"
	r.Edges = append([]graph.Edge{dns}, r.Edges...)
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	n := 0
	for _, e := range web.Policy.Spec.Egress {
		if e.To[0].PodSelector.MatchLabels["k8s-app"] == "kube-dns" {
			n++
			if len(e.Ports) != 2 {
				t.Errorf("observed DNS rule should cover udp and tcp: %+v", e.Ports)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want exactly one DNS rule, got %d: %+v", n, web.Policy.Spec.Egress)
	}
	for _, r := range web.Reasons {
		if strings.Contains(r.Peer, "kube-dns") && (r.Assumed || !strings.Contains(strings.Join(r.Evidence, " "), "tcp/53 ASSUMED")) {
			t.Errorf("observed DNS rule should cite the observation and flag tcp as assumed: %+v", r)
		}
	}
}

func TestEntryPointOnlySeenFromCompletedPods(t *testing.T) {
	// web's only client on 8080 is a helm test pod that has completed: the
	// policy would admit nothing but the test. That must be called out.
	r := shop()
	r.Pods[1].Phase = "Succeeded" // edge/gateway-x, web's only inbound client
	web := find(t, Suggest(r, Options{}), "Deployment/web")
	if !hasGap(web, "ENTRY POINT WARNING: ingress on tcp/8080") || !hasGap(web, "only from edge/gateway-x") || !hasGap(web, "SHUTS THEM OUT") {
		t.Fatalf("gaps = %v", web.Gaps)
	}
	// A running client on the same port means real traffic was seen: no warning.
	r.Pods[1].Phase = "Running"
	if web := find(t, Suggest(r, Options{}), "Deployment/web"); hasGap(web, "ENTRY POINT WARNING") {
		t.Fatalf("running client must not trigger the warning: %v", web.Gaps)
	}
	// Mixed clients (one completed, one running) on a port: no warning.
	r.Pods[1].Phase = "Succeeded"
	r.Pods = append(r.Pods, graph.Pod{Namespace: "edge", Name: "lb", Workload: "Deployment/lb", Labels: map[string]string{"app": "lb"}, Phase: "Running", Probe: graph.Probe{Status: graph.ProbeNotTargeted}})
	r.Edges = append(r.Edges, edge("shop/web-a", graph.Inbound, podPeer("edge", "lb"), 8080))
	if web := find(t, Suggest(r, Options{}), "Deployment/web"); hasGap(web, "ENTRY POINT WARNING") {
		t.Fatalf("a running client was also seen: %v", web.Gaps)
	}
	// Captures without phase information (older files) stay silent rather than guess.
	r = shop()
	if web := find(t, Suggest(r, Options{}), "Deployment/web"); hasGap(web, "ENTRY POINT WARNING") {
		t.Fatal("no phase information: no warning")
	}
}

func TestReportCarriesCaptureLimitsAndUDPListeners(t *testing.T) {
	r := shop()
	r.Pods[0].Listening = append(r.Pods[0].Listening, graph.Listener{Protocol: "udp", Address: "0.0.0.0", Port: 5353})
	rep := Suggest(r, Options{})
	joined := strings.Join(rep.Gaps, "\n")
	for _, want := range []string{"This is sampling, not capture", "CONNECTED socket", "ClusterIP", "No history"} {
		if !strings.Contains(joined, want) {
			t.Errorf("report gaps missing capture limit %q", want)
		}
	}
	api := find(t, rep, "Deployment/api")
	if !hasGap(api, "Listens on udp/5353: an unconnected UDP socket records no peer") || hasGap(api, "Listens on udp/5353 but no client") {
		t.Errorf("UDP listener gap wrong: %v", api.Gaps)
	}
}

// withoutAPITraffic removes every record of api's traffic, from both ends:
// api's own edges and its clients' edges to it.
func withoutAPITraffic(r graph.Result) graph.Result {
	var keep []graph.Edge
	for _, e := range r.Edges {
		if strings.HasPrefix(e.Pod, "shop/api-") || e.Peer.ID() == "svc/shop/api" {
			continue
		}
		keep = append(keep, e)
	}
	r.Edges = keep
	return r
}

// An unconnected UDP server names no client in its own sockets; its clients'
// connected sockets do. Their outbound edges are its ingress evidence.
func TestClientSideIngress(t *testing.T) {
	r := shop()
	r.Services = append(r.Services, graph.Service{Namespace: "shop", Name: "stats", Selector: map[string]string{"app": "api"},
		Ports: []graph.ServicePort{{Protocol: "udp", Port: 8125, TargetPort: "8125"}}})
	udp := func(pod string, peer graph.Peer, port uint16, attempted bool) graph.Edge {
		e := edge(pod, graph.Outbound, peer, port)
		e.Protocol, e.Attempted = "udp", attempted
		return e
	}
	r.Edges = append(r.Edges,
		udp("shop/web-a", svcPeer("shop", "stats"), 8125, false),                                              // through a Service
		udp("edge/gateway-x", graph.Peer{Kind: graph.PeerPod, Namespace: "shop", Name: "api-1"}, 9999, false), // straight at a pod
		udp("shop/web-b", graph.Peer{Kind: graph.PeerPod, Namespace: "shop", Name: "api-1"}, 7777, true))      // attempted only
	api := find(t, Suggest(r, Options{}), "Deployment/api")
	got := map[string]bool{}
	for _, in := range api.Policy.Spec.Ingress {
		for _, p := range in.Ports {
			got[fmt.Sprintf("%v %s/%s", in.From[0].PodSelector.MatchLabels["app"], strings.ToLower(string(*p.Protocol)), p.Port.String())] = true
		}
	}
	for _, want := range []string{"web udp/8125", "gateway udp/9999", "web tcp/8080"} {
		if !got[want] {
			t.Errorf("missing ingress %q; got %v", want, got)
		}
	}
	if got["web udp/7777"] {
		t.Error("an attempted-only flow must not be allowed")
	}
	// The server-side view of web over TCP is not repeated by the client's
	// view through the Service's NAMED target port.
	if got["web tcp/http"] {
		t.Errorf("client-side duplicate of a flow the server saw: %v", got)
	}
	ev := ""
	for _, rs := range api.Reasons {
		ev += strings.Join(rs.Evidence, "\n")
	}
	if !strings.Contains(ev, "web-a -> svc/shop/stats udp/8125") || !strings.Contains(ev, "seen from the CLIENT's side only") {
		t.Errorf("evidence should say the rule rests on the client's view:\n%s", ev)
	}
}
