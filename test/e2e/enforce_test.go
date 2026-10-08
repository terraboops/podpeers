//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1 "k8s.io/api/networking/v1"

	"github.com/terraboops/podpeers/internal/graph"
)

// docker runs docker on the host. The e2e cluster's nodes are containers on
// a docker network; containers started here on that network are addresses
// outside the cluster (not a pod, a service or a node).
func docker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// connects reports whether a new TCP connection from a pod's container to
// host:port succeeds within 3 seconds.
func connects(from, host string, port int) bool {
	ns, pod, ctr := splitFrom(from)
	cmd := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx,
		"exec", "-n", ns, pod, "-c", ctr, "--", "nc", "-z", "-w", "3", host, fmt.Sprint(port))
	return cmd.Run() == nil
}

func splitFrom(from string) (ns, pod, ctr string) {
	p := strings.Split(from, "/")
	return p[0], p[1], p[2]
}

type check struct {
	what      string
	from      string // ns/pod/container
	host      string
	port      int
	allowed   bool   // after the policies are applied
	ruleOrWhy string // the rule that allows it, or why it must be blocked
}

func TestPolicyEnforcement(t *testing.T) {
	ctx := context.Background()
	network := "k3d-podpeers-e2e"
	ext1, ext1b, ext2 := "pp-ext1", "pp-ext1-b", "pp-ext2"
	rmExt := func() { exec.Command("docker", "rm", "-f", ext1b, ext1, ext2).Run() }
	rmExt()
	t.Cleanup(rmExt)
	// ext1 listens on 7000 and (a second process sharing its network) 7001;
	// ext2 is a second outside address listening on 7000.
	docker(t, "run", "-d", "--name", ext1, "--network", network, "busybox:1.36", "nc", "-lk", "-p", "7000", "-e", "cat")
	docker(t, "run", "-d", "--name", ext1b, "--network", "container:"+ext1, "busybox:1.36", "nc", "-lk", "-p", "7001", "-e", "cat")
	docker(t, "run", "-d", "--name", ext2, "--network", network, "busybox:1.36", "nc", "-lk", "-p", "7000", "-e", "cat")
	ipOf := func(c string) string {
		return docker(t, "inspect", "-f", "{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", c)
	}
	ext1IP, ext2IP := ipOf(ext1), ipOf(ext2)
	server, agent := "k3d-podpeers-e2e-server-0", "k3d-podpeers-e2e-agent-0"
	nodeIP := strings.TrimSpace(kubectl(t, "get", "node", server, "-o", `jsonpath={.status.addresses[?(@.type=="InternalIP")].address}`))
	t.Logf("outside the cluster: ext1 %s (7000, 7001), ext2 %s (7000); server node %s", ext1IP, ext2IP, nodeIP)

	b, err := os.ReadFile(filepath.Join("testdata", "enforce.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(outDir, "enforce.yaml")
	os.WriteFile(manifest, []byte(strings.NewReplacer("@EXT1@", ext1IP, "@NODE@", nodeIP).Replace(string(b))), 0o644)
	kubectl(t, "delete", "-f", manifest, "--ignore-not-found", "--wait=true", "--timeout=120s")
	kubectl(t, "apply", "-f", manifest)
	t.Cleanup(func() {
		exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", manifest, "--ignore-not-found", "--wait=false").Run()
	})
	for _, ns := range []string{"pp-front", "pp-back", "pp-other"} {
		kubectl(t, "wait", "-n", ns, "--for=condition=Ready", "pod", "--all", "--timeout=120s")
	}
	podName := func(ns, app string) string {
		return strings.TrimSpace(kubectl(t, "get", "pod", "-n", ns, "-l", "app="+app, "-o", "jsonpath={.items[0].metadata.name}"))
	}
	web, api := podName("pp-front", "web"), podName("pp-back", "api")
	time.Sleep(3 * time.Second) // let every client connect

	// Capture both namespaces at once, not the decoy.
	out := filepath.Join(outDir, "e2e-enforce.json")
	r := podpeers(ctx, t, "capture", "-A", "-l", "podpeers-e2e=enforce,!decoy", "--duration", "8s", "--interval", "1s", "-o", out)
	t.Logf("exit=%d\n%s", r.code, r.stderr)
	if r.code != 0 {
		t.Fatalf("capture exit %d", r.code)
	}
	res := load(t, out)
	expectEdges(t, res, "pp-front/"+web,
		"outbound svc/pp-back/api tcp/8080 open",
		"outbound node/"+server+" tcp/7100 open")
	got := edgeSet(res, "pp-back/"+api)
	t.Logf("api edges: %v", got)
	var fromAgent, toExt bool
	for _, e := range res.Edges {
		if e.Pod != "pp-back/"+api {
			continue
		}
		if e.Direction == graph.Outbound && e.Peer.Kind == graph.PeerExternal && e.Peer.IP == ext1IP && e.Port == 7000 {
			toExt = true
		}
		if e.Direction == graph.Inbound && e.Port == 8080 && e.Peer.Kind == graph.PeerNode && e.Peer.Name == agent && e.Peer.PodRange {
			fromAgent = true
		}
	}
	if !toExt {
		t.Errorf("api: no outbound edge to external %s:7000", ext1IP)
	}
	if !fromAgent {
		t.Errorf("api: the host-network client on %s is not identified as that node (on its pod network)", agent)
	}

	// The policies, as podpeers writes them.
	policyFile := filepath.Join(outDir, "e2e-enforce-policy.yaml")
	if s := podpeers(ctx, t, "suggest", "-o", policyFile, out); s.code != 0 {
		t.Fatal(s.stderr)
	}
	js := podpeers(ctx, t, "suggest", "-format", "json", out)
	var rep struct {
		Suggestions []struct {
			Workload, Namespace, Refused string
			Gaps                         []string
			Policy                       *netv1.NetworkPolicy
		}
	}
	if err := json.Unmarshal([]byte(js.stdout), &rep); err != nil {
		t.Fatal(err)
	}
	for _, s := range rep.Suggestions {
		if s.Policy == nil {
			t.Fatalf("%s/%s refused: %s", s.Namespace, s.Workload, s.Refused)
		}
		t.Logf("%s/%s gaps: %q", s.Namespace, s.Workload, s.Gaps)
	}
	gapsOf := map[string]string{}
	for _, s := range rep.Suggestions {
		gapsOf[s.Namespace] = strings.Join(s.Gaps, "\n")
	}
	if g := gapsOf["pp-back"]; !strings.Contains(g, "Ingress from node "+agent+" on its pod network") || strings.Contains(g, "did not resolve to any pod") {
		t.Errorf("api's gaps should name the agent node's pod-network address, not an unknown address:\n%s", g)
	}
	if g := gapsOf["pp-front"]; !strings.Contains(g, "Egress to node "+server) || strings.Contains(g, "CDNs") {
		t.Errorf("web's gaps should describe the node egress as a node:\n%s", g)
	}
	if len(rep.Suggestions) != 2 {
		t.Fatalf("want policies for web and api, got %d", len(rep.Suggestions))
	}
	pol, _ := os.ReadFile(policyFile)
	t.Logf("policies applied:\n%s", pol)

	// The impostor really carries every label web's selector names, so only
	// the namespace selector can keep it out.
	webSel := ""
	for _, s := range rep.Suggestions {
		if s.Namespace == "pp-front" {
			var kv []string
			for k, v := range s.Policy.Spec.PodSelector.MatchLabels {
				kv = append(kv, k+"="+v)
			}
			webSel = strings.Join(kv, ",")
		}
	}
	if m := strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-other", "-l", webSel, "-o", "name")); m != "pod/impostor" {
		t.Fatalf("the impostor must match web's selector %q; got %q", webSel, m)
	}

	apiSvc := "api.pp-back.svc.cluster.local"
	W, A := "pp-front/"+web+"/to-api", "pp-back/"+api+"/client"
	checks := []check{
		{"web -> api in another namespace", W, apiSvc, 8080, true, "egress to api's pods in pp-back, ingress from web's pods in pp-front"},
		{"web -> the server node's address", W, nodeIP, 7100, true, "egress ipBlock node"},
		{"api -> outside the cluster", A, ext1IP, 7000, true, "egress ipBlock external"},
		{"the agent node (host network) -> api", "pp-other/hostcli/main", apiSvc, 8080, true, "ingress ipBlock from the agent node"},

		{"a stranger in web's namespace -> api", "pp-front/stranger/main", apiSvc, 8080, false, "not web's labels"},
		{"an impostor with web's labels in another namespace -> api", "pp-other/impostor/main", apiSvc, 8080, false, "namespace selector"},
		{"web -> api on a port web never used", W, apiSvc, 8081, false, "port"},
		{"web -> the server node on a port web never used", W, nodeIP, 7101, false, "port"},
		{"web -> outside the cluster (web never went there)", W, ext1IP, 7000, false, "no egress rule"},
		{"api -> outside the cluster on a port api never used", A, ext1IP, 7001, false, "port"},
		{"api -> a second outside address", A, ext2IP, 7000, false, "the ipBlock is one address"},
		{"api -> the server node (api never went there)", A, nodeIP, 7100, false, "no egress rule"},
		{"the agent node (host network) -> api on a port it never used", "pp-other/hostcli/main", apiSvc, 8081, false, "port"},
	}

	// Control: with no policy, every one of these connects, so a failure
	// afterwards is the policy's doing.
	for _, c := range checks {
		ok := false
		for i := 0; i < 3 && !ok; i++ {
			ok = connects(c.from, c.host, c.port)
		}
		if !ok {
			t.Fatalf("control: %s (%s:%d) fails with no policy at all; the check would prove nothing", c.what, c.host, c.port)
		}
	}
	t.Logf("control: all %d connections succeed with no policy", len(checks))

	kubectl(t, "apply", "-f", policyFile)
	t.Cleanup(func() {
		exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", policyFile, "--ignore-not-found").Run()
	})
	// Wait until the policy is enforced at all before judging anything.
	deadline := time.Now().Add(60 * time.Second)
	for connects(checks[4].from, checks[4].host, checks[4].port) {
		if time.Now().After(deadline) {
			t.Fatal("policies applied but nothing is blocked after 60s")
		}
		time.Sleep(2 * time.Second)
	}
	for _, c := range checks {
		ok := connects(c.from, c.host, c.port)
		if c.allowed && !ok {
			ok = connects(c.from, c.host, c.port) // one retry for an allowed path
		}
		verdict := "blocked"
		if ok {
			verdict = "allowed"
		}
		t.Logf("%-60s %s:%d  %s", c.what, c.host, c.port, verdict)
		if ok != c.allowed {
			want := "blocked (" + c.ruleOrWhy + ")"
			if c.allowed {
				want = "allowed by " + c.ruleOrWhy
			}
			t.Errorf("ENFORCEMENT DOES NOT MATCH INTENT: %s is %s; want %s", c.what, verdict, want)
		}
	}

	// Attribution: each address flow is allowed BY its ipBlock rule, not by
	// a CNI default for node or outside traffic. Remove every ipBlock rule
	// and those flows must stop while the pod-selector flow still works.
	stripped := filepath.Join(outDir, "e2e-enforce-policy-no-ipblocks.json")
	list := map[string]any{"apiVersion": "v1", "kind": "List"}
	var items []any
	removed := 0
	for _, s := range rep.Suggestions {
		p := s.Policy.DeepCopy()
		p.APIVersion, p.Kind = "networking.k8s.io/v1", "NetworkPolicy"
		var in []netv1.NetworkPolicyIngressRule
		for _, r := range p.Spec.Ingress {
			if r.From[0].IPBlock == nil {
				in = append(in, r)
			} else {
				removed++
			}
		}
		var eg []netv1.NetworkPolicyEgressRule
		for _, r := range p.Spec.Egress {
			if len(r.To) == 0 || r.To[0].IPBlock == nil {
				eg = append(eg, r)
			} else {
				removed++
			}
		}
		p.Spec.Ingress, p.Spec.Egress = in, eg
		items = append(items, p)
	}
	if removed != 3 {
		t.Fatalf("want 3 ipBlock rules (node egress, outside egress, node ingress), found %d", removed)
	}
	list["items"] = items
	jb, _ := json.Marshal(list)
	os.WriteFile(stripped, jb, 0o644)
	kubectl(t, "apply", "-f", stripped)
	time.Sleep(5 * time.Second)
	for _, c := range []check{checks[1], checks[2], checks[3]} {
		if connects(c.from, c.host, c.port) {
			t.Errorf("ATTRIBUTION: %s still connects with its ipBlock rule removed; the rule is not what allows it", c.what)
		} else {
			t.Logf("without its ipBlock rule: %-40s blocked", c.what)
		}
	}
	if !connects(checks[0].from, checks[0].host, checks[0].port) && !connects(checks[0].from, checks[0].host, checks[0].port) {
		t.Errorf("ATTRIBUTION: %s stopped working when only ipBlock rules were removed", checks[0].what)
	}
}
