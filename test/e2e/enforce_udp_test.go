//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	netv1 "k8s.io/api/networking/v1"
)

// lookup sends an A query for name from a pod's container, to server (or to
// the pod's configured resolver when server is ""), and reports whether an
// answer containing want came back, the output, and how long it took. Only a
// datagram that got there and back produces the answer.
func lookup(from, name, server, want string) (bool, string, time.Duration) {
	ns, pod, ctr := splitFrom(from)
	args := []string{"--kubeconfig", kubeconfig, "--context", kubeCtx, "exec", "-n", ns, pod, "-c", ctr, "--", "nslookup", "-type=a", name}
	if server != "" {
		args = append(args, server)
	}
	start := time.Now()
	out, _ := exec.Command("kubectl", args...).CombinedOutput()
	return strings.Contains(string(out), "Address: "+want), string(out), time.Since(start)
}

type dgramCheck struct {
	what    string
	allowed bool
	why     string
	probe   func() bool
}

func TestPolicyEnforcementUDPAndDNS(t *testing.T) {
	ctx := context.Background()
	manifest := filepath.Join("testdata", "enforce-udp.yaml")
	kubectl(t, "delete", "-f", manifest, "--ignore-not-found", "--wait=true", "--timeout=120s")
	kubectl(t, "apply", "-f", manifest)
	t.Cleanup(func() {
		exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", manifest, "--ignore-not-found", "--wait=false").Run()
	})
	for _, ns := range []string{"pp-dgram", "pp-dgram-srv", "pp-dgram-other"} {
		kubectl(t, "wait", "-n", ns, "--for=condition=Ready", "pod", "--all", "--timeout=120s")
	}
	get := func(args ...string) string { return strings.TrimSpace(kubectl(t, append([]string{"get"}, args...)...)) }
	client := get("pod", "-n", "pp-dgram", "-l", "app=client", "-o", "jsonpath={.items[0].metadata.name}")
	geoIP := get("svc", "geo", "-n", "pp-dgram-srv", "-o", "jsonpath={.spec.clusterIP}")
	decoyIP := get("pod", "decoy", "-n", "pp-dgram-other", "-o", "jsonpath={.status.podIP}")
	dnsPod := get("pod", "-n", "kube-system", "-l", "k8s-app=kube-dns", "-o", "jsonpath={.items[0].status.podIP}")
	apiIP := get("svc", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}")
	time.Sleep(3 * time.Second)

	out := filepath.Join(outDir, "e2e-dgram.json")
	r := podpeers(ctx, t, "capture", "-A", "-l", "podpeers-e2e=dgram", "--duration", "8s", "--interval", "1s", "-o", out)
	t.Logf("exit=%d\n%s", r.code, r.stderr)
	if r.code != 0 {
		t.Fatalf("capture exit %d", r.code)
	}
	res := load(t, out)
	expectEdges(t, res, "pp-dgram/"+client, "outbound svc/pp-dgram-srv/geo udp/53 open")
	geo := ""
	for _, p := range res.Pods {
		if p.Namespace == "pp-dgram-srv" {
			geo = p.ID()
		}
	}
	// The server's own table shows no client: it is an unconnected socket.
	expectEdges(t, res, geo)

	policyFile := filepath.Join(outDir, "e2e-dgram-policy.yaml")
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
	if len(rep.Suggestions) != 2 {
		t.Fatalf("want policies for client and geo, got %d", len(rep.Suggestions))
	}
	for _, s := range rep.Suggestions {
		if s.Policy == nil {
			t.Fatalf("%s/%s refused: %s", s.Namespace, s.Workload, s.Refused)
		}
		t.Logf("%s/%s gaps:\n  %s", s.Namespace, s.Workload, strings.Join(s.Gaps, "\n  "))
	}
	pol, _ := os.ReadFile(policyFile)
	t.Logf("policies applied:\n%s", pol)

	C, S := "pp-dgram/"+client+"/probe", "pp-dgram/stranger/main"
	udp := func(from, server, want string) func() bool {
		return func() bool { ok, _, _ := lookup(from, "probe.test.", server, want); return ok }
	}
	tcp := func(from, host string, port int) func() bool {
		return func() bool { return connects(from, host, port) }
	}
	checks := []dgramCheck{
		{"client -> geo (udp/53, by ClusterIP)", true, "client's egress to geo's pods, geo's ingress from client's pods", udp(C, geoIP, "192.0.2.1")},
		{"client -> geo (udp/53, by Service name: needs DNS first)", true, "the DNS rule, then the geo rules", udp(C, "geo.pp-dgram-srv.svc.cluster.local", "192.0.2.1")},
		{"client -> cluster DNS lookup (udp/53)", true, "the DNS rule", func() bool {
			ok, _, _ := lookup(C, "kubernetes.default.svc.cluster.local", "", apiIP)
			return ok
		}},
		{"client -> cluster DNS pod over tcp/53", true, "the DNS rule's tcp/53", tcp(C, dnsPod, 53)},

		{"a stranger in client's namespace -> geo (udp/53)", false, "geo's ingress admits only client's pods", udp(S, geoIP, "192.0.2.1")},
		{"client -> another DNS server (udp/53, decoy)", false, "the DNS rule is udp/53 to the cluster DNS pods, not udp/53 anywhere", udp(C, decoyIP, "192.0.2.2")},
		{"client -> cluster DNS pod on its metrics port (tcp/9153)", false, "the DNS rule is port 53 only", tcp(C, dnsPod, 9153)},
	}
	run := func(c dgramCheck) bool {
		if c.probe() {
			return true
		}
		if c.allowed { // one retry for a path that should work
			return c.probe()
		}
		return false
	}

	// Control: with no policy, every one of these gets through.
	for _, c := range checks {
		if !run(c) && !run(c) {
			t.Fatalf("control: %s fails with no policy at all; the check would prove nothing", c.what)
		}
	}
	t.Logf("control: all %d exchanges succeed with no policy", len(checks))

	kubectl(t, "apply", "-f", policyFile)
	t.Cleanup(func() {
		exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", policyFile, "--ignore-not-found").Run()
	})
	deadline := time.Now().Add(60 * time.Second)
	for checks[6].probe() { // wait until the policy is enforced at all
		if time.Now().After(deadline) {
			t.Fatal("policies applied but nothing is blocked after 60s")
		}
		time.Sleep(2 * time.Second)
	}
	for _, c := range checks {
		ok := run(c)
		verdict := map[bool]string{true: "allowed", false: "blocked"}[ok]
		t.Logf("%-60s %s", c.what, verdict)
		if ok != c.allowed {
			t.Errorf("ENFORCEMENT DOES NOT MATCH INTENT: %s is %s; want %s (%s)", c.what, verdict, map[bool]string{true: "allowed", false: "blocked"}[c.allowed], c.why)
		}
	}

	// What the DNS rule actually does: replace client's policy with the same
	// policy minus the DNS rule (suggest -dns never).
	noDNS := filepath.Join(outDir, "e2e-dgram-policy-nodns.yaml")
	if s := podpeers(ctx, t, "suggest", "-dns", "never", "-workload", "Deployment/client", "-o", noDNS, out); s.code != 0 {
		t.Fatal(s.stderr)
	}
	kubectl(t, "apply", "-f", noDNS)
	time.Sleep(5 * time.Second)
	ok, txt, took := lookup(C, "kubernetes.default.svc.cluster.local", "", apiIP)
	t.Logf("without the DNS rule, a cluster DNS lookup: answered=%v after %s:\n%s", ok, took.Round(100*time.Millisecond), txt)
	if ok {
		t.Error("DNS RULE: lookups still work with the DNS rule removed; the rule is not what allows them")
	}
	if checks[3].probe() {
		t.Error("DNS RULE: tcp/53 to the DNS pod still connects with the DNS rule removed")
	}
	if checks[1].probe() {
		t.Error("DNS RULE: geo by Service name still works without DNS")
	}
	if !run(checks[0]) {
		t.Error("DNS RULE: geo by ClusterIP stopped working when only the DNS rule was removed")
	}
	t.Log("without the DNS rule: lookups time out, geo is unreachable by name, still reachable by address")
}
