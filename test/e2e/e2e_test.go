//go:build e2e

// Package e2e runs the real podpeers binary against a real, local, throwaway
// Kubernetes cluster with workloads whose connections are known in advance, and
// checks that what podpeers reports is exactly what was built.
//
// Run it with `make e2e` (which creates the k3d cluster). It refuses to run
// unless PODPEERS_E2E_KUBECONFIG points at a kubeconfig whose current context is
// exactly PODPEERS_E2E_CONTEXT (default k3d-podpeers-e2e), and it passes that
// file and context explicitly to every kubectl and podpeers invocation, so the
// operator's default kubeconfig is never read.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/terraboops/podpeers/internal/graph"
)

var (
	kubeconfig string
	kubeCtx    string
	binary     string
	outDir     string
)

func TestMain(m *testing.M) {
	kubeconfig = os.Getenv("PODPEERS_E2E_KUBECONFIG")
	kubeCtx = os.Getenv("PODPEERS_E2E_CONTEXT")
	if kubeCtx == "" {
		kubeCtx = "k3d-podpeers-e2e"
	}
	if kubeconfig == "" {
		fmt.Println("e2e: PODPEERS_E2E_KUBECONFIG not set; run `make e2e` to create the local cluster")
		os.Exit(1)
	}
	cfg, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		fmt.Println("e2e:", err)
		os.Exit(1)
	}
	// Hard stop: only the cluster this suite created.
	if cfg.CurrentContext != kubeCtx || !strings.HasPrefix(kubeCtx, "k3d-") && !strings.HasPrefix(kubeCtx, "kind-") {
		fmt.Printf("e2e: REFUSING: kubeconfig current-context is %q, expected local %q\n", cfg.CurrentContext, kubeCtx)
		os.Exit(1)
	}
	tmp, err := os.MkdirTemp("", "podpeers-e2e-")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(tmp, "podpeers")
	if out, err := exec.Command("go", "build", "-o", binary, "../../cmd/podpeers").CombinedOutput(); err != nil {
		fmt.Printf("e2e: build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	outDir = os.Getenv("PODPEERS_E2E_OUT")
	if outDir == "" {
		outDir = tmp
	}
	os.MkdirAll(outDir, 0o755)
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// kubectl runs kubectl against the e2e cluster only.
func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"--kubeconfig", kubeconfig, "--context", kubeCtx}, args...)
	out, err := exec.Command("kubectl", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

type result struct {
	code           int
	stdout, stderr string
}

// podpeers runs the built binary. Unless the caller passes its own
// --kubeconfig, the e2e kubeconfig is used.
func podpeers(ctx context.Context, t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfig)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running podpeers: %v", err)
	}
	return result{code, out.String(), errb.String()}
}

func load(t *testing.T, path string) graph.Result {
	t.Helper()
	r, err := graph.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// ephemeral returns the names of ephemeral containers in a pod.
func ephemeral(t *testing.T, ns, pod string) []string {
	out := kubectl(t, "get", "pod", "-n", ns, pod, "-o", "jsonpath={.spec.ephemeralContainers[*].name}")
	return strings.Fields(out)
}

// edgeSet renders a pod's edges as sorted "dir peer proto/port open|closed" lines.
// DNS lookups are sub-second UDP exchanges that a sample catches only by
// luck, so edges to the cluster DNS service are left out of exact comparisons.
func edgeSet(r graph.Result, pod string) []string {
	var out []string
	for _, e := range r.Edges {
		if e.Pod != pod || e.Peer.ID() == "svc/kube-system/kube-dns" {
			continue
		}
		st := "open"
		if !e.Open {
			st = "closed"
		}
		out = append(out, fmt.Sprintf("%s %s %s/%d %s", e.Direction, e.Peer.ID(), e.Protocol, e.Port, st))
	}
	sort.Strings(out)
	return out
}

func probeOf(r graph.Result, id string) (graph.Probe, bool) {
	for _, p := range r.Pods {
		if p.ID() == id {
			return p.Probe, true
		}
	}
	return graph.Probe{}, false
}

func expectEdges(t *testing.T, r graph.Result, pod string, want ...string) {
	t.Helper()
	sort.Strings(want)
	got := edgeSet(r, pod)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%s edges:\n got:\n  %s\n want:\n  %s", pod, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestE2E(t *testing.T) {
	ctx := context.Background()
	manifest := filepath.Join("testdata", "workloads.yaml")

	// Fresh pods every run: ephemeral containers cannot be removed, so reuse
	// would let an earlier run's containers leak into this run's assertions.
	exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx,
		"delete", "-f", manifest, "--ignore-not-found", "--wait=true", "--timeout=120s").Run()
	kubectl(t, "apply", "-f", manifest)
	kubectl(t, "wait", "-n", "pp-app", "--for=condition=Ready", "--timeout=120s",
		"pod/api", "pod/web", "pod/brief", "pod/excluded", "pod/loner")
	kubectl(t, "wait", "-n", "pp-edge", "--for=condition=Ready", "--timeout=60s", "pod/gateway")
	kubectl(t, "wait", "-n", "pp-locked", "--for=condition=Ready", "--timeout=60s", "pod/vault")
	time.Sleep(3 * time.Second) // let the clients' connections establish

	t.Run("guard refuses a non-local context name, even for a reachable local cluster", func(t *testing.T) {
		// Same cluster, same credentials, but a context name that does not say
		// "local": refused by default, and no pod is modified.
		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Contexts["staging-cluster"] = cfg.Contexts[kubeCtx]
		delete(cfg.Contexts, kubeCtx)
		cfg.CurrentContext = "staging-cluster"
		renamed := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(*cfg, renamed); err != nil {
			t.Fatal(err)
		}
		r := podpeers(ctx, t, "capture", "--kubeconfig", renamed, "-A", "-l", "podpeers-e2e=target", "--duration", "5s", "--interval", "1s", "-o", filepath.Join(t.TempDir(), "x.json"))
		t.Logf("exit=%d stderr:\n%s", r.code, r.stderr)
		if r.code != 2 || !strings.Contains(r.stderr, "REFUSED") {
			t.Fatalf("want refusal exit 2, got %d", r.code)
		}
		if got := ephemeral(t, "pp-app", "api"); len(got) != 0 {
			t.Fatalf("refused run modified a pod: %v", got)
		}
		// The deliberate opt-in naming that exact context is accepted.
		r = podpeers(ctx, t, "check-context", "--kubeconfig", renamed, "--allow-context", "staging-cluster")
		t.Logf("opt-in: exit=%d stdout=%q stderr=%s", r.code, r.stdout, r.stderr)
		if r.code != 0 || strings.TrimSpace(r.stdout) != "allowed" {
			t.Fatalf("explicit opt-in should be allowed, got %d", r.code)
		}
	})

	t.Run("capture matches the workloads that were built", func(t *testing.T) {
		out := filepath.Join(outDir, "e2e-capture.json")
		done := make(chan result, 1)
		go func() {
			done <- podpeers(ctx, t, "capture", "-A", "-l", "podpeers-e2e=target",
				"--duration", "30s", "--interval", "2s", "-o", out)
		}()

		// Close brief's connection once its sampler has been running a while,
		// so the window sees it both open and closed.
		deadline := time.Now().Add(90 * time.Second)
		for {
			st := kubectl(t, "get", "pod", "-n", "pp-app", "brief", "-o", "jsonpath={.status.ephemeralContainerStatuses[0].state.running.startedAt}")
			if st != "" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("brief's sampler never started")
			}
			time.Sleep(time.Second)
		}
		time.Sleep(10 * time.Second)
		kubectl(t, "exec", "-n", "pp-app", "brief", "-c", "main", "--", "pkill", "nc")
		t.Log("closed pp-app/brief's connection to api mid-window")

		r := <-done
		t.Logf("podpeers capture exit=%d\n%s", r.code, r.stderr)
		if r.code != 0 {
			t.Fatalf("capture exit %d", r.code)
		}
		res := load(t, out)

		// Pods the selector matched, and what happened to each.
		for id, want := range map[string]graph.ProbeStatus{
			"pp-app/api": graph.ProbeObserved, "pp-app/web": graph.ProbeObserved,
			"pp-app/brief": graph.ProbeObserved, "pp-app/loner": graph.ProbeObserved,
			"pp-edge/gateway": graph.ProbeObserved, "pp-app/pending": graph.ProbeSkipped,
			"pp-app/excluded": graph.ProbeNotTargeted, // appears only as api's peer
		} {
			p, ok := probeOf(res, id)
			if !ok || p.Status != want {
				t.Errorf("%s probe = %+v (present=%v); want %s", id, p, ok, want)
			}
			if want == graph.ProbeObserved && (!p.Complete || p.Samples < 10) {
				t.Errorf("%s: sampler incomplete: %+v", id, p)
			}
		}
		if _, ok := probeOf(res, "pp-locked/vault"); ok {
			t.Error("pp-locked/vault does not match the selector and must not appear")
		}

		expectEdges(t, res, "pp-app/api",
			"inbound pp-app/web tcp/9000 open",
			"inbound pp-app/excluded tcp/9000 open",
			"inbound pp-app/brief tcp/9000 closed")
		expectEdges(t, res, "pp-app/web",
			"outbound svc/pp-app/api tcp/9000 open",
			"inbound pp-edge/gateway tcp/8080 open")
		expectEdges(t, res, "pp-app/brief",
			"outbound svc/pp-app/api tcp/9000 closed")
		expectEdges(t, res, "pp-edge/gateway",
			"outbound svc/pp-app/web tcp/8080 open")
		expectEdges(t, res, "pp-app/loner") // a pod with no peers at all

		// The selector-excluded pod and the pending pod were never touched.
		if got := ephemeral(t, "pp-app", "excluded"); len(got) != 0 {
			t.Errorf("excluded pod was modified: %v", got)
		}
		if got := ephemeral(t, "pp-app", "pending"); len(got) != 0 {
			t.Errorf("pending pod was modified: %v", got)
		}
		// Every sampler stopped by itself, successfully, at the end of the window.
		for _, p := range []string{"api", "web", "brief", "loner"} {
			codes := kubectl(t, "get", "pod", "-n", "pp-app", p, "-o", "jsonpath={.status.ephemeralContainerStatuses[*].state.terminated.exitCode}")
			if strings.TrimSpace(codes) != "0" {
				t.Errorf("%s sampler exit codes = %q; want one terminated container with 0", p, codes)
			}
		}

		// The outputs render and the query interface answers from this capture.
		for _, f := range []string{"text", "dot", "html"} {
			rr := podpeers(ctx, t, "render", "-format", f, "-o", filepath.Join(outDir, "e2e-capture."+f), out)
			if rr.code != 0 {
				t.Errorf("render %s: %s", f, rr.stderr)
			}
		}
		q := podpeers(ctx, t, "query", out, `{ pod(id: "pp-app/api") { listening { port } peers(direction: "inbound", open: true) { id } } }`)
		t.Logf("query api's open inbound peers:\n%s", q.stdout)
		if q.code != 0 || !strings.Contains(q.stdout, `"id": "pp-app/excluded"`) || !strings.Contains(q.stdout, `"id": "pp-app/web"`) || strings.Contains(q.stdout, "brief") {
			t.Errorf("query result unexpected")
		}
		text, _ := os.ReadFile(filepath.Join(outDir, "e2e-capture.text"))
		t.Logf("rendered report:\n%s", text)
	})

	t.Run("suggestions from real traffic, refusing where evidence is thin", func(t *testing.T) {
		capture := filepath.Join(outDir, "e2e-capture.json")
		r := podpeers(ctx, t, "suggest", "-format", "json", capture)
		if r.code != 0 {
			t.Fatalf("suggest: %s", r.stderr)
		}
		var rep struct {
			Suggestions []struct {
				Workload, Refused string
				Gaps              []string
				Policy            *struct{ Spec map[string]any }
			}
		}
		if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, s := range rep.Suggestions {
			state := "policy"
			if s.Refused != "" {
				state = "refused: " + s.Refused
			}
			got[s.Workload] = state
			t.Logf("%-14s %s", s.Workload, state)
		}
		for wl, want := range map[string]string{
			"Pod/api": "policy", "Pod/web": "policy", "Pod/brief": "policy", "Pod/gateway": "policy",
			"Pod/loner":   "refused: no traffic at all was observed",
			"Pod/pending": "refused: no pod of this workload was observed",
		} {
			if !strings.HasPrefix(got[wl], want) {
				t.Errorf("%s = %q; want prefix %q", wl, got[wl], want)
			}
		}
		y := podpeers(ctx, t, "suggest", "-o", filepath.Join(outDir, "e2e-policy.yaml"), capture)
		if y.code != 0 {
			t.Fatal(y.stderr)
		}
		// Server-side validation of every suggested policy by the real API server.
		kubectl(t, "apply", "--dry-run=server", "-f", filepath.Join(outDir, "e2e-policy.yaml"))
	})

	t.Run("MCP server answers over stdio from the real capture", func(t *testing.T) {
		capture := filepath.Join(outDir, "e2e-capture.json")
		cmd := exec.Command(binary, "mcp", capture)
		cmd.Stdin = strings.NewReader(strings.Join([]string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"peers","arguments":{"pod":"pp-app/api","direction":"inbound"}}}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"suggest_policies","arguments":{"workload":"Pod/web"}}}`,
		}, "\n") + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) != 3 {
			t.Fatalf("want 3 responses, got %d:\n%s", len(lines), out)
		}
		var peersResp struct {
			Result struct {
				Content []struct{ Text string }
			}
		}
		if err := json.Unmarshal([]byte(lines[1]), &peersResp); err != nil || len(peersResp.Result.Content) == 0 {
			t.Fatalf("peers response: %v %.300s", err, lines[1])
		}
		for _, want := range []string{`"name": "excluded"`, `"name": "brief"`, `"name": "web"`} {
			if !strings.Contains(peersResp.Result.Content[0].Text, want) {
				t.Errorf("peers response missing %s", want)
			}
		}
		if !strings.Contains(lines[2], "podpeers-web") || !strings.Contains(lines[2], "NOT COVERED") {
			t.Errorf("suggest_policies response: %.400s", lines[2])
		}
		t.Logf("MCP peers response: %.300s...", lines[1])
	})

	t.Run("connections older than a policy are reported as inconclusive, not OK", func(t *testing.T) {
		// web holds one connection to api for its whole life. A policy that
		// denies all of web's egress does not cut it (CNIs check policy when a
		// connection opens), so the flow keeps "working" while any reconnect
		// would fail. The diff must say so instead of reporting OK.
		pol := filepath.Join(t.TempDir(), "deny-web-egress.yaml")
		os.WriteFile(pol, []byte(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: e2e-deny-web-egress, namespace: pp-app}
spec:
  podSelector: {matchLabels: {app: web}}
  policyTypes: [Egress]
  egress: []
`), 0o644)
		kubectl(t, "apply", "-f", pol)
		defer kubectl(t, "delete", "-f", pol, "--ignore-not-found")
		time.Sleep(8 * time.Second)

		// Probe the ClusterIP, not the name: DNS is blocked too, and a failed
		// lookup would make the probe pass for the wrong reason.
		apiIP := strings.TrimSpace(kubectl(t, "get", "svc", "-n", "pp-app", "api", "-o", "jsonpath={.spec.clusterIP}"))
		probe, _ := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "exec", "-n", "pp-app", "web", "-c", "main", "--",
			"sh", "-c", "timeout 6 nc -z -w 4 "+apiIP+" 9000 && echo NEW-CONNECT-OK || echo NEW-CONNECT-BLOCKED").CombinedOutput()
		t.Logf("a new TCP connection from web to the api ClusterIP under the policy: %s", strings.TrimSpace(string(probe)))
		if !strings.Contains(string(probe), "NEW-CONNECT-BLOCKED") {
			t.Fatal("policy is not enforced for new connections; this test needs an enforcing CNI")
		}

		after := filepath.Join(outDir, "e2e-after-deny.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-app", "-l", "app=web", "--duration", "8s", "--interval", "1s", "-o", after, "--summary", "none")
		if r.code != 0 {
			t.Fatalf("capture: %s", r.stderr)
		}
		d := podpeers(ctx, t, "diff", filepath.Join(outDir, "e2e-capture.json"), after)
		t.Logf("diff exit=%d\n%s", d.code, d.stdout)
		if d.code != 5 || !strings.Contains(d.stdout, "preexisting pp-app/Pod/web -> svc/pp-app/api tcp/9000") || !strings.Contains(d.stdout, "INCONCLUSIVE") {
			t.Fatalf("want INCONCLUSIVE (exit 5) naming web -> api, got exit %d", d.code)
		}
	})

	t.Run("debug container that cannot start is reported, not waited on forever", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "bad-image.json")
		start := time.Now()
		r := podpeers(ctx, t, "capture", "-n", "pp-app", "-l", "app=loner", "--image", "registry.example.invalid/podpeers/no-such-image:0",
			"--start-timeout", "20s", "--duration", "10s", "--interval", "2s", "-o", out)
		t.Logf("exit=%d after %s\n%s", r.code, time.Since(start).Round(time.Second), r.stderr)
		if r.code != 3 {
			t.Fatalf("want partial-failure exit 3, got %d", r.code)
		}
		p, _ := probeOf(load(t, out), "pp-app/loner")
		if p.Status != graph.ProbeFailed || !strings.Contains(p.Reason, "did not start within 20s") ||
			!(strings.Contains(p.Reason, "ErrImagePull") || strings.Contains(p.Reason, "ImagePullBackOff")) {
			t.Fatalf("loner probe = %+v", p)
		}
	})

	t.Run("namespace where the credentials may not do this", func(t *testing.T) {
		token := strings.TrimSpace(kubectl(t, "create", "token", "pp-limited", "-n", "pp-app", "--duration", "10m"))
		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		cluster := cfg.Contexts[kubeCtx].Cluster
		limited := clientcmdapi.NewConfig()
		limited.Clusters["e2e"] = cfg.Clusters[cluster]
		limited.AuthInfos["limited"] = &clientcmdapi.AuthInfo{Token: token}
		limited.Contexts[kubeCtx+"-limited"] = &clientcmdapi.Context{Cluster: "e2e", AuthInfo: "limited"}
		limited.CurrentContext = kubeCtx + "-limited"
		lk := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(*limited, lk); err != nil {
			t.Fatal(err)
		}

		// May read pods in pp-locked but not add ephemeral containers there.
		out := filepath.Join(t.TempDir(), "locked.json")
		r := podpeers(ctx, t, "capture", "--kubeconfig", lk, "-n", "pp-locked", "-l", "podpeers-e2e=locked", "--duration", "5s", "--interval", "1s", "-o", out)
		t.Logf("pp-locked: exit=%d\n%s", r.code, r.stderr)
		if r.code != 3 {
			t.Fatalf("want exit 3, got %d", r.code)
		}
		p, _ := probeOf(load(t, out), "pp-locked/vault")
		if p.Status != graph.ProbeFailed || !strings.Contains(p.Reason, "forbidden") || !strings.Contains(p.Reason, "pods/ephemeralcontainers") {
			t.Fatalf("vault probe = %+v", p)
		}
		if got := ephemeral(t, "pp-locked", "vault"); len(got) != 0 {
			t.Fatalf("forbidden run modified vault: %v", got)
		}

		// No access at all to pp-sealed: the capture fails cleanly at listing.
		r = podpeers(ctx, t, "capture", "--kubeconfig", lk, "-n", "pp-sealed", "-l", "app", "--duration", "5s", "--interval", "1s", "-o", filepath.Join(t.TempDir(), "sealed.json"))
		t.Logf("pp-sealed: exit=%d\n%s", r.code, r.stderr)
		if r.code != 1 || !strings.Contains(r.stderr, "forbidden") {
			t.Fatalf("want exit 1 with forbidden, got %d", r.code)
		}
	})
}
