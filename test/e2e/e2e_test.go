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
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	netv1 "k8s.io/api/networking/v1"

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
	kubectl(t, "wait", "-n", "pp-strict", "--for=condition=Ready", "--timeout=60s", "pod/vaultd", "pod/auditor")
	kubectl(t, "wait", "-n", "pp-udp", "--for=condition=Ready", "--timeout=60s", "pod/udp-echo", "pod/dnsd", "pod/udp-client")
	kubectl(t, "wait", "-n", "pp-busy", "--for=condition=Ready", "--timeout=60s", "pod/busy")
	kubectl(t, "rollout", "status", "-n", "pp-kinds", "statefulset/db", "--timeout=120s")
	kubectl(t, "rollout", "status", "-n", "pp-kinds", "daemonset/node-agent", "--timeout=120s")
	time.Sleep(3 * time.Second) // let the clients' connections establish

	t.Run("a tunnel to a cluster with the context's own identity passes: the documented residual", func(t *testing.T) {
		// The README says what still gets through the node gate: a remote
		// cluster whose nodes carry exactly the identity the context names.
		// Through the Kubernetes API a loopback tunnel to such a cluster looks
		// the same as the cluster itself. This pins that statement: a real TCP
		// tunnel, a second loopback port forwarded to this cluster's API server,
		// under the cluster's own context name, is allowed. If podpeers ever
		// learns to tell a tunnel apart, this fails and the README must change.
		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		cl := cfg.Clusters[cfg.Contexts[kubeCtx].Cluster]
		target := strings.TrimPrefix(strings.TrimPrefix(cl.Server, "https://"), "http://")
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					u, err := net.Dial("tcp", target)
					if err != nil {
						return
					}
					defer u.Close()
					go io.Copy(u, c)
					io.Copy(c, u)
				}()
			}
		}()
		cl.Server = "https://" + l.Addr().String()
		tunnelled := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(*cfg, tunnelled); err != nil {
			t.Fatal(err)
		}
		r := podpeers(ctx, t, "check-context", "--kubeconfig", tunnelled)
		t.Logf("through a tunnel on %s: exit=%d %s %s", l.Addr(), r.code, strings.TrimSpace(r.stdout), strings.TrimSpace(r.stderr))
		if r.code != 0 || strings.TrimSpace(r.stdout) != "allowed" {
			t.Fatalf("the documented residual changed: a same-identity tunnel was not allowed (exit %d); update the README", r.code)
		}
	})

	t.Run("guard refuses a local-looking context answered by another cluster's nodes", func(t *testing.T) {
		// What a tunnel to some other k3s cluster looks like from here: a k3d
		// context name and a loopback server pass the pre-flight, but the API
		// server answering is not the cluster the context names. Every k3s
		// cluster writes k3s:// provider IDs, so the scheme alone would pass;
		// the nodes must belong to k3d cluster "elsewhere", and they do not.
		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Contexts["k3d-elsewhere"] = cfg.Contexts[kubeCtx]
		delete(cfg.Contexts, kubeCtx)
		cfg.CurrentContext = "k3d-elsewhere"
		renamed := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(*cfg, renamed); err != nil {
			t.Fatal(err)
		}
		r := podpeers(ctx, t, "capture", "--kubeconfig", renamed, "-A", "-l", "podpeers-e2e=target", "--duration", "5s", "--interval", "1s", "-o", filepath.Join(t.TempDir(), "x.json"))
		t.Logf("exit=%d stderr:\n%s", r.code, r.stderr)
		if r.code != 2 || !strings.Contains(r.stderr, "nodes of a different cluster") || strings.Contains(r.stderr, "k3s://") {
			t.Fatalf("want refusal exit 2 by the node gate, without naming the nodes, got %d", r.code)
		}
		if got := ephemeral(t, "pp-app", "api"); len(got) != 0 {
			t.Fatalf("refused run modified a pod: %v", got)
		}
		// The same for every exact-name local tool: a foreign k3s cluster behind
		// a loopback port does not become colima's (or anyone's) by its name.
		for _, name := range []string{"colima", "rancher-desktop", "orbstack", "docker-desktop", "minikube"} {
			cfg.Contexts[name] = cfg.Contexts["k3d-elsewhere"]
			cfg.CurrentContext = name
			as := filepath.Join(t.TempDir(), name+".kubeconfig")
			if err := clientcmd.WriteToFile(*cfg, as); err != nil {
				t.Fatal(err)
			}
			r := podpeers(ctx, t, "check-context", "--kubeconfig", as)
			t.Logf("as %s: exit=%d %s", name, r.code, strings.TrimSpace(r.stderr))
			if r.code != 2 || !strings.Contains(r.stderr, "nodes of a different cluster") {
				t.Errorf("this cluster under the context name %q: want refusal exit 2 by the node gate, got %d", name, r.code)
			}
		}
		// Control: the real name, same file otherwise, is allowed.
		if r := podpeers(ctx, t, "check-context", "--kubeconfig", kubeconfig); r.code != 0 {
			t.Fatalf("control: the cluster's own context should be allowed, got %d: %s", r.code, r.stderr)
		}
	})

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
		// Refused by the pre-flight, from the kubeconfig alone, before any
		// request: the node gate refusing it too would hide a broken pre-flight.
		if r.code != 2 || !strings.Contains(r.stderr, "is not a recognised local cluster") {
			t.Fatalf("want the pre-flight refusal (exit 2, before any API request), got %d", r.code)
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

		// The safety invariant comes first, whatever the exit code: this run's
		// debug container must exist only in pods the selector matched, across
		// the whole cluster (kube-system included).
		m := regexp.MustCompile(`added (podpeers-[a-z0-9]+)`).FindStringSubmatch(r.stderr)
		if m == nil {
			t.Fatal("could not find this run's debug container name in the output")
		}
		runContainer := m[1]
		all := kubectl(t, "get", "pods", "-A", "-o",
			`jsonpath={range .items[*]}{.metadata.namespace}/{.metadata.name} {.metadata.labels.podpeers-e2e} {.spec.ephemeralContainers[*].name}{"\n"}{end}`)
		touched := 0
		for _, line := range strings.Split(strings.TrimSpace(all), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || !strings.Contains(line, runContainer) {
				continue
			}
			touched++
			if len(f) < 2 || f[1] != "target" {
				t.Errorf("pod outside the selector was modified by this run: %s", f[0])
			}
		}
		if touched != 5 {
			t.Errorf("this run modified %d pods; want exactly the 5 running targets", touched)
		}
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
		// gateway -> web crosses nodes; both ends saw it.
		nodes := map[string]string{}
		for _, p := range res.Pods {
			nodes[p.ID()] = p.Node
		}
		t.Logf("cross-node: pp-edge/gateway on %s, pp-app/web on %s", nodes["pp-edge/gateway"], nodes["pp-app/web"])
		if nodes["pp-edge/gateway"] == "" || nodes["pp-edge/gateway"] == nodes["pp-app/web"] {
			t.Errorf("gateway and web must be on different nodes for this to prove cross-node capture: %v", nodes)
		}
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
				Reasons           []struct {
					Rule, Direction, Peer string
					Ports, Evidence       []string
					Assumed               bool
				}
			}
			Gaps []string
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
		// The honest gap list, from the real capture: what the window could
		// not see, rare traffic, and the egress each workload would lose.
		all := strings.Join(rep.Gaps, "\n")
		for _, want := range []string{"Observation window:", "nightly, weekly and failover-only traffic was almost certainly not seen",
			"nothing here is a namespace-wide default-deny"} {
			if !strings.Contains(all, want) {
				t.Errorf("report gaps lack %q:\n%s", want, all)
			}
		}
		for _, s := range rep.Suggestions {
			if s.Workload != "Pod/web" {
				continue
			}
			// The reasoning (brief 11.2): which peer, which direction, which
			// ports, and the observation behind each rule, from real traffic.
			var why []string
			for _, r := range s.Reasons {
				why = append(why, fmt.Sprintf("%s %s %s %v | %s | assumed=%v", r.Rule, r.Direction, r.Peer, r.Ports, strings.Join(r.Evidence, " / "), r.Assumed))
			}
			w := strings.Join(why, "\n")
			t.Logf("Pod/web WHY:\n%s", w)
			for _, want := range []*regexp.Regexp{
				regexp.MustCompile(`ingress\[\d\] ingress pods app=gateway\S* in namespace pp-edge \(pp-edge/Pod/gateway\) \[tcp/8080\] \| web <- pp-edge/gateway tcp/8080: \d+ connection\(s\), seen in \d+ sample\(s\)[^|]*\| assumed=false`),
				regexp.MustCompile(`egress\[\d\] egress pods behind service pp-app/api \(app=api\) \[tcp/9000\] \| web -> svc/pp-app/api tcp/9000: \d+ connection\(s\)[^|]*\| assumed=false`),
				regexp.MustCompile(`egress\[\d\] egress cluster DNS[^|]*\| ASSUMED, not observed[^|]*\| assumed=true`),
			} {
				if !want.MatchString(w) {
					t.Errorf("Pod/web's reasoning lacks %s", want)
				}
			}
			g := strings.Join(s.Gaps, "\n")
			t.Logf("Pod/web NOT COVERED:\n%s", g)
			// web calls api inside the cluster and nothing outside it.
			if !strings.Contains(g, "The workload would LOSE:") || !strings.Contains(g, "every address outside the cluster") ||
				!strings.Contains(g, "dependencies that were idle during the window") {
				t.Errorf("Pod/web's gaps should name the egress it would lose")
			}
		}
		y := podpeers(ctx, t, "suggest", "-o", filepath.Join(outDir, "e2e-policy.yaml"), capture)
		if y.code != 0 {
			t.Fatal(y.stderr)
		}
		if py, _ := os.ReadFile(filepath.Join(outDir, "e2e-policy.yaml")); !strings.Contains(string(py), "# NOT COVERED by this observation:") ||
			!strings.Contains(string(py), "would LOSE") || !strings.Contains(string(py), "NO POLICY SUGGESTED") {
			t.Error("policy.yaml should carry the gaps and the refusals as comments")
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

	t.Run("MCP serves the same data as the query interface, the visualization and suggest", func(t *testing.T) {
		// Brief section 12: the same data as the visualization and the query
		// interface, exposed over MCP. Each MCP answer must equal the CLI's
		// answer for the same real capture, not merely mention a few names.
		capture := filepath.Join(outDir, "e2e-capture.json")
		q := `{ pods { id probe { status } edges { direction port protocol open peer { id kind } } } edges(direction: "outbound") { pod { id } port } }`
		qj, _ := json.Marshal(q)
		calls := []string{
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"0"}}}`,
			`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"summary","arguments":{}}}`,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"query":` + string(qj) + `}}}`,
			`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"suggest_policies","arguments":{"namespace":"pp-app"}}}`,
			`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"peers","arguments":{"pod":"pp-app/web","direction":"inbound"}}}`,
			`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"list_pods","arguments":{"namespace":"pp-app"}}}`,
		}
		cmd := exec.Command(binary, "mcp", capture)
		cmd.Stdin = strings.NewReader(strings.Join(calls, "\n") + "\n")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		text := map[float64]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			var resp struct {
				ID     float64
				Result struct {
					Content []struct{ Text string }
					IsError bool
				}
			}
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				t.Fatalf("%v: %.200s", err, line)
			}
			if resp.Result.IsError || (resp.ID > 1 && len(resp.Result.Content) == 0) {
				t.Fatalf("MCP call %v failed: %.300s", resp.ID, line)
			}
			if len(resp.Result.Content) > 0 {
				text[resp.ID] = resp.Result.Content[0].Text
			}
		}
		// summary == the text visualization
		if want := podpeers(ctx, t, "render", "-format", "text", capture).stdout; text[2] != want {
			t.Errorf("MCP summary differs from `podpeers render -format text`:\n--- mcp\n%.600s\n--- cli\n%.600s", text[2], want)
		}
		// query == the GraphQL query interface
		var cli struct{ Data any }
		if err := json.Unmarshal([]byte(podpeers(ctx, t, "query", capture, q).stdout), &cli); err != nil {
			t.Fatal(err)
		}
		var mcpData any
		if err := json.Unmarshal([]byte(text[3]), &mcpData); err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(mcpData)
		b, _ := json.Marshal(cli.Data)
		if string(a) != string(b) || len(a) < 100 {
			t.Errorf("MCP query differs from `podpeers query`:\n--- mcp\n%.400s\n--- cli\n%.400s", a, b)
		}
		// suggest_policies == suggest
		if want := podpeers(ctx, t, "suggest", "-n", "pp-app", capture).stdout; text[4] != want {
			t.Errorf("MCP suggest_policies differs from `podpeers suggest -n pp-app`")
		}
		// peers and list_pods == the capture itself, which the web UI embeds
		res := load(t, capture)
		// web has edges both ways (inbound from gateway, outbound to api), so
		// a peers tool that ignored the direction would show here.
		var inbound []graph.Edge
		outbound := 0
		for _, e := range res.Edges {
			if e.Pod == "pp-app/web" && e.Direction == graph.Inbound {
				inbound = append(inbound, e)
			}
			if e.Pod == "pp-app/web" && e.Direction == graph.Outbound {
				outbound++
			}
		}
		if outbound == 0 {
			t.Fatal("precondition: pp-app/web should have outbound edges too")
		}
		var gotEdges []graph.Edge
		json.Unmarshal([]byte(text[5]), &gotEdges)
		ae, _ := json.Marshal(gotEdges)
		be, _ := json.Marshal(inbound)
		if string(ae) != string(be) || len(inbound) == 0 {
			t.Errorf("MCP peers(pp-app/web, inbound) differs from the capture's edges:\n--- mcp\n%s\n--- capture\n%s", ae, be)
		}
		var gotPods, wantPods []graph.Pod
		json.Unmarshal([]byte(text[6]), &gotPods)
		for _, p := range res.Pods {
			if p.Namespace == "pp-app" {
				wantPods = append(wantPods, p)
			}
		}
		ap, _ := json.Marshal(gotPods)
		bp, _ := json.Marshal(wantPods)
		if string(ap) != string(bp) {
			t.Errorf("MCP list_pods(pp-app) differs from the capture's pods")
		}
		html := podpeers(ctx, t, "render", "-format", "html", capture).stdout
		for _, p := range wantPods {
			if !strings.Contains(html, `"name":"`+p.Name+`"`) {
				t.Errorf("the web UI page lacks pod %s", p.ID())
			}
		}
		t.Logf("MCP == CLI for summary (%d bytes), query (%d bytes), suggest (%d bytes), peers (%d edges), list_pods (%d pods)",
			len(text[2]), len(a), len(text[4]), len(inbound), len(wantPods))
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

		// Now web also tries new connections while the old one stays up. The
		// failed connects must not count as the policy being exercised: the
		// pool hides a block, and the verdict is BROKEN, not OK.
		retry := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "exec", "-n", "pp-app", "web", "-c", "main", "--",
			"sh", "-c", "for i in 1 2 3 4 5 6 7 8 9 10; do timeout 2 nc -z -w 1 "+apiIP+" 9000; sleep 0.5; done")
		if err := retry.Start(); err != nil {
			t.Fatal(err)
		}
		pooled := filepath.Join(outDir, "e2e-after-deny-retry.json")
		r = podpeers(ctx, t, "capture", "-n", "pp-app", "-l", "app=web", "--duration", "8s", "--interval", "1s", "-o", pooled, "--summary", "none")
		_ = retry.Wait()
		if r.code != 0 {
			t.Fatalf("capture: %s", r.stderr)
		}
		d = podpeers(ctx, t, "diff", filepath.Join(outDir, "e2e-capture.json"), pooled)
		t.Logf("diff with failed reconnects exit=%d\n%s", d.code, d.stdout)
		if d.code != 4 || !strings.Contains(d.stdout, "blocked pp-app/Pod/web -> svc/pp-app/api tcp/9000") ||
			!strings.Contains(d.stdout, "every connection opened under the policy failed") {
			t.Fatalf("want BROKEN (exit 4): web -> api blocked behind its old connection, got exit %d", d.code)
		}
	})

	t.Run("UDP: connected sockets are seen, an unconnected server's clients only from the client side", func(t *testing.T) {
		out := filepath.Join(outDir, "e2e-udp.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-udp", "-l", "podpeers-e2e=udp", "--duration", "6s", "--interval", "1s", "-o", out)
		t.Logf("exit=%d\n%s", r.code, r.stderr)
		if r.code != 0 {
			t.Fatalf("capture exit %d", r.code)
		}
		res := load(t, out)
		expectEdges(t, res, "pp-udp/udp-client",
			"outbound svc/pp-udp/udp-echo udp/5353 open",
			"outbound svc/pp-udp/dnsd udp/5354 open")
		// busybox nc -u -l connect()s to its client: the server side names it.
		expectEdges(t, res, "pp-udp/udp-echo", "inbound pp-udp/udp-client udp/5353 open")
		// dnsd's socket is unconnected: /proc has no peer, so no edge at all,
		// only the listener. This is the inherent UDP blind spot.
		expectEdges(t, res, "pp-udp/dnsd")
		listens := false
		for _, p := range res.Pods {
			if p.ID() == "pp-udp/dnsd" {
				for _, l := range p.Listening {
					listens = listens || (l.Protocol == "udp" && l.Port == 5354)
				}
			}
		}
		if !listens {
			t.Error("dnsd's unconnected UDP listener on 5354 should be recorded")
		}
		if !strings.Contains(strings.Join(res.Limits, " "), "pp-udp/dnsd udp/5354") {
			t.Errorf("limits should name dnsd's unconnected UDP port: %v", res.Limits)
		}
	})

	t.Run("sub-second interval is honoured, timed and costed, not rounded", func(t *testing.T) {
		out := filepath.Join(outDir, "e2e-subsecond.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-udp", "-l", "app=udp-client", "--duration", "4s", "--interval", "200ms", "-o", out)
		t.Logf("exit=%d\n%s", r.code, r.stderr)
		if r.code != 0 {
			t.Fatalf("capture exit %d", r.code)
		}
		for _, want := range []string{"WARNING: --interval 200ms costs about 10 process starts per second", "sampling every 200ms for 4s: about 21 samples per pod"} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("stderr missing %q", want)
			}
		}
		res := load(t, out)
		if res.Window.Interval != "200ms" {
			t.Errorf("window interval = %q; want 200ms (not rounded)", res.Window.Interval)
		}
		p, _ := probeOf(res, "pp-udp/udp-client")
		t.Logf("samples taken at 200ms over 4s: %d", p.Samples)
		// 4s / 200ms + 1 = 21. Too few means the interval was rounded up
		// (1s gives 5); too many means it collapsed and the sampler spun.
		if p.Samples < 15 || p.Samples > 25 {
			t.Errorf("want about 21 samples at 200ms over 4s, got %d (a rounded 1s interval gives 5; a collapsed 0s interval spins)", p.Samples)
		}
		bad := podpeers(ctx, t, "capture", "-n", "pp-udp", "-l", "app=udp-client", "--duration", "4s", "--interval", "50ms")
		if bad.code != 1 || !strings.Contains(bad.stderr, "below the 100ms minimum") {
			t.Errorf("50ms must be refused loudly, got exit %d: %s", bad.code, bad.stderr)
		}
	})

	t.Run("StatefulSet, DaemonSet and CronJob targets are captured, grouped and rendered", func(t *testing.T) {
		// Trigger a CronJob run and wait for its pod: it holds a connection
		// to db-0 for 150s, long enough to be captured.
		kubectl(t, "create", "job", "--from=cronjob/report", "report-e2e", "-n", "pp-kinds")
		kubectl(t, "wait", "-n", "pp-kinds", "--for=condition=Ready", "pod", "-l", "job-name=report-e2e", "--timeout=90s")
		time.Sleep(4 * time.Second)
		out := filepath.Join(outDir, "e2e-kinds.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-kinds", "-l", "podpeers-e2e=kinds", "--duration", "8s", "--interval", "1s", "-o", out)
		t.Logf("exit=%d\n%s", r.code, r.stderr)
		if r.code != 0 {
			t.Fatalf("capture exit %d", r.code)
		}
		res := load(t, out)

		// Every pod of every kind was observed, under its controller's name.
		byWorkload := map[string][]graph.Pod{}
		for _, p := range res.Pods {
			if p.Probe.Status == graph.ProbeObserved {
				byWorkload[p.Workload] = append(byWorkload[p.Workload], p)
			}
		}
		for wl, n := range map[string]int{"StatefulSet/db": 2, "DaemonSet/node-agent": 2, "CronJob/report": 1} {
			if len(byWorkload[wl]) != n {
				t.Errorf("%s: %d observed pods; want %d (workloads seen: %v)", wl, len(byWorkload[wl]), n, keys(byWorkload))
			}
		}
		if a := byWorkload["DaemonSet/node-agent"]; len(a) == 2 && a[0].Node == a[1].Node {
			t.Errorf("DaemonSet pods should be on different nodes: %s, %s", a[0].Node, a[1].Node)
		}

		// Known traffic, per kind.
		for _, a := range byWorkload["DaemonSet/node-agent"] {
			expectEdges(t, res, a.ID(), "outbound svc/pp-kinds/db-rw tcp/5432 open")
		}
		var report graph.Pod
		if rp := byWorkload["CronJob/report"]; len(rp) == 1 {
			report = rp[0]
			// Headless DNS resolves to the pod IP: the peer is the pod itself.
			expectEdges(t, res, report.ID(), "outbound pp-kinds/db-0 tcp/5432 open")
		}
		inbound := map[string]bool{}
		for _, e := range res.Edges {
			if strings.HasPrefix(e.Pod, "pp-kinds/db-") && e.Direction == graph.Inbound {
				inbound[e.Peer.ID()] = true
			}
		}
		for _, p := range append(byWorkload["DaemonSet/node-agent"], report) {
			if p.Name != "" && !inbound[p.ID()] {
				t.Errorf("no db pod saw %s connect (db inbound peers: %v)", p.ID(), inbound)
			}
		}

		// Rendered in every format.
		for _, f := range []string{"text", "dot", "html"} {
			rr := podpeers(ctx, t, "render", "-format", f, "-o", filepath.Join(outDir, "e2e-kinds."+f), out)
			b, _ := os.ReadFile(filepath.Join(outDir, "e2e-kinds."+f))
			if rr.code != 0 || !strings.Contains(string(b), "db-0") || !strings.Contains(string(b), "node-agent") || !strings.Contains(string(b), "report-e2e") {
				t.Errorf("render %s: exit %d, %d bytes", f, rr.code, len(b))
			}
		}

		// One policy per workload, selecting by stable labels only.
		s := podpeers(ctx, t, "suggest", "-format", "json", out)
		var rep struct {
			Suggestions []struct {
				Workload, Refused string
				Policy            *netv1.NetworkPolicy
			}
		}
		if err := json.Unmarshal([]byte(s.stdout), &rep); err != nil {
			t.Fatal(err)
		}
		volatile := []string{"statefulset.kubernetes.io/pod-name", "apps.kubernetes.io/pod-index", "controller-revision-hash",
			"pod-template-generation", "job-name", "batch.kubernetes.io/job-name", "controller-uid", "batch.kubernetes.io/controller-uid"}
		got := map[string]int{}
		for _, sg := range rep.Suggestions {
			got[sg.Workload]++
			if sg.Policy == nil {
				t.Errorf("%s refused: %s", sg.Workload, sg.Refused)
				continue
			}
			sels := []map[string]string{sg.Policy.Spec.PodSelector.MatchLabels}
			for _, in := range sg.Policy.Spec.Ingress {
				for _, f := range in.From {
					if f.PodSelector != nil {
						sels = append(sels, f.PodSelector.MatchLabels)
					}
				}
			}
			for _, sel := range sels {
				for _, v := range volatile {
					if _, bad := sel[v]; bad {
						t.Errorf("%s: selector uses per-pod/per-run label %q: %v", sg.Workload, v, sel)
					}
				}
			}
		}
		t.Logf("suggestions per workload: %v", got)
		for _, wl := range []string{"StatefulSet/db", "DaemonSet/node-agent", "CronJob/report"} {
			if got[wl] != 1 {
				t.Errorf("want exactly one suggestion for %s, got %d (all: %v)", wl, got[wl], got)
			}
		}
		y := podpeers(ctx, t, "suggest", "-n", "pp-kinds", "-o", filepath.Join(outDir, "e2e-kinds-policy.yaml"), out)
		if y.code != 0 {
			t.Fatal(y.stderr)
		}
		kubectl(t, "apply", "--dry-run=server", "-f", filepath.Join(outDir, "e2e-kinds-policy.yaml"))
	})

	t.Run("a busy pod's samples survive kubelet log rotation", func(t *testing.T) {
		time.Sleep(10 * time.Second) // let the busy pod open its connections
		out := filepath.Join(outDir, "e2e-busy.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-busy", "-l", "app=busy", "--duration", "60s", "--interval", "200ms", "-o", out, "--summary", "none")
		t.Logf("exit=%d\n%s", r.code, r.stderr)
		// Prove the log really rotated during this capture, or the test proves nothing.
		m := regexp.MustCompile(`added (podpeers-[a-z0-9]+)`).FindStringSubmatch(r.stderr)
		if m == nil {
			t.Fatal("no debug container name in the output")
		}
		uid := strings.TrimSpace(kubectl(t, "get", "pod", "busy", "-n", "pp-busy", "-o", "jsonpath={.metadata.uid}"))
		node := strings.TrimSpace(kubectl(t, "get", "pod", "busy", "-n", "pp-busy", "-o", "jsonpath={.spec.nodeName}"))
		files := kubectl(t, "get", "--raw", "/api/v1/nodes/"+node+"/proxy/logs/pods/pp-busy_busy_"+uid+"/"+m[1]+"/")
		t.Logf("sampler log files on %s: %s", node, regexp.MustCompile(`href="[^"]*"`).FindAllString(files, -1))
		if !strings.Contains(files, `href="0.log.`) {
			t.Fatal("the sampler log did not rotate; raise the socket count or duration so this test exercises rotation")
		}
		if r.code != 0 {
			t.Fatalf("capture exit %d", r.code)
		}
		p, _ := probeOf(load(t, out), "pp-busy/busy")
		t.Logf("busy pod probe: %+v", p)
		if p.Status != graph.ProbeObserved || !p.Complete || p.Samples < 295 || p.Samples > 305 {
			t.Fatalf("want all ~301 samples, complete, despite rotation; got %+v", p)
		}
	})

	t.Run("debug container is admitted where Pod Security restricted is enforced", func(t *testing.T) {
		// Enforcement must really be on, or admitting podpeers proves nothing.
		out, err := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "run", "unhardened", "-n", "pp-strict",
			"--image=busybox:1.36", "--restart=Never", "--dry-run=server", "--command", "--", "sleep", "1").CombinedOutput()
		t.Logf("a pod without a restricted securityContext: err=%v\n%s", err, out)
		if err == nil || !strings.Contains(string(out), "violates PodSecurity") {
			t.Fatal("pp-strict does not enforce the restricted Pod Security Standard")
		}
		capture := filepath.Join(t.TempDir(), "strict.json")
		r := podpeers(ctx, t, "capture", "-n", "pp-strict", "-l", "podpeers-e2e=strict", "--duration", "6s", "--interval", "1s", "-o", capture)
		t.Logf("exit=%d\n%s", r.code, r.stderr)
		if r.code != 0 {
			t.Fatalf("capture in a restricted namespace: exit %d", r.code)
		}
		res := load(t, capture)
		expectEdges(t, res, "pp-strict/vaultd", "inbound pp-strict/auditor tcp/9000 open")
		expectEdges(t, res, "pp-strict/auditor", "outbound svc/pp-strict/vaultd tcp/9000 open")
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
		// Its own file, so it keeps the cluster's context name: the node gate
		// holds a k3d-NAME context to cluster NAME's nodes.
		limited.Contexts[kubeCtx] = &clientcmdapi.Context{Cluster: "e2e", AuthInfo: "limited"}
		limited.CurrentContext = kubeCtx
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

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
