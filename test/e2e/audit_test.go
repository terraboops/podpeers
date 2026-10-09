//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/terraboops/podpeers/internal/graph"
	"github.com/terraboops/podpeers/internal/policy"
)

// TestAuditFixes proves on a real cluster the fixes from the security audit
// that unit tests alone could only model: what the API server really accepts
// in pod metadata, what kubectl really applies, how a real node's IPAM really
// reuses addresses, and what the real binary serves. testdata/audit.yaml
// describes the workloads.
func TestAuditFixes(t *testing.T) {
	ctx := context.Background()
	manifest := filepath.Join("testdata", "audit.yaml")
	reuser := filepath.Join(t.TempDir(), "reuser.yaml")
	os.WriteFile(reuser, []byte(`apiVersion: v1
kind: Pod
metadata:
  name: reuser
  namespace: pp-xa
  labels: {app: reuser, podpeers-e2e: audit}
spec:
  terminationGracePeriodSeconds: 1
  nodeName: k3d-podpeers-e2e-agent-0
  containers:
  - name: main
    image: busybox:1.36
    imagePullPolicy: IfNotPresent
    command: ["sh", "-c", "until nc -z -w 2 web 8080; do sleep 1; done; sleep 86400 | nc web 8080"]
`), 0o644)
	del := func() {
		for _, f := range []string{reuser, manifest} {
			exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx,
				"delete", "-f", f, "--ignore-not-found", "--wait=true", "--timeout=120s").Run()
		}
	}
	del()
	t.Cleanup(func() {
		if os.Getenv("PODPEERS_E2E_KEEP") == "" {
			del()
		}
	})
	kubectl(t, "apply", "-f", manifest)
	kubectl(t, "wait", "-n", "pp-xa", "--for=condition=Ready", "--timeout=120s", "pod/gw", "pod/web")
	kubectl(t, "rollout", "status", "-n", "pp-xa", "deployment/web", "--timeout=120s")
	kubectl(t, "rollout", "status", "-n", "pp-xb", "deployment/web", "--timeout=120s")
	kubectl(t, "wait", "-n", "pp-xb", "--for=condition=Ready", "--timeout=60s", "pod/client")
	kubectl(t, "wait", "-n", "pp-xz", "--for=jsonpath={.status.phase}=Succeeded", "--timeout=60s", "pod/stale")

	// Address reuse, for real and unaided: the stale pod has finished and
	// still reports its IP. The node's host-local IPAM hands out the next free
	// address after its cursor and wraps at the end of the node's range, so
	// placeholder pods walk the cursor round until the finished pod's address
	// is next; then the reuser is created and the allocator gives it that
	// address. Nothing touches IPAM state.
	staleIP := netip.MustParseAddr(strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-xz", "stale", "-o", "jsonpath={.status.podIP}")))
	walkIPAMTo(t, "k3d-podpeers-e2e-agent-0", staleIP)
	kubectl(t, "apply", "-f", reuser)
	kubectl(t, "wait", "-n", "pp-xa", "--for=condition=Ready", "--timeout=60s", "pod/reuser")
	reuserIP := strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-xa", "reuser", "-o", "jsonpath={.status.podIP}"))
	if reuserIP != staleIP.String() {
		t.Fatalf("precondition: reuser got %s, not the finished pod's %s", reuserIP, staleIP)
	}
	if again := strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-xz", "stale", "-o", "jsonpath={.status.phase} {.status.podIP}")); again != "Succeeded "+staleIP.String() {
		t.Fatalf("precondition: the finished pod should still report the address, got %q", again)
	}
	t.Logf("the finished pod pp-xz/stale and the running pod pp-xa/reuser both report the same address")
	time.Sleep(4 * time.Second) // let the long-lived connections establish

	capture := filepath.Join(outDir, "e2e-audit.json")
	r := podpeers(ctx, t, "capture", "-A", "-l", "podpeers-e2e=audit", "--duration", "10s", "--interval", "1s", "-o", capture)
	t.Logf("capture exit=%d\n%s", r.code, r.stderr)
	if r.code != 0 {
		t.Fatalf("capture exit %d", r.code)
	}
	res := load(t, capture)
	esc := "\\" + "u001b" // what Printable turns ESC into

	suggest := func(t *testing.T, ns string) policy.Report {
		t.Helper()
		r := podpeers(ctx, t, "suggest", "-n", ns, "-format", "json", capture)
		var rep policy.Report
		if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
			t.Fatalf("suggest -format json: %v\n%s", err, r.stderr)
		}
		return rep
	}
	find := func(t *testing.T, rep policy.Report, workload string) policy.Suggestion {
		t.Helper()
		for _, s := range rep.Suggestions {
			if s.Workload == workload {
				return s
			}
		}
		t.Fatalf("no suggestion for %s", workload)
		return policy.Suggestion{}
	}
	peers := func(s policy.Suggestion) string {
		var b strings.Builder
		for _, r := range s.Reasons {
			fmt.Fprintf(&b, "%s allows %s on %s\n", r.Rule, r.Peer, strings.Join(r.Ports, ","))
		}
		return b.String()
	}

	t.Run("the API server accepts a hostile ownerReference, and capture records it as is", func(t *testing.T) {
		for _, p := range res.Pods {
			if p.ID() == "pp-xa/gw" {
				if !strings.Contains(p.Workload, "\n---\napiVersion: v1\nkind: ConfigMap") || !strings.ContainsRune(p.Workload, 0x1b) {
					t.Fatalf("gw workload = %q", p.Workload)
				}
				t.Logf("gw's workload, from the API server: %q", p.Workload)
				return
			}
		}
		t.Fatal("gw not in the capture")
	})

	t.Run("suggest keeps hostile names in comments; applying it creates one NetworkPolicy per workload and nothing else", func(t *testing.T) {
		pol := filepath.Join(t.TempDir(), "policy.yaml")
		if r := podpeers(ctx, t, "suggest", "-n", "pp-xa", "-o", pol, capture); r.code != 0 {
			t.Fatalf("suggest: %s", r.stderr)
		}
		y, _ := os.ReadFile(pol)
		for _, c := range string(y) {
			if c != '\n' && !unicode.IsPrint(c) {
				t.Fatalf("unprintable %U in policy.yaml", c)
			}
		}
		if !strings.Contains(string(y), "Gateway/gw"+esc) {
			t.Errorf("the hostile name should be visible, escaped:\n%s", y)
		}
		applied := kubectl(t, "apply", "-f", pol)
		defer exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", pol, "--ignore-not-found").Run()
		t.Logf("kubectl apply:\n%s", applied)
		for _, line := range strings.Split(strings.TrimSpace(applied), "\n") {
			if !strings.HasPrefix(line, "networkpolicy.networking.k8s.io/") {
				t.Errorf("kubectl applied something that is not a NetworkPolicy: %s", line)
			}
		}
		if cm := kubectl(t, "get", "configmap", "-A", "--field-selector", "metadata.name=injected", "-o", "name"); strings.TrimSpace(cm) != "" {
			t.Fatalf("the hostile ownerReference created %s", cm)
		}
		rep := suggest(t, "pp-xa")
		names := map[string]string{}
		for _, s := range rep.Suggestions {
			if s.Policy == nil {
				continue
			}
			if other, dup := names[s.Policy.Name]; dup {
				t.Errorf("%s and %s share the name %s", other, s.Workload, s.Policy.Name)
			}
			names[s.Policy.Name] = s.Workload
		}
		dep, bare := find(t, rep, "Deployment/web"), find(t, rep, "Pod/web")
		if dep.Policy == nil || bare.Policy == nil {
			t.Fatalf("both webs should get a policy: %q / %q", dep.Refused, bare.Refused)
		}
		inCluster := strings.Fields(kubectl(t, "get", "networkpolicy", "-n", "pp-xa", "-o", "jsonpath={.items[*].metadata.name}"))
		t.Logf("NetworkPolicies in pp-xa after apply: %v (Deployment/web=%s, Pod/web=%s)", inCluster, dep.Policy.Name, bare.Policy.Name)
		if len(inCluster) != len(names) {
			t.Fatalf("%d suggested policies, %d in the cluster: one overwrote another", len(names), len(inCluster))
		}
		got := kubectl(t, "get", "networkpolicy", "-n", "pp-xa", dep.Policy.Name, "-o", "jsonpath={.spec.podSelector.matchLabels.app}")
		if got != "web" {
			t.Fatalf("Deployment/web's policy in the cluster selects app=%s", got)
		}
	})

	t.Run("a Service is ingress evidence only in its own namespace", func(t *testing.T) {
		pre := false
		for _, e := range res.Edges {
			if e.Pod == "pp-xb/client" && e.Direction == graph.Outbound && e.Peer.ID() == "svc/pp-xb/web" && !e.Attempted {
				pre = true
			}
		}
		if !pre {
			t.Fatal("precondition: pp-xb/client -> svc/pp-xb/web was not captured")
		}
		if xb := peers(find(t, suggest(t, "pp-xb"), "Deployment/web")); !strings.Contains(xb, "app=client") {
			t.Fatalf("control: pp-xb's web should admit its client:\n%s", xb)
		}
		xa := peers(find(t, suggest(t, "pp-xa"), "Deployment/web"))
		t.Logf("pp-xa/Deployment/web rules:\n%s", xa)
		if strings.Contains(xa, "pp-xb") || strings.Contains(xa, "app=client") {
			t.Fatalf("pp-xb's client never talked to pp-xa's web, yet:\n%s", xa)
		}
	})

	t.Run("a running pod owns an address a finished pod still reports", func(t *testing.T) {
		// The capture keeps only targets and the pods they talked to, so the
		// finished pod is checked in the cluster: it still claims the address.
		if got := strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-xz", "stale", "-o", "jsonpath={.status.phase} {.status.podIP}")); got != "Succeeded "+reuserIP {
			t.Fatalf("precondition: pp-xz/stale should still report %s, got %q", reuserIP, got)
		}
		var inbound []string
		for _, e := range res.Edges {
			if strings.HasPrefix(e.Pod, "pp-xa/web-") && e.Direction == graph.Inbound {
				inbound = append(inbound, e.Peer.ID())
			}
		}
		t.Logf("pp-xa/Deployment/web inbound peers: %v", inbound)
		if !strings.Contains(strings.Join(inbound, " "), "pp-xa/reuser") || strings.Contains(strings.Join(inbound, " "), "pp-xz/") {
			t.Fatalf("the reused address should resolve to pp-xa/reuser, got %v", inbound)
		}
		if xa := peers(find(t, suggest(t, "pp-xa"), "Deployment/web")); strings.Contains(xa, "pp-xz") || !strings.Contains(xa, "app=reuser") {
			t.Fatalf("policy should admit reuser, not the finished pod's namespace:\n%s", xa)
		}
	})

	t.Run("diff and render escape hostile names; flows nobody re-observed are inconclusive", func(t *testing.T) {
		xb := filepath.Join(outDir, "e2e-audit-xb.json")
		if r := podpeers(ctx, t, "capture", "-n", "pp-xb", "-l", "podpeers-e2e=audit", "--duration", "6s", "--interval", "1s", "-o", xb, "--summary", "none"); r.code != 0 {
			t.Fatalf("capture: %s", r.stderr)
		}
		d := podpeers(ctx, t, "diff", xb, capture)
		t.Logf("diff (pp-xb only -> everything) exit=%d\n%s", d.code, d.stdout)
		if strings.ContainsRune(d.stdout, 0x1b) || !strings.Contains(d.stdout, esc) {
			t.Fatal("diff should show the hostile name escaped, with no raw ESC")
		}
		for _, line := range strings.Split(d.stdout, "\n") {
			if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "apiVersion") || strings.HasPrefix(line, "kind:") {
				t.Fatalf("a hostile name added a line to the report: %q", line)
			}
		}
		// Listing pp-xb with none of its pods makes them all count as started
		// after the change, so its long-lived connections are not
		// "preexisting": the only thing left unproven is pp-xa, unobserved.
		existing := filepath.Join(t.TempDir(), "existing.txt")
		os.WriteFile(existing, []byte("pp-xb/none\n"), 0o644)
		d = podpeers(ctx, t, "diff", "-existing-pods", existing, capture, xb)
		t.Logf("diff (everything -> pp-xb only) exit=%d\n%s", d.code, d.stdout)
		if d.code != 5 || !strings.Contains(d.stdout, "unverifiable pp-xa/") || strings.Contains(d.stdout, "preexisting") ||
			strings.Contains(d.stdout, "every flow seen before was seen after") ||
			!strings.Contains(d.stdout, "VERDICT: INCONCLUSIVE") {
			t.Fatalf("pp-xa's flows were not re-observed: want INCONCLUSIVE (exit 5), got exit %d", d.code)
		}
		for _, format := range []string{"text", "dot"} {
			out := podpeers(ctx, t, "render", "-format", format, capture).stdout
			if strings.ContainsRune(out, 0x1b) || strings.Contains(out, "\n---\n") {
				t.Errorf("render -format %s passed the hostile name through raw", format)
			}
		}
	})

	t.Run("serve on a real capture answers only its own origin, and a cyclic query is cut off", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		l.Close()
		sctx, cancel := context.WithCancel(ctx)
		defer cancel()
		srv := exec.CommandContext(sctx, binary, "serve", "-addr", addr, capture)
		if err := srv.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cancel(); srv.Wait() }()
		get := func(host, origin, query string) (int, string) {
			req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/graphql?query="+url.QueryEscape(query), nil)
			req.Host = host
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
			if err != nil {
				return 0, err.Error()
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b)
		}
		for i := 0; i < 50; i++ {
			if c, _ := get(addr, "", "{ window { interval } }"); c == 200 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if c, body := get(addr, "http://"+addr, "{ pods { id } }"); c != 200 || !strings.Contains(body, "pp-xa/gw") {
			t.Fatalf("own origin: %d %.200s", c, body)
		}
		if c, _ := get("rebind.example.test:"+strings.Split(addr, ":")[1], "", "{ pods { id } }"); c != http.StatusMisdirectedRequest {
			t.Fatalf("a rebound name got %d, want 421", c)
		}
		if c, _ := get(addr, "https://evil.example.test", "{ pods { id } }"); c != http.StatusForbidden {
			t.Fatalf("a foreign Origin got %d, want 403", c)
		}
		q := "id"
		// gw has two edges here, so each level doubles the work: 20 levels ask
		// for about a million pods.
		for i := 0; i < 20; i++ {
			q = "id edges { pod { " + q + " } }"
		}
		start := time.Now()
		c, body := get(addr, "", "{ pods { "+q+" } }")
		t.Logf("a 20-deep cyclic query: %d in %s, %d bytes", c, time.Since(start).Round(time.Millisecond), len(body))
		if !strings.Contains(body, "query too large") || time.Since(start) > 20*time.Second {
			t.Fatalf("the cyclic query should be refused quickly: %.300s", body)
		}
	})

	t.Run("serve under a hard memory cap refuses a cyclic query and survives", func(t *testing.T) {
		// The real server, built for the node, runs as a pod with a 256 MiB
		// memory limit (a cgroup the kernel enforces). Unbounded, the 20-deep
		// cyclic query below needs gigabytes and the container is OOM-killed;
		// bounded, it is refused and the container lives, its memory peak
		// under the cap.
		node := "k3d-" + strings.TrimPrefix(kubeCtx, "k3d-") + "-server-0"
		arch, err := exec.Command("docker", "exec", node, "uname", "-m").Output()
		if err != nil {
			t.Fatal(err)
		}
		goarch := map[string]string{"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}[strings.TrimSpace(string(arch))]
		bin := filepath.Join(t.TempDir(), "podpeers")
		build := exec.Command("go", "build", "-o", bin, "../../cmd/podpeers")
		build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch)
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building for %s: %v\n%s", goarch, err, out)
		}
		for _, cp := range [][]string{{"exec", node, "mkdir", "-p", "/opt/podpeers-e2e"}, {"cp", bin, node + ":/opt/podpeers-e2e/podpeers"},
			{"cp", capture, node + ":/opt/podpeers-e2e/capture.json"}} {
			if out, err := exec.Command("docker", cp...).CombinedOutput(); err != nil {
				t.Fatalf("docker %v: %v\n%s", cp, err, out)
			}
		}
		pod := filepath.Join(t.TempDir(), "gql.yaml")
		os.WriteFile(pod, []byte(`apiVersion: v1
kind: Pod
metadata: {name: gqlcap, namespace: pp-xa, labels: {app: gqlcap}}
spec:
  nodeName: `+node+`
  terminationGracePeriodSeconds: 1
  restartPolicy: Always
  containers:
  - name: serve
    image: busybox:1.36
    imagePullPolicy: IfNotPresent
    command: ["/opt/pp/podpeers", "serve", "-addr", "0.0.0.0:8080", "/opt/pp/capture.json"]
    resources:
      requests: {memory: 256Mi}
      limits: {memory: 256Mi}
    volumeMounts: [{name: pp, mountPath: /opt/pp, readOnly: true}]
  volumes: [{name: pp, hostPath: {path: /opt/podpeers-e2e, type: Directory}}]
`), 0o644)
		kubectl(t, "apply", "-f", pod)
		defer exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "-f", pod, "--wait=false").Run()
		kubectl(t, "wait", "-n", "pp-xa", "--for=condition=Ready", "--timeout=60s", "pod/gqlcap")
		max := strings.TrimSpace(kubectl(t, "exec", "-n", "pp-xa", "gqlcap", "--", "cat", "/sys/fs/cgroup/memory.max"))
		if max != "268435456" {
			t.Fatalf("precondition: the container's cgroup memory.max is %q, want 268435456 (256 MiB)", max)
		}

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := strings.Split(l.Addr().String(), ":")[1]
		l.Close()
		pf := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "port-forward", "-n", "pp-xa", "pod/gqlcap", port+":8080")
		if err := pf.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { pf.Process.Kill(); pf.Wait() }()
		addr := "127.0.0.1:" + port
		get := func(query string) (int, string, error) {
			resp, err := (&http.Client{Timeout: 60 * time.Second}).Get("http://" + addr + "/graphql?query=" + url.QueryEscape(query))
			if err != nil {
				return 0, "", err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return resp.StatusCode, string(b), nil
		}
		for i := 0; i < 50; i++ {
			if c, _, err := get("{ window { interval } }"); err == nil && c == 200 {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		q := "id"
		for i := 0; i < 20; i++ {
			q = "id edges { pod { " + q + " } }"
		}
		start := time.Now()
		c, body, err := get("{ pods { " + q + " } }")
		took := time.Since(start).Round(time.Millisecond)
		state := strings.TrimSpace(kubectl(t, "get", "pod", "-n", "pp-xa", "gqlcap", "-o",
			"jsonpath={.status.containerStatuses[0].restartCount} {.status.containerStatuses[0].lastState.terminated.reason}"))
		t.Logf("20-deep cyclic query under a 256 MiB cap: status %d, %d bytes, %s, err=%v; container restarts/last reason: %q", c, len(body), took, err, state)
		if err != nil || !strings.Contains(body, "query too large") {
			t.Fatalf("the cyclic query should be refused by the bound under the cap (container restarts/last reason: %q)", state)
		}
		if state != "0" {
			t.Fatalf("the server died under the cap (restarts/last reason: %q)", state)
		}
		if c, body, _ := get("{ pods { id } }"); c != 200 || !strings.Contains(body, "pp-xa/gw") {
			t.Fatalf("the server should still answer after refusing: %d %.200s", c, body)
		}
		// memory.peak needs a 5.19+ kernel; where it exists, log how close it came.
		if peak, err := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "exec", "-n", "pp-xa", "gqlcap", "--",
			"cat", "/sys/fs/cgroup/memory.peak").Output(); err == nil {
			t.Logf("cgroup memory.peak %s bytes of memory.max %s", strings.TrimSpace(string(peak)), max)
		}
	})

	t.Run("a loopback API server behind a proxy-url is refused before anything is touched", func(t *testing.T) {
		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Clusters[cfg.Contexts[kubeCtx].Cluster].ProxyURL = "socks5://127.0.0.1:9"
		proxied := filepath.Join(t.TempDir(), "kubeconfig")
		if err := clientcmd.WriteToFile(*cfg, proxied); err != nil {
			t.Fatal(err)
		}
		before := len(ephemeral(t, "pp-xa", "web"))
		r := podpeers(ctx, t, "capture", "--kubeconfig", proxied, "-n", "pp-xa", "-l", "podpeers-e2e=audit", "--duration", "5s", "--interval", "1s",
			"-o", filepath.Join(t.TempDir(), "x.json"))
		t.Logf("exit=%d stderr=%s", r.code, r.stderr)
		if r.code != 2 || !strings.Contains(r.stderr, "proxy-url") {
			t.Fatalf("want refusal (exit 2) naming the proxy-url, got %d", r.code)
		}
		if after := len(ephemeral(t, "pp-xa", "web")); after != before {
			t.Fatalf("pp-xa/web gained %d debug container(s) despite the refusal", after-before)
		}
	})
}

// walkIPAMTo leaves node's host-local IPAM cursor just before target, using
// only pods: placeholders take the free addresses between the cursor and the
// target (at most 60 at a time, the node's pod limit permitting), and are
// deleted again so the walk can go on round the range.
func walkIPAMTo(t *testing.T, node string, target netip.Addr) {
	t.Helper()
	cidr := netip.MustParsePrefix(strings.TrimSpace(kubectl(t, "get", "node", node, "-o", "jsonpath={.spec.podCIDR}")))
	first := cidr.Addr().Next().Next() // .1 is the bridge
	last := first
	for a := first; cidr.Contains(a.Next()); a = a.Next() {
		last = a // the broadcast address is never handed out
	}
	next := func(a netip.Addr) netip.Addr {
		if a == last {
			return first
		}
		return a.Next()
	}
	inUse := func() map[netip.Addr]bool {
		u := map[netip.Addr]bool{}
		out := kubectl(t, "get", "pods", "-A", "--field-selector", "spec.nodeName="+node, "-o",
			`jsonpath={range .items[*]}{.status.phase}|{.spec.hostNetwork}|{.status.podIP}{"\n"}{end}`)
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			// hostNetwork is empty, not "false", for ordinary pods: split on
			// a separator, not on whitespace.
			f := strings.Split(l, "|")
			if len(f) == 3 && (f[0] == "Running" || f[0] == "Pending") && f[1] != "true" {
				if a, err := netip.ParseAddr(f[2]); err == nil {
					u[a] = true
				}
			}
		}
		return u
	}
	placeholders := func(n, round int) []netip.Addr {
		var docs []string
		for i := 0; i < n; i++ {
			docs = append(docs, fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata: {name: churn-%d-%d, namespace: pp-xz, labels: {app: churn}}
spec:
  nodeName: %s
  terminationGracePeriodSeconds: 0
  containers: [{name: main, image: busybox:1.36, imagePullPolicy: IfNotPresent, command: ["sleep", "3600"]}]`, round, i, node))
		}
		f := filepath.Join(t.TempDir(), "churn.yaml")
		os.WriteFile(f, []byte(strings.Join(docs, "\n---\n")), 0o644)
		kubectl(t, "apply", "-f", f)
		var ips []netip.Addr
		for i := 0; i < 120; i++ {
			ips = nil
			for _, w := range strings.Fields(kubectl(t, "get", "pods", "-n", "pp-xz", "-l", "app=churn", "-o", "jsonpath={.items[*].status.podIP}")) {
				if a, err := netip.ParseAddr(w); err == nil {
					ips = append(ips, a)
				}
			}
			if len(ips) == n {
				break
			}
			time.Sleep(time.Second)
		}
		kubectl(t, "delete", "pods", "-n", "pp-xz", "-l", "app=churn", "--wait=true", "--timeout=120s")
		if len(ips) != n {
			t.Fatalf("only %d of %d placeholder pods got an address", len(ips), n)
		}
		return ips
	}
	// furthest returns the address handed out last: the one furthest round
	// the range from the cursor.
	furthest := func(from netip.Addr, ips []netip.Addr) netip.Addr {
		best, bestD := from, -1
		for _, a := range ips {
			d := 0
			for b := next(from); b != a; b = next(b) {
				d++
			}
			if d > bestD {
				best, bestD = a, d
			}
		}
		return best
	}
	cursor := placeholders(1, 0)[0]
	for round := 1; round <= 30; round++ {
		u := inUse()
		gap := 0
		for a := next(cursor); a != target; a = next(a) {
			if !u[a] {
				gap++
			}
		}
		if gap == 0 {
			t.Logf("walked node %s's IPAM round to %s in %d round(s) of placeholder pods", node, target, round)
			return
		}
		// Near the target go one pod at a time, so a miscounted address can
		// overshoot by one at most, not by a whole batch.
		n := gap
		switch {
		case n > 60:
			n = 60
		case n > 5:
			n -= 5
		default:
			n = 1
		}
		cursor = furthest(cursor, placeholders(n, round))
	}
	t.Fatalf("could not walk node %s's IPAM round to %s", node, target)
}
