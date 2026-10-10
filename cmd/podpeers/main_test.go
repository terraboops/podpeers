package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/terraboops/podpeers/internal/graph"
)

const fixture = "../../internal/testdata/capture.json"

// kubeconfig writes a kubeconfig whose single context points at server.
func kubeconfig(t *testing.T, context, server string) string {
	t.Helper()
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: %s
    insecure-skip-tls-verify: true
users:
- name: u
  user:
    token: not-a-real-token
contexts:
- name: %s
  context: {cluster: c, user: u, namespace: shop}
current-context: %s
`, server, context, context)
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// apiServer is a stand-in API server on loopback that counts every request, so
// tests can prove a refusal happened before any traffic.
func apiServer(t *testing.T, providerID string) (*httptest.Server, *int64) {
	var hits int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/nodes" {
			fmt.Fprintf(w, `{"kind":"NodeList","apiVersion":"v1","items":[{"metadata":{"name":"n1"},"spec":{"providerID":%q}}]}`, providerID)
			return
		}
		http.Error(w, `{"kind":"Status","status":"Failure","code":404}`, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCaptureRefusesNonLocalContextWithoutAnyRequest(t *testing.T) {
	// The API server is real and reachable on loopback, but the context name is
	// not a local-cluster name: the default must be refusal, with zero requests.
	srv, hits := apiServer(t, "k3s://n1")
	kc := kubeconfig(t, "prod-eu", srv.URL)
	code, _, stderr := runCLI("capture", "--kubeconfig", kc, "-l", "app", "--duration", "5s", "--interval", "1s")
	if code != exitRefused {
		t.Fatalf("exit %d, want %d; stderr: %s", code, exitRefused, stderr)
	}
	if !strings.Contains(stderr, "REFUSED") || !strings.Contains(stderr, "--allow-context=prod-eu") {
		t.Fatalf("stderr: %s", stderr)
	}
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Fatalf("refusal made %d API request(s); want 0", n)
	}
}

func TestCaptureRefusesRemoteServerEvenWithLocalName(t *testing.T) {
	kc := kubeconfig(t, "kind-dev", "https://cluster.example.invalid:6443")
	code, _, stderr := runCLI("capture", "--kubeconfig", kc, "-l", "app")
	if code != exitRefused || !strings.Contains(stderr, "not on loopback") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
}

func TestCaptureRefusesLoopbackServerBehindAProxy(t *testing.T) {
	// A loopback server URL proves nothing when the cluster entry sends
	// requests through a proxy, which can forward them to any cluster. The
	// refusal must come before any request reaches the API server.
	srv, hits := apiServer(t, "k3s://n1")
	kc := kubeconfig(t, "k3d-dev", srv.URL)
	b, _ := os.ReadFile(kc)
	os.WriteFile(kc, []byte(strings.Replace(string(b), "    insecure-skip-tls-verify: true\n",
		"    insecure-skip-tls-verify: true\n    proxy-url: socks5://127.0.0.1:1080\n", 1)), 0o600)
	code, _, stderr := runCLI("capture", "--kubeconfig", kc, "-l", "app", "--duration", "5s", "--interval", "1s")
	if code != exitRefused || !strings.Contains(stderr, "proxy-url") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if n := atomic.LoadInt64(hits); n != 0 {
		t.Fatalf("refusal made %d API request(s); want 0", n)
	}
}

func TestContextFlagIsGuardedToo(t *testing.T) {
	// --context selecting a non-local context must be refused just like
	// current-context; and an unknown --context is an error, not a fallback.
	kc := kubeconfig(t, "prod-eu", "https://cluster.example.invalid")
	if code, _, stderr := runCLI("check-context", "--kubeconfig", kc, "--context", "prod-eu"); code != exitRefused {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if code, _, stderr := runCLI("check-context", "--kubeconfig", kc, "--context", "kind-missing"); code != exitError || !strings.Contains(stderr, "not found") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
}

func TestAllowContextMustNameTheActiveContext(t *testing.T) {
	srv, hits := apiServer(t, "aws:///zone/i-0")
	kc := kubeconfig(t, "prod-eu", srv.URL)
	code, _, stderr := runCLI("check-context", "--kubeconfig", kc, "--allow-context", "staging")
	if code != exitRefused || !strings.Contains(stderr, "does not match") || atomic.LoadInt64(hits) != 0 {
		t.Fatalf("exit %d hits %d stderr %s", code, *hits, stderr)
	}
	code, out, stderr := runCLI("check-context", "--kubeconfig", kc, "--allow-context", "prod-eu")
	if code != exitOK || strings.TrimSpace(out) != "allowed" || !strings.Contains(stderr, "explicitly allowed") {
		t.Fatalf("explicit opt-in: exit %d out %q stderr %s", code, out, stderr)
	}
}

func TestNodeGuardCatchesTunnelToCloudCluster(t *testing.T) {
	// Local-looking name and loopback server (as with an SSH tunnel or port
	// forward), but the nodes are cloud nodes: refuse after the read-only check.
	srv, _ := apiServer(t, "gce://project/zone/vm-1")
	kc := kubeconfig(t, "kind-tunnel", srv.URL)
	code, _, stderr := runCLI("check-context", "--kubeconfig", kc)
	if code != exitRefused || !strings.Contains(stderr, "gce://...") || strings.Contains(stderr, "vm-1") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
}

func TestLocalClusterAllowed(t *testing.T) {
	srv, _ := apiServer(t, "k3s://k3d-dev-server-0")
	kc := kubeconfig(t, "k3d-dev", srv.URL)
	code, out, stderr := runCLI("check-context", "--kubeconfig", kc)
	if code != exitOK || strings.TrimSpace(out) != "allowed" {
		t.Fatalf("exit %d out %q stderr %s", code, out, stderr)
	}
}

func TestNodeGuardCatchesTunnelToAnotherK3sCluster(t *testing.T) {
	// Every k3s cluster writes k3s://, remote and production ones included.
	// A k3d-dev context answered by nodes that are not k3d-dev's is a tunnel
	// or a reused port, and is refused without naming the foreign nodes.
	srv, _ := apiServer(t, "k3s://edge-node-7")
	kc := kubeconfig(t, "k3d-dev", srv.URL)
	code, _, stderr := runCLI("check-context", "--kubeconfig", kc)
	if code != exitRefused || !strings.Contains(stderr, "nodes of a different cluster") || strings.Contains(stderr, "edge-node-7") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
}

// Without -n or -A, capture targets the context's namespace, never every
// namespace (an empty namespace in client-go lists cluster-wide).
func TestCaptureTargetsTheContextNamespace(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/nodes" {
			fmt.Fprint(w, `{"kind":"NodeList","apiVersion":"v1","items":[{"metadata":{"name":"n1"},"spec":{"providerID":"k3s://k3d-dev-server-0"}}]}`)
			return
		}
		fmt.Fprint(w, `{"kind":"PodList","apiVersion":"v1","items":[]}`)
	}))
	defer srv.Close()
	kc := kubeconfig(t, "k3d-dev", srv.URL)
	runCLI("capture", "--kubeconfig", kc, "-l", "app", "--duration", "1s", "--interval", "1s", "-o", filepath.Join(t.TempDir(), "x.json"))
	mu.Lock()
	defer mu.Unlock()
	listed := ""
	for _, p := range paths {
		if strings.HasSuffix(p, "/pods") {
			listed = p
			break
		}
	}
	if listed != "/api/v1/namespaces/shop/pods" {
		t.Fatalf("capture without -n listed its targets at %q, want the context namespace shop (requests: %v)", listed, paths)
	}
}

// A capture file that cannot be read is an error in every command. Treated as
// an empty capture, a diff against it would say "VERDICT: OK".
func TestUnreadableCaptureIsAnErrorEverywhere(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, args := range [][]string{
		{"render", missing}, {"query", missing, "{ window { interval } }"}, {"suggest", missing},
		{"serve", "-addr", "127.0.0.1:0", missing}, {"diff", missing, fixture}, {"diff", fixture, missing},
	} {
		code, out, _ := runCLI(args...)
		if code != exitError || strings.Contains(out, "VERDICT") {
			t.Errorf("%v: exit %d, want %d and no verdict (stdout %.100q)", args, code, exitError, out)
		}
	}
}

func TestRenderFailsWhenItCannotWrite(t *testing.T) {
	if code, _, stderr := runCLI("render", "-format", "text", "-o", filepath.Join(t.TempDir(), "no-such-dir", "r.txt"), fixture); code != exitError {
		t.Fatalf("render to an unwritable path: exit %d, want %d (%s)", code, exitError, stderr)
	}
}

// A file that cannot be written is a failure, not success with no output.
func TestSuggestFailsWhenItCannotWrite(t *testing.T) {
	if code, _, stderr := runCLI("suggest", "-o", filepath.Join(t.TempDir(), "no-such-dir", "p.yaml"), fixture); code != exitError {
		t.Fatalf("suggest to an unwritable path: exit %d, want %d (%s)", code, exitError, stderr)
	}
}

func TestCaptureFlagValidationHappensFirst(t *testing.T) {
	cases := [][]string{
		{"capture"}, // no selector
		{"capture", "-l", "app", "-n", "x", "-A"},    // -n with -A
		{"capture", "-l", "app", "--duration", "0s"}, // empty window
		{"capture", "-l", "app", "--interval", "6m"}, // interval > window
		{"capture", "-l", "app", "stray-positional"}, // typo guard
		{"capture", "--no-such-flag"},                // unknown flag
	}
	for _, c := range cases {
		if code, _, _ := runCLI(c...); code != exitError {
			t.Errorf("%v: exit %d, want %d", c, code, exitError)
		}
	}
}

func TestRender(t *testing.T) {
	for format, want := range map[string]string{
		"text": "shop/api  [observed]",
		"dot":  "digraph podpeers",
		"html": "<!doctype html>",
		"json": `"schema": "podpeers/v1"`,
	} {
		code, out, stderr := runCLI("render", "-format", format, fixture)
		if code != exitOK || !strings.Contains(out, want) {
			t.Errorf("render %s: exit %d stderr %s", format, code, stderr)
		}
	}
	if code, _, _ := runCLI("render", "-format", "pdf", fixture); code != exitError {
		t.Error("unknown format should fail")
	}
	if code, _, _ := runCLI("render", "/does/not/exist.json"); code != exitError {
		t.Error("missing file should fail")
	}
	outFile := filepath.Join(t.TempDir(), "g.dot")
	if code, _, _ := runCLI("render", "-format", "dot", "-o", outFile, fixture); code != exitOK {
		t.Fatal("render -o failed")
	}
	if b, _ := os.ReadFile(outFile); !strings.HasPrefix(string(b), "digraph") {
		t.Fatal("render -o wrote nothing useful")
	}
}

func TestRenderRejectsWrongSchema(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.json")
	os.WriteFile(p, []byte(`{"schema":"other/v9"}`), 0o644)
	if code, _, stderr := runCLI("render", p); code != exitError || !strings.Contains(stderr, "schema") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
}

func TestQuery(t *testing.T) {
	code, out, _ := runCLI("query", fixture, `{ pod(id: "shop/web") { peers(direction: "outbound") { id } } }`)
	if code != exitOK || !strings.Contains(out, `"id": "svc/shop/api"`) {
		t.Fatalf("exit %d out %s", code, out)
	}
	code, out, _ = runCLI("query", "-vars", `{"s":"skipped"}`, fixture, `query($s: String) { pods(status: $s) { id } }`)
	// The variable must filter: ignored, the query would list every pod,
	// queued included.
	if code != exitOK || !strings.Contains(out, "shop/queued") || strings.Contains(out, "shop/api") {
		t.Fatalf("vars: exit %d out %s", code, out)
	}
	if code, _, _ := runCLI("query", "-vars", `{not json`, fixture, `{ window { interval } }`); code != exitError {
		t.Fatalf("bad -vars JSON: exit %d, want %d", code, exitError)
	}
	if code, out, _ := runCLI("query", fixture, `{ nope }`); code != exitError || !strings.Contains(out, "errors") {
		t.Fatalf("bad query: exit %d out %s", code, out)
	}
	if code, _, _ := runCLI("query", fixture); code != exitError {
		t.Fatal("missing query should fail")
	}
}

func TestServeHandler(t *testing.T) {
	code, _, _ := runCLI("render", "-format", "json", fixture) // sanity
	if code != exitOK {
		t.Fatal("fixture unreadable")
	}
	res := mustLoad(t)
	h, err := Handler(res)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/graphql", "application/json",
		strings.NewReader(`{"query":"query($id:String){ pod(id:$id){ name } }","variables":{"id":"shop/api"}}`))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if fmt.Sprint(body["data"]) != "map[pod:map[name:api]]" {
		t.Fatalf("POST /graphql = %v", body)
	}

	resp, _ = http.Get(srv.URL + "/graphql?query=" + "%7B%20window%20%7B%20interval%20%7D%20%7D")
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if fmt.Sprint(body["data"]) != "map[window:map[interval:5s]]" {
		t.Fatalf("GET /graphql = %v", body)
	}

	resp, _ = http.Get(srv.URL + "/")
	var page bytes.Buffer
	page.ReadFrom(resp.Body)
	resp.Body.Close()
	if !strings.Contains(page.String(), `const GRAPHQL = "graphql";`) {
		t.Fatal("served page should enable the GraphQL console")
	}
	for path, want := range map[string]int{"/nope": 404, "/favicon.ico": 204} {
		r, _ := http.Get(srv.URL + path)
		if r.StatusCode != want {
			t.Errorf("%s = %d", path, r.StatusCode)
		}
	}
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/graphql", nil)
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE /graphql = %d", r.StatusCode)
	}
	if r, _ := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader("{")); r.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body = %d", r.StatusCode)
	}
}

// serve binds to loopback, which keeps other machines out but not other web
// sites: a page can rebind its own name to 127.0.0.1, or post cross-site.
func TestServeRefusesRebindingAndCrossSite(t *testing.T) {
	h, err := Handler(mustLoad(t))
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, host string, hdr map[string]string) int {
		req := httptest.NewRequest(method, "/graphql?query=%7B%20window%20%7B%20interval%20%7D%20%7D", strings.NewReader(`{"query":"{ window { interval } }"}`))
		req.Host = host
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		method, host string
		hdr          map[string]string
		want         int
	}{
		{"GET", "127.0.0.1:8080", nil, 200},
		{"GET", "localhost:8080", map[string]string{"Origin": "http://localhost:8080", "Sec-Fetch-Site": "same-origin"}, 200},
		{"GET", "[::1]:8080", nil, 200},
		{"GET", "192.0.2.5:8080", nil, 200}, // an operator who chose -addr on a LAN address
		{"GET", "rebind.example.test:8080", nil, http.StatusMisdirectedRequest},
		{"GET", "rebind.example.test:8080", map[string]string{"Origin": "http://rebind.example.test:8080"}, http.StatusMisdirectedRequest},
		{"POST", "127.0.0.1:8080", map[string]string{"Origin": "https://evil.example.test", "Content-Type": "text/plain"}, http.StatusForbidden},
		{"GET", "127.0.0.1:8080", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"POST", "127.0.0.1:8080", map[string]string{"Origin": "null"}, http.StatusForbidden},
	} {
		if got := do(c.method, c.host, c.hdr); got != c.want {
			t.Errorf("%s Host=%s %v: %d, want %d", c.method, c.host, c.hdr, got, c.want)
		}
	}
}

func TestUsageAndUnknownCommand(t *testing.T) {
	if code, _, _ := runCLI(); code != exitError {
		t.Error("no args should fail")
	}
	if code, _, stderr := runCLI("frobnicate"); code != exitError || !strings.Contains(stderr, "unknown command") {
		t.Error("unknown command")
	}
	if code, out, _ := runCLI("help"); code != exitOK || !strings.Contains(out, "SAFETY") {
		t.Error("help should explain the safety rule")
	}
	if code, out, _ := runCLI("version"); code != exitOK || !strings.HasPrefix(out, "podpeers ") {
		t.Error("version")
	}
}

func mustLoad(t *testing.T) graph.Result {
	t.Helper()
	r, err := graph.LoadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSuggestCLI(t *testing.T) {
	code, out, stderr := runCLI("suggest", "-min-samples", "1", fixture)
	if code != exitOK || !strings.Contains(out, "kind: NetworkPolicy") || !strings.Contains(stderr, "policy suggestion(s)") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	code, out, _ = runCLI("suggest", "-format", "json", "-n", "shop", "-workload", "Pod/web", "-min-samples", "1", fixture)
	if code != exitOK || !strings.Contains(out, `"workload": "Pod/web"`) || strings.Contains(out, `"workload": "Pod/api"`) {
		t.Fatalf("json filter: %s", out)
	}
	for _, bad := range [][]string{{"suggest", "-dns", "maybe", fixture}, {"suggest", "-format", "xml", fixture}, {"suggest"}} {
		if code, _, _ := runCLI(bad...); code != exitError {
			t.Errorf("%v should fail", bad)
		}
	}
	f := filepath.Join(t.TempDir(), "p.yaml")
	if code, _, _ := runCLI("suggest", "-o", f, "-min-samples", "1", fixture); code != exitOK {
		t.Fatal("suggest -o")
	}
	if b, _ := os.ReadFile(f); !strings.Contains(string(b), "NOT COVERED") {
		t.Fatal("suggest -o content")
	}
}

func TestDiffCLI(t *testing.T) {
	code, out, _ := runCLI("diff", fixture, fixture)
	if code != exitOK || !strings.Contains(out, "VERDICT: OK") {
		t.Fatalf("exit %d out %s", code, out)
	}
	b, _ := os.ReadFile(fixture)
	broken := strings.Replace(string(b), `"port": 8080, "protocol": "tcp", "connections": 1, "newConnections": 1, "firstSeen": "2023-11-14T22:13:20Z", "lastSeen": "2023-11-14T22:14:15Z", "samples": 12, "open": true}`,
		`"port": 8080, "protocol": "tcp", "connections": 1, "newConnections": 1, "firstSeen": "2023-11-14T22:13:20Z", "lastSeen": "2023-11-14T22:14:15Z", "samples": 12, "open": false, "attempted": true}`, 1)
	if broken == string(b) {
		t.Fatal("fixture edit did not apply")
	}
	after := filepath.Join(t.TempDir(), "after.json")
	os.WriteFile(after, []byte(broken), 0o644)
	code, out, _ = runCLI("diff", fixture, after)
	if code != exitBroken || !strings.Contains(out, "blocked") {
		t.Fatalf("exit %d out %s", code, out)
	}
	code, out, _ = runCLI("diff", "-json", fixture, after)
	if code != exitBroken || !strings.Contains(out, `"broken": true`) {
		t.Fatalf("json: %s", out)
	}
	stale := strings.ReplaceAll(string(b), `"newConnections": 1,`, `"newConnections": 0,`)
	stale = strings.ReplaceAll(stale, `"newConnections": 2,`, `"newConnections": 0,`)
	stalePath := filepath.Join(t.TempDir(), "stale.json")
	os.WriteFile(stalePath, []byte(stale), 0o644)
	if code, out, _ := runCLI("diff", fixture, stalePath); code != exitInconclusive || !strings.Contains(out, "INCONCLUSIVE") {
		t.Fatalf("pre-existing only: exit %d out %s", code, out)
	}
	if code, _, _ := runCLI("diff", "-existing-pods", "/no/such/file", fixture, stalePath); code != exitError {
		t.Error("missing -existing-pods file should fail")
	}
	podsFile := filepath.Join(t.TempDir(), "pods.txt")
	os.WriteFile(podsFile, []byte("pod/edge/old-gateway\nshop/old-api\n"), 0o644)
	if code, out, _ := runCLI("diff", "-existing-pods", podsFile, fixture, stalePath); code != exitOK {
		t.Errorf("every capture pod is newer than the change: exit %d\n%s", code, out)
	}
	if code, _, _ := runCLI("diff", fixture); code != exitError {
		t.Error("one file should fail")
	}
}

func TestMCPCLI(t *testing.T) {
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"summary","arguments":{}}}` + "\n")
	var out, errb bytes.Buffer
	if code := cmdMCP([]string{fixture}, in, &out, &errb); code != exitOK || !strings.Contains(out.String(), "shop/api") {
		t.Fatalf("exit %d out %s err %s", code, out.String(), errb.String())
	}
	if code := cmdMCP([]string{"/nope.json"}, strings.NewReader(""), &out, &errb); code != exitError {
		t.Error("missing capture should fail before serving")
	}
	if code := cmdMCP(nil, strings.NewReader(""), &out, &errb); code != exitError {
		t.Error("no capture should fail")
	}
}

// The MCP server reports the same version as `podpeers version`; it once
// reported the raw ldflags default ("dev") for `go install` builds.
func TestMCPReportsTheBuildVersion(t *testing.T) {
	saved := buildVersion
	defer func() { buildVersion = saved }()
	buildVersion = func() string { return "v0.0.0-20990101000000-abcdef123456" }
	_, v, _ := runCLI("version")
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}` + "\n")
	var out, errb bytes.Buffer
	if code := cmdMCP([]string{fixture}, in, &out, &errb); code != exitOK {
		t.Fatalf("mcp exit %d: %s", code, errb.String())
	}
	var resp struct {
		Result struct {
			ServerInfo struct{ Version string } `json:"serverInfo"`
		}
	}
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if want := strings.TrimSpace(strings.TrimPrefix(v, "podpeers ")); resp.Result.ServerInfo.Version != want {
		t.Errorf("MCP serverInfo.version = %q; `podpeers version` says %q", resp.Result.ServerInfo.Version, want)
	}
}
