package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terraboops/podpeers/internal/graph"
)

const fixture = "../../internal/testdata/capture.json"

// TestMain points KUBECONFIG at a tripwire, so a test that reaches connect()
// without --kubeconfig never reads the developer's own (whose default context
// may be production). Its context looks local and its stand-in API server is
// on loopback, so such a test gets past the pre-flight gate and is counted:
// any request fails the run.
func TestMain(m *testing.M) {
	var tripped int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tripped, 1)
		http.Error(w, "tripwire", http.StatusTeapot)
	}))
	dir, err := os.MkdirTemp("", "podpeers-tripwire")
	if err != nil {
		panic(err)
	}
	kc := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kc, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: c
  cluster: {server: %s, insecure-skip-tls-verify: true}
users:
- name: u
  user: {token: not-a-real-token}
contexts:
- name: k3d-tripwire
  context: {cluster: c, user: u}
current-context: k3d-tripwire
`, srv.URL)), 0o600); err != nil {
		panic(err)
	}
	os.Setenv("KUBECONFIG", kc)
	code := m.Run()
	srv.Close()
	os.RemoveAll(dir)
	if n := atomic.LoadInt64(&tripped); n != 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d request(s) reached a cluster through the default kubeconfig: a test ran connect() without --kubeconfig\n", n)
		code = 1
	}
	os.Exit(code)
}

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

// runCLIFresh runs the CLI in a new process with env added, and no proxy
// setting of its own: Go reads the proxy environment once per process, so in
// this one it may already be fixed.
func runCLIFresh(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	a, _ := json.Marshal(args)
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIInAFreshProcess$")
	for _, kv := range os.Environ() {
		if name, _, _ := strings.Cut(kv, "="); !strings.HasSuffix(strings.ToUpper(name), "_PROXY") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, append(env, "PODPEERS_TEST_CLI_ARGS="+string(a))...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	var exit *exec.ExitError
	if err := cmd.Run(); errors.As(err, &exit) {
		return exit.ExitCode(), out.String(), errb.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return exitOK, out.String(), errb.String()
}

func TestCLIInAFreshProcess(t *testing.T) {
	a := os.Getenv("PODPEERS_TEST_CLI_ARGS")
	if a == "" {
		t.Skip("runs only as runCLIFresh's child")
	}
	var args []string
	if err := json.Unmarshal([]byte(a), &args); err != nil {
		t.Fatal(err)
	}
	os.Exit(run(context.Background(), args, os.Stdout, os.Stderr))
}

func TestLoopbackServerBehindTheEnvironmentsProxyIsRefused(t *testing.T) {
	// k3d writes https://0.0.0.0:PORT, and Go sends 0.0.0.0 through
	// HTTPS_PROXY (only 127/8, ::1 and localhost go direct): the proxy, not
	// this machine, would pick the cluster. The refusal comes before any
	// request, and does not show the proxy's password.
	srv, hits := apiServer(t, "k3s://k3d-dev-server-0")
	var proxied int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&proxied, 1)
		http.Error(w, "not a proxy", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	kc := kubeconfig(t, "k3d-dev", "https://0.0.0.0:"+port)
	env := []string{"HTTPS_PROXY=" + strings.Replace(proxy.URL, "http://", "http://alice:hunter2@", 1)}

	code, _, stderr := runCLIFresh(t, env, "check-context", "--kubeconfig", kc)
	if code != exitRefused || !strings.Contains(stderr, "set in the environment") || strings.Contains(stderr, "hunter2") {
		t.Fatalf("exit %d stderr %s", code, stderr)
	}
	if n, p := atomic.LoadInt64(hits), atomic.LoadInt64(&proxied); n != 0 || p != 0 {
		t.Fatalf("refusal made %d API request(s), %d through the proxy; want 0", n, p)
	}

	// Exempted by NO_PROXY it goes direct, and is judged by its nodes.
	code, out, stderr := runCLIFresh(t, append(env, "NO_PROXY=0.0.0.0"), "check-context", "--kubeconfig", kc)
	if code != exitOK || strings.TrimSpace(out) != "allowed" || atomic.LoadInt64(&proxied) != 0 {
		t.Fatalf("NO_PROXY exempted: exit %d out %q stderr %s", code, out, stderr)
	}
	// 127.0.0.1 is never proxied, so the same environment is no reason to refuse it.
	code, out, stderr = runCLIFresh(t, env, "check-context", "--kubeconfig", kubeconfig(t, "k3d-dev", srv.URL))
	if code != exitOK || strings.TrimSpace(out) != "allowed" || atomic.LoadInt64(&proxied) != 0 {
		t.Fatalf("127.0.0.1: exit %d out %q stderr %s", code, out, stderr)
	}
}

func TestUnparseableServerIsRefused(t *testing.T) {
	kc := kubeconfig(t, "k3d-dev", "::not a url")
	code, _, stderr := runCLI("check-context", "--kubeconfig", kc)
	if code != exitRefused || !strings.Contains(stderr, "not on loopback") {
		t.Fatalf("exit %d stderr %s", code, stderr)
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
	// The selector matches nothing here: a failed capture, which writes no file.
	x := filepath.Join(t.TempDir(), "x.json")
	code, _, stderr := runCLI("capture", "--kubeconfig", kc, "-l", "app", "--duration", "1s", "--interval", "1s", "-o", x)
	if _, err := os.Stat(x); code != exitError || !strings.Contains(stderr, "capture failed: ") || !strings.Contains(stderr, "matched no pods") || err == nil {
		t.Errorf("a capture of nothing: exit %d, file written: %v, stderr %s", code, err == nil, stderr)
	}
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

// An -o that cannot be written is refused before connecting: found at the
// end, every targeted pod would have been changed for nothing. A file made
// for the check is not left behind; one already there is not truncated.
func TestCaptureChecksItsOutputFirst(t *testing.T) {
	srv, hits := apiServer(t, "k3s://k3d-dev-server-0")
	kc := kubeconfig(t, "k3d-dev", srv.URL)
	dir := t.TempDir()
	for _, out := range []string{filepath.Join(dir, "missing", "x.json"), dir} {
		code, _, stderr := runCLI("capture", "--kubeconfig", kc, "-l", "app", "--duration", "1s", "--interval", "1s", "-o", out)
		if code != exitError || !strings.Contains(stderr, "-o cannot be written, so nothing was captured") || atomic.LoadInt64(hits) != 0 {
			t.Errorf("-o %s: exit %d, %d API request(s), stderr %s", out, code, atomic.LoadInt64(hits), stderr)
		}
	}
	var b bytes.Buffer
	fresh := filepath.Join(dir, "fresh.json")
	if !writable(fresh, &b) {
		t.Fatal(b.String())
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Errorf("the check left %s behind: %v", fresh, err)
	}
	kept := filepath.Join(dir, "kept.json")
	os.WriteFile(kept, []byte("an earlier capture"), 0o600)
	if !writable(kept, &b) {
		t.Fatal(b.String())
	}
	if got, _ := os.ReadFile(kept); string(got) != "an earlier capture" {
		t.Errorf("the check changed an existing file to %q", got)
	}
}

// A flag written after the capture file is not parsed, so it is refused
// rather than ignored: "suggest c.json -n shop" would otherwise suggest for
// every namespace. diff and mcp take an exact count of files.
func TestStrayArgumentsAreRefused(t *testing.T) {
	after := "after the capture file (flags go before it)"
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"render", fixture, "-format", "dot"}, after},
		{[]string{"suggest", fixture, "-n", "shop"}, after},
		{[]string{"serve", "-addr", "127.0.0.1:0", fixture, "extra"}, after},
		{[]string{"diff", fixture, fixture, fixture}, "diff needs two capture files"},
		{[]string{"mcp", fixture, fixture}, "mcp needs the capture file"},
	} {
		code, out, stderr := runCLI(c.args...)
		if code != exitError || out != "" || !strings.Contains(stderr, c.says) {
			t.Errorf("%v: exit %d, stdout %.80q, stderr %.200q", c.args, code, out, stderr)
		}
	}
	// Too few arguments get the usage line, not whatever reading "" says.
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"render"}, "missing capture file argument"},
		{[]string{"suggest"}, "missing capture file argument"},
		{[]string{"serve"}, "missing capture file argument"},
		{[]string{"query"}, "missing capture file argument"},
		{[]string{"query", fixture}, "missing GraphQL query argument"},
		{[]string{"diff", fixture}, "diff needs two capture files: before.json after.json"},
		{[]string{"mcp"}, "mcp needs the capture file to serve"},
	} {
		code, out, stderr := runCLI(c.args...)
		if code != exitError || out != "" || stderr != "podpeers: "+c.says+"\n" {
			t.Errorf("%v: exit %d, stdout %.80q, stderr %.200q", c.args, code, out, stderr)
		}
	}
	// query alone takes the rest of the line: it is the query.
	if code, out, stderr := runCLI("query", fixture, "{", "window", "{", "interval", "}", "}"); code != exitOK || !strings.Contains(out, "interval") {
		t.Errorf("a query in several arguments: exit %d, stdout %q, stderr %s", code, out, stderr)
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
		code, out, stderr := runCLI(args...)
		if code != exitError || strings.Contains(out, "VERDICT") || strings.Contains(stderr, "unknown command") {
			t.Errorf("%v: exit %d, want %d, no verdict, and the command run (stdout %.100q, stderr %.200q)", args, code, exitError, out, stderr)
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
		{"capture", "-l", "app", "-n", "x", "-A"},     // -n with -A
		{"capture", "-l", "app", "--duration", "0s"},  // empty window
		{"capture", "-l", "app", "--interval", "6m"},  // interval > window
		{"capture", "-l", "app", "stray-positional"},  // typo guard
		{"capture", "--no-such-flag"},                 // unknown flag
		{"capture", "-l", "app", "--summary", "json"}, // a summary format there is not
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
	// ... before -o is opened: the file there is left as it was.
	kept := filepath.Join(t.TempDir(), "view.html")
	os.WriteFile(kept, []byte("an earlier view"), 0o600)
	if code, _, stderr := runCLI("render", "-format", "pdf", "-o", kept, fixture); code != exitError || !strings.Contains(stderr, `unknown format "pdf"`) {
		t.Errorf("unknown format with -o: exit %d stderr %s", code, stderr)
	}
	if b, _ := os.ReadFile(kept); string(b) != "an earlier view" {
		t.Errorf("an unknown format truncated -o's file to %q", b)
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
	// A body is read up to 1 MiB, not into memory whole: a well-formed query
	// padded past that is refused.
	padded := `{"query":"{ window { interval } }","pad":"` + strings.Repeat("x", 2<<20) + `"}`
	if r, _ := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(padded)); r.StatusCode != http.StatusBadRequest {
		t.Errorf("a 2 MiB body = %d, want %d", r.StatusCode, http.StatusBadRequest)
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
		{"GET", "web.localhost:8080", nil, 200}, // *.localhost is loopback by definition (RFC 6761)
		{"GET", "localhost.rebind.example.test:8080", nil, http.StatusMisdirectedRequest},
		{"GET", "rebind-localhost:8080", nil, http.StatusMisdirectedRequest},
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

// Each flag reaches the options it names, and the closing count says what
// came of them.
func TestSuggestFlagsReachTheirOptions(t *testing.T) {
	for _, c := range []struct {
		args    []string
		count   string
		shorter bool
	}{
		{[]string{"-min-samples", "1"}, "3 policy suggestion(s), 2 workload(s) refused for thin evidence", true},
		{[]string{"-min-samples", "1000"}, "0 policy suggestion(s), 5 workload(s) refused for thin evidence", true},
		{[]string{"-min-samples", "1", "-allow-empty"}, "4 policy suggestion(s), 1 workload(s) refused for thin evidence", true},
		{[]string{"-min-samples", "1", "-min-window", "1m"}, "3 policy suggestion(s), 2 workload(s) refused for thin evidence", false},
	} {
		code, out, stderr := runCLI(append(append([]string{"suggest"}, c.args...), fixture)...)
		if code != exitOK || stderr != "podpeers: "+c.count+"\n" || strings.Contains(out, "is shorter than") != c.shorter {
			t.Errorf("%v: exit %d, stderr %q, window warning %v", c.args, code, stderr, !c.shorter)
		}
	}
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

// capturePaths runs capture against a fake API server for context k3d-dev
// (namespace shop) and returns the request paths and the exit code.
func capturePaths(t *testing.T, args ...string) ([]string, int, string) {
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
	code, _, stderr := runCLI(append([]string{"capture", "--kubeconfig", kc, "-l", "app", "--duration", "1s", "--interval", "1s",
		"-o", filepath.Join(t.TempDir(), "x.json")}, args...)...)
	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), paths...), code, stderr
}

// An explicit -n is the namespace captured, never replaced by the context's;
// -n and -A together are refused before any request.
func TestCaptureNamespaceFlags(t *testing.T) {
	paths, _, stderr := capturePaths(t, "-n", "payments")
	if strings.Contains(stderr, "WARNING") {
		t.Errorf("an interval of exactly 1s costs nothing worth a warning: %s", stderr)
	}
	listed := ""
	for _, p := range paths {
		if strings.HasSuffix(p, "/pods") {
			listed = p
			break
		}
	}
	if listed != "/api/v1/namespaces/payments/pods" {
		t.Errorf("capture -n payments listed its targets at %q (stderr %s)", listed, stderr)
	}
	paths, code, stderr := capturePaths(t, "-A", "-n", "payments")
	if code != exitError || !strings.Contains(stderr, "-n and -A are mutually exclusive") || len(paths) != 0 {
		t.Errorf("-A with -n: exit %d, %d request(s): %s", code, len(paths), stderr)
	}
}

// syncBuffer is a bytes.Buffer safe to read while another goroutine writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// Stopped (its context ended), serve shuts down cleanly: success, no error.
func TestServeStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var stderr syncBuffer
	done := make(chan int)
	go func() { done <- run(ctx, []string{"serve", "-addr", "127.0.0.1:0", fixture}, io.Discard, &stderr) }()
	for i := 0; i < 200 && !strings.Contains(stderr.String(), "serving"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // listening
	cancel()
	select {
	case code := <-done:
		if code != exitOK || strings.Count(stderr.String(), "podpeers:") != 1 {
			t.Fatalf("a stopped serve: exit %d, want %d and nothing but the serving line:\n%s", code, exitOK, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve did not stop")
	}
}

// `podpeers mcp` serves MCP on stdin and stdout.
func TestMCPCommandAnswers(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = stdin }()
	fmt.Fprintln(w, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	w.Close()
	code, out, stderr := runCLI("mcp", fixture)
	if code != exitOK || !strings.Contains(out, `"id":1`) || !strings.Contains(out, `"result"`) {
		t.Fatalf("mcp: exit %d\nstdout %s\nstderr %s", code, out, stderr)
	}
}

// Every subcommand refuses a flag it does not know, before doing anything.
func TestUnknownFlagsAreRefused(t *testing.T) {
	for _, cmd := range []string{"capture", "check-context", "render", "query", "serve", "suggest", "diff", "mcp"} {
		code, out, stderr := runCLI(cmd, "--no-such-flag")
		if code != exitError || out != "" || !strings.Contains(stderr, "no-such-flag") {
			t.Errorf("%s --no-such-flag: exit %d, stdout %q, stderr %q", cmd, code, out, stderr)
		}
	}
}

// A kubeconfig that does not parse is reported as such, not taken for an
// empty one.
func TestMalformedKubeconfigIsReported(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	os.WriteFile(kc, []byte("this: [is not: a kubeconfig\n"), 0o600)
	code, _, stderr := runCLI("check-context", "--kubeconfig", kc)
	if code == 0 || !strings.Contains(stderr, "yaml") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

// serve on an address already in use fails at once, saying why.
func TestServeOnABusyAddressFails(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	var code int
	var stderr string
	go func() { code, _, stderr = runCLI("serve", "--addr", l.Addr().String(), fixture); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("serve kept running on an address it could not listen on")
	}
	if code == 0 || !strings.Contains(stderr, "address already in use") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
