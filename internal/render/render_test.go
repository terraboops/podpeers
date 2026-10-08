package render

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/terraboops/podpeers/internal/graph"
)

func fixture(t *testing.T) graph.Result {
	t.Helper()
	r, err := graph.LoadFile("../testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFlowsOrientClientToServer(t *testing.T) {
	fs := Flows(fixture(t))
	has := func(from, to string, port uint16, open bool) bool {
		for _, f := range fs {
			if f.From == from && f.To == to && f.Port == port && f.Open == open {
				return true
			}
		}
		return false
	}
	// inbound on api from web => web -> api
	if !has("shop/web", "shop/api", 9000, true) {
		t.Error("inbound edge not oriented client->server")
	}
	// outbound on web to service api => web -> service
	if !has("shop/web", "svc/shop/api", 9000, true) || !has("edge/gateway", "svc/shop/web", 8080, true) {
		t.Error("outbound edge not oriented pod->peer")
	}
	if !has("shop/batch", "shop/api", 9000, false) {
		t.Error("closed edge lost its state")
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, fixture(t)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`selector "tier" in all namespaces`,
		"shop/api  [observed]",
		"listening: tcp/9000",
		"<-   shop/batch",
		"closed in window",
		"->   203.0.113.9",
		"shop/idle  [observed]\n  no peers observed",
		"shop/queued  [skipped: pod phase is Pending, not Running]",
		"pods: 4 observed, 0 failed, 1 skipped, 1 peer-only; 6 edges",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "shop/batch  [") {
		t.Error("peer-only pods should not get their own block")
	}
}

func TestDOT(t *testing.T) {
	var b bytes.Buffer
	if err := DOT(&b, fixture(t)); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"digraph podpeers {",
		`label="namespace shop"`,
		`"shop/batch" [label="batch", shape=box, style=dashed]`,
		`"shop/queued" [label="queued", shape=box, style=dotted]`,
		`"203.0.113.9" [label="203.0.113.9", shape=diamond`,
		`"shop/batch" -> "shop/api" [label="tcp/9000", style=dashed]`,
		`"edge/gateway" -> "svc/shop/web" [label="tcp/8080", style=solid]`,
		`"edge/gateway" -> "shop/web" [label="tcp/8080", style=solid]`,
		`"svc/shop/web" [label="web", shape=ellipse`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dot missing %q:\n%s", want, out)
		}
	}
	// A pod and a service that share a name must stay two distinct nodes.
	if strings.Count(out, `"shop/web" [label="web"`) != 1 || strings.Count(out, `"svc/shop/web" [label="web"`) != 1 {
		t.Error("pod and service with the same name were merged")
	}
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Error("unbalanced braces")
	}
}

func TestHTMLIsSelfContainedAndInjectionSafe(t *testing.T) {
	r := fixture(t)
	r.Pods[0].Name = `evil</script><script>alert(1)</script>`
	var b bytes.Buffer
	if err := HTML(&b, r, ""); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "/*__DATA__*/") || strings.Contains(out, "/*__GRAPHQL__*/") {
		t.Fatal("placeholders not substituted")
	}
	if strings.Contains(out, "alert(1)</script>") {
		t.Fatal("pod name escaped the script block")
	}
	if !strings.Contains(out, `"schema":"podpeers/v1"`) || !strings.Contains(out, `const GRAPHQL = "";`) {
		t.Fatal("data not embedded")
	}
	for _, banned := range []string{"http://", "https://", "<link", "src="} {
		if strings.Contains(strings.ReplaceAll(out, "http://www.w3.org/2000/svg", ""), banned) {
			t.Errorf("page must not fetch anything; found %q", banned)
		}
	}
}

func TestHTMLWithConsole(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, fixture(t), "/graphql"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `const GRAPHQL = "/graphql";`) {
		t.Fatal("graphql path not embedded")
	}
}

func TestHTMLHasWorkloadAndPodViews(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, fixture(t), ""); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="v-wl"`, `id="v-pod"`, "function build(view)", "svcPods", "targetPort("} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestEveryViewStatesWhatTheCaptureCouldNotSee(t *testing.T) {
	// The fixture predates the limits field: they must be computed for it.
	r := fixture(t)
	var text, page bytes.Buffer
	Text(&text, r)
	HTML(&page, r, "")
	if !strings.Contains(text.String(), "WHAT THIS CAPTURE COULD NOT SEE:") || !strings.Contains(text.String(), "one sample every 5s") {
		t.Errorf("text report lacks limits:\n%s", text.String())
	}
	if !strings.Contains(page.String(), `"limits":[`) || !strings.Contains(page.String(), "What this capture could not see") {
		t.Error("HTML page lacks limits")
	}
}

// Capture files can be written by anyone. Their strings must not reach the
// terminal as escape sequences, and a trailing backslash must not end a DOT
// string early (Go's %q is not DOT quoting; Graphviz lexers disagree on it).
func TestHostileStringsAreInert(t *testing.T) {
	r := fixture(t)
	r.Pods = append(r.Pods, graph.Pod{Namespace: "n", Name: "a\\", Probe: graph.Probe{Status: graph.ProbeFailed, Reason: "x\x1b[8m\nforged"}})
	r.Edges = append(r.Edges, graph.Edge{Pod: "n/a\\", Direction: graph.Outbound, Protocol: "tcp", Port: 443,
		Peer: graph.Peer{Kind: graph.PeerExternal, IP: `] X [label=INJ] y [k=\`}})
	var text, dot bytes.Buffer
	Text(&text, r)
	if err := DOT(&dot, r); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(text.String(), 0x1b) || strings.Contains(text.String(), "\nforged") {
		t.Fatalf("raw control characters in text:\n%q", text.String())
	}
	// A backslash only ever starts a \uXXXX escape or escapes a quote, so no
	// lexer can read a delimiter as escaped or an escape as a delimiter.
	if strings.Contains(dot.String(), `\\`) {
		t.Fatalf("raw backslash pair in DOT:\n%s", dot.String())
	}
	if !strings.Contains(dot.String(), `"] X [label=INJ] y [k=`+`\`+`u005c" [label=`) {
		t.Fatalf("capture text escaped its DOT string:\n%s", dot.String())
	}
}

// The DOT above must also survive a real Graphviz lexer: the hostile peer
// stays one node with its text as its name, and no node X or y appears. CI
// installs Graphviz and sets PODPEERS_REQUIRE_DOT, so there this cannot skip.
func TestHostileDOTParsesInGraphviz(t *testing.T) {
	dotBin, err := exec.LookPath("dot")
	if err != nil {
		if os.Getenv("PODPEERS_REQUIRE_DOT") != "" {
			t.Fatal("Graphviz (dot) is required here but not installed")
		}
		t.Skip("Graphviz (dot) is not installed, so DOT output is not parsed by a real Graphviz here; CI installs it")
	}
	r := fixture(t)
	r.Pods = append(r.Pods, graph.Pod{Namespace: "n", Name: "a\\", Probe: graph.Probe{Status: graph.ProbeFailed}})
	r.Edges = append(r.Edges, graph.Edge{Pod: "n/a\\", Direction: graph.Outbound, Protocol: "tcp", Port: 443,
		Peer: graph.Peer{Kind: graph.PeerExternal, IP: `] X [label=INJ] y [k=\`}})
	var dot bytes.Buffer
	if err := DOT(&dot, r); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(dotBin, "-Tjson")
	cmd.Stdin = &dot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Graphviz rejected the DOT: %v\n%s", err, out)
	}
	var g struct {
		Objects []struct{ Name string } `json:"objects"`
	}
	if err := json.Unmarshal(out, &g); err != nil {
		t.Fatal(err)
	}
	hostile := false
	for _, o := range g.Objects {
		if o.Name == "X" || o.Name == "y" {
			t.Fatalf("capture text became DOT statements: node %q", o.Name)
		}
		if strings.HasPrefix(o.Name, "] X [label=INJ] y [k=") {
			hostile = true
		}
	}
	if !hostile {
		t.Fatalf("the hostile peer should be one node named by its text; nodes: %+v", g.Objects)
	}
}
