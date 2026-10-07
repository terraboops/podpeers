package render

import (
	"bytes"
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
