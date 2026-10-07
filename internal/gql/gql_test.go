package gql

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/graphql-go/graphql"

	"github.com/terraboops/podpeers/internal/graph"
)

func schema(t *testing.T) graphql.Schema {
	t.Helper()
	res, err := graph.LoadFile("../testdata/capture.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSchema(res)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// run executes q and returns the JSON of its data, failing on GraphQL errors.
func run(t *testing.T, s graphql.Schema, q string) string {
	t.Helper()
	r := Do(s, q, nil)
	if r.HasErrors() {
		t.Fatalf("query %s: %v", q, r.Errors)
	}
	b, _ := json.Marshal(r.Data)
	return string(b)
}

func TestPodPeersAndDirections(t *testing.T) {
	s := schema(t)
	got := run(t, s, `{ pod(id: "shop/api") { name listening { port } inbound: peers(direction: "inbound") { id kind } outbound: peers(direction: "outbound") { id kind } } }`)
	want := `{"pod":{"inbound":[{"id":"shop/batch","kind":"pod"},{"id":"shop/web","kind":"pod"}],"listening":[{"port":9000}],"name":"api","outbound":[{"id":"203.0.113.9","kind":"external"}]}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestPodByNamespaceAndName(t *testing.T) {
	s := schema(t)
	if got := run(t, s, `{ pod(namespace: "shop", name: "web") { id ip label(key: "tier") nope: label(key: "missing") } }`); got !=
		`{"pod":{"id":"shop/web","ip":"192.0.2.11","label":"front","nope":null}}` {
		t.Fatal(got)
	}
	if got := run(t, s, `{ pod(id: "shop/ghost") { id } }`); got != `{"pod":null}` {
		t.Fatal(got)
	}
	if r := Do(s, `{ pod(namespace: "shop") { id } }`, nil); !r.HasErrors() {
		t.Fatal("pod without full identity should error")
	}
}

func TestPodsFilters(t *testing.T) {
	s := schema(t)
	cases := map[string]string{
		`{ pods(namespace: "edge") { id } }`:                                    `{"pods":[{"id":"edge/gateway"}]}`,
		`{ pods(status: "skipped") { id probe { reason } } }`:                   `{"pods":[{"id":"shop/queued","probe":{"reason":"pod phase is Pending, not Running"}}]}`,
		`{ pods(label: "tier=front") { id } }`:                                  `{"pods":[{"id":"shop/web"}]}`,
		`{ pods(label: "tier", namespace: "shop", status: "observed") { id } }`: `{"pods":[{"id":"shop/api"},{"id":"shop/idle"},{"id":"shop/web"}]}`,
		`{ pods(status: "not-targeted") { id } }`:                               `{"pods":[{"id":"shop/batch"}]}`,
	}
	for q, want := range cases {
		if got := run(t, s, q); got != want {
			t.Errorf("%s\n got  %s\n want %s", q, got, want)
		}
	}
}

func TestPodWithNoPeers(t *testing.T) {
	s := schema(t)
	if got := run(t, s, `{ pod(id: "shop/idle") { probe { status } edges { port } peers { id } seenBy { pod { id } } } }`); got !=
		`{"pod":{"edges":[],"peers":[],"probe":{"status":"observed"},"seenBy":[]}}` {
		t.Fatal(got)
	}
}

func TestSeenByCoversUnprobedPods(t *testing.T) {
	// batch was never probed; the only evidence of it is api's inbound edge.
	s := schema(t)
	got := run(t, s, `{ pod(id: "shop/batch") { probe { status } edges { port } seenBy { pod { id } direction port open } } }`)
	want := `{"pod":{"edges":[],"probe":{"status":"not-targeted"},"seenBy":[{"direction":"inbound","open":false,"pod":{"id":"shop/api"},"port":9000}]}}`
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestEdgeFilters(t *testing.T) {
	s := schema(t)
	cases := map[string]string{
		`{ edges(open: false) { pod { id } peer { id } } }`:                        `{"edges":[{"peer":{"id":"shop/batch"},"pod":{"id":"shop/api"}}]}`,
		`{ edges(peerKind: "external") { port connections firstSeen } }`:           `{"edges":[{"connections":3,"firstSeen":"2023-11-14T22:13:25Z","port":443}]}`,
		`{ edges(port: 8080, direction: "inbound") { pod { id } } }`:               `{"edges":[{"pod":{"id":"shop/web"}}]}`,
		`{ edges(protocol: "udp") { port } }`:                                      `{"edges":[]}`,
		`{ peers(peerKind: "service") { id service { selector { key value } } } }`: `{"peers":[{"id":"svc/shop/api","service":{"selector":[{"key":"app","value":"api"}]}},{"id":"svc/shop/web","service":{"selector":[{"key":"app","value":"web"}]}}]}`,
	}
	for q, want := range cases {
		if got := run(t, s, q); got != want {
			t.Errorf("%s\n got  %s\n want %s", q, got, want)
		}
	}
}

func TestTraversalTwoHops(t *testing.T) {
	// Who talks to the pods that gateway's service peer fronts? gateway -> svc web,
	// and web's own inbound edges name gateway: the graph closes the loop.
	s := schema(t)
	got := run(t, s, `{ pod(id: "edge/gateway") { edges { peer { id pod { id } service { id } } } } pods(label: "app=web") { edges(direction: "inbound") { peer { pod { id labels { key value } } } } } }`)
	if !strings.Contains(got, `"service":{"id":"svc/shop/web"}`) || !strings.Contains(got, `"pod":null`) ||
		!strings.Contains(got, `{"key":"tier","value":"edge"}`) {
		t.Fatal(got)
	}
}

func TestWindowAndIntrospection(t *testing.T) {
	s := schema(t)
	if got := run(t, s, `{ window { start end interval } }`); got != `{"window":{"end":"2023-11-14T22:14:20Z","interval":"5s","start":"2023-11-14T22:13:20Z"}}` {
		t.Fatal(got)
	}
	if got := run(t, s, `{ __type(name: "Pod") { fields { name } } }`); !strings.Contains(got, `"seenBy"`) {
		t.Fatal("schema should be introspectable")
	}
	if r := Do(s, `{ pods { nosuchfield } }`, nil); !r.HasErrors() {
		t.Fatal("unknown field should be a validation error")
	}
}

func TestVariables(t *testing.T) {
	s := schema(t)
	r := Do(s, `query($id: String) { pod(id: $id) { name } }`, map[string]any{"id": "shop/web"})
	if r.HasErrors() {
		t.Fatal(r.Errors)
	}
	b, _ := json.Marshal(r.Data)
	if string(b) != `{"pod":{"name":"web"}}` {
		t.Fatal(string(b))
	}
}
