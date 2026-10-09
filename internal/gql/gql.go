// Package gql exposes a capture as a GraphQL API.
//
// GraphQL was chosen over a TinkerPop/Gremlin endpoint because a capture is a
// small, typed, read-only graph that is loaded once from a file: GraphQL runs
// in-process with no graph server (Gremlin Server is a JVM service plus a
// backing store), gives clients a self-describing schema, and its nested
// selections (pod -> edges -> peer -> pod -> edges) express the one-hop and
// two-hop questions NetworkPolicy authoring asks. What it gives up is arbitrary
// path search (Gremlin's repeat()), which policy, being per-hop, does not need.
package gql

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/gqlerrors"

	"github.com/terraboops/podpeers/internal/graph"
)

// index holds lookups over one Result.
type index struct {
	res      graph.Result
	pods     map[string]graph.Pod
	services map[string]graph.Service
	byPod    map[string][]graph.Edge // edges observed on a pod
	toPod    map[string][]graph.Edge // edges whose peer is a pod
}

func newIndex(r graph.Result) *index {
	ix := &index{res: r, pods: map[string]graph.Pod{}, services: map[string]graph.Service{},
		byPod: map[string][]graph.Edge{}, toPod: map[string][]graph.Edge{}}
	for _, p := range r.Pods {
		ix.pods[p.ID()] = p
	}
	for _, s := range r.Services {
		ix.services[s.ID()] = s
	}
	for _, e := range r.Edges {
		ix.byPod[e.Pod] = append(ix.byPod[e.Pod], e)
		if e.Peer.Kind == graph.PeerPod {
			ix.toPod[e.Peer.ID()] = append(ix.toPod[e.Peer.ID()], e)
		}
	}
	return ix
}

type kv struct{ Key, Value string }

func labels(m map[string]string) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// edgeFilter is shared by Query.edges and Pod.edges.
type edgeFilter struct {
	direction, peerKind, protocol string
	port                          int
	open                          *bool
}

func filterArgs() graphql.FieldConfigArgument {
	return graphql.FieldConfigArgument{
		"direction": {Type: graphql.String, Description: "inbound or outbound"},
		"peerKind":  {Type: graphql.String, Description: "pod, service, node or external"},
		"protocol":  {Type: graphql.String, Description: "tcp or udp"},
		"port":      {Type: graphql.Int},
		"open":      {Type: graphql.Boolean, Description: "true: still open at window end; false: closed during the window"},
	}
}

func parseFilter(args map[string]any) edgeFilter {
	f := edgeFilter{}
	f.direction, _ = args["direction"].(string)
	f.peerKind, _ = args["peerKind"].(string)
	f.protocol, _ = args["protocol"].(string)
	f.port, _ = args["port"].(int)
	if o, ok := args["open"].(bool); ok {
		f.open = &o
	}
	return f
}

func (f edgeFilter) match(e graph.Edge) bool {
	return (f.direction == "" || string(e.Direction) == f.direction) &&
		(f.peerKind == "" || string(e.Peer.Kind) == f.peerKind) &&
		(f.protocol == "" || e.Protocol == f.protocol) &&
		(f.port == 0 || int(e.Port) == f.port) &&
		(f.open == nil || e.Open == *f.open)
}

func filterEdges(es []graph.Edge, f edgeFilter) []graph.Edge {
	out := []graph.Edge{}
	for _, e := range es {
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out
}

func uniquePeers(es []graph.Edge) []graph.Peer {
	seen := map[string]bool{}
	out := []graph.Peer{}
	for _, e := range es {
		if !seen[e.Peer.ID()] {
			seen[e.Peer.ID()] = true
			out = append(out, e.Peer)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// NewSchema builds the GraphQL schema over a capture.
func NewSchema(r graph.Result) (graphql.Schema, error) {
	ix := newIndex(r)
	timeField := func(get func(any) time.Time) *graphql.Field {
		return &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) {
			t := get(p.Source)
			if t.IsZero() {
				return nil, nil
			}
			return t.UTC().Format(time.RFC3339), nil
		}}
	}

	labelT := graphql.NewObject(graphql.ObjectConfig{Name: "Label", Fields: graphql.Fields{
		"key":   {Type: graphql.NewNonNull(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(kv).Key, nil }},
		"value": {Type: graphql.NewNonNull(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(kv).Value, nil }},
	}})
	probeT := graphql.NewObject(graphql.ObjectConfig{Name: "Probe", Fields: graphql.Fields{
		"status":   {Type: graphql.NewNonNull(graphql.String), Description: "observed, failed, skipped or not-targeted", Resolve: func(p graphql.ResolveParams) (any, error) { return string(p.Source.(graph.Probe).Status), nil }},
		"reason":   {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Probe).Reason, nil }},
		"samples":  {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Probe).Samples, nil }},
		"complete": {Type: graphql.Boolean, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Probe).Complete, nil }},
	}})
	listenerT := graphql.NewObject(graphql.ObjectConfig{Name: "Listener", Fields: graphql.Fields{
		"protocol": {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Listener).Protocol, nil }},
		"address":  {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Listener).Address, nil }},
		"port":     {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return int(p.Source.(graph.Listener).Port), nil }},
	}})
	serviceT := graphql.NewObject(graphql.ObjectConfig{Name: "Service", Fields: graphql.Fields{
		"id":         {Type: graphql.String, Description: "\"svc/ns/name\", the same id a Peer of kind service has", Resolve: func(p graphql.ResolveParams) (any, error) { return "svc/" + p.Source.(graph.Service).ID(), nil }},
		"namespace":  {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Service).Namespace, nil }},
		"name":       {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Service).Name, nil }},
		"clusterIPs": {Type: graphql.NewList(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Service).ClusterIPs, nil }},
		"selector":   {Type: graphql.NewList(labelT), Resolve: func(p graphql.ResolveParams) (any, error) { return labels(p.Source.(graph.Service).Selector), nil }},
	}})
	windowT := graphql.NewObject(graphql.ObjectConfig{Name: "Window", Fields: graphql.Fields{
		"start":      timeField(func(s any) time.Time { return s.(graph.Window).Start }),
		"end":        timeField(func(s any) time.Time { return s.(graph.Window).End }),
		"interval":   {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Window).Interval, nil }},
		"samplesMin": {Type: graphql.Int, Description: "fewest samples any observed pod got", Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Window).SamplesMin, nil }},
		"samplesMax": {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Window).SamplesMax, nil }},
	}})

	var podT, peerT, edgeT *graphql.Object
	podT = graphql.NewObject(graphql.ObjectConfig{Name: "Pod", Fields: graphql.FieldsThunk(func() graphql.Fields {
		return graphql.Fields{
			"id":        {Type: graphql.NewNonNull(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).ID(), nil }},
			"namespace": {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Namespace, nil }},
			"name":      {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Name, nil }},
			"ip":        {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).IP, nil }},
			"node":      {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Node, nil }},
			"workload": {Type: graphql.String, Description: "owning controller, Kind/name",
				Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Workload, nil }},
			"hostNetwork": {Type: graphql.Boolean, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).HostNetwork, nil }},
			"labels":      {Type: graphql.NewList(labelT), Resolve: func(p graphql.ResolveParams) (any, error) { return labels(p.Source.(graph.Pod).Labels), nil }},
			"label": {Type: graphql.String, Args: graphql.FieldConfigArgument{"key": {Type: graphql.NewNonNull(graphql.String)}},
				Resolve: func(p graphql.ResolveParams) (any, error) {
					v, ok := p.Source.(graph.Pod).Labels[p.Args["key"].(string)]
					if !ok {
						return nil, nil
					}
					return v, nil
				}},
			"probe":     {Type: probeT, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Probe, nil }},
			"listening": {Type: graphql.NewList(listenerT), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Pod).Listening, nil }},
			"edges": {Type: graphql.NewList(edgeT), Args: filterArgs(), Description: "connections observed on this pod",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return filterEdges(ix.byPod[p.Source.(graph.Pod).ID()], parseFilter(p.Args)), nil
				}},
			"peers": {Type: graphql.NewList(peerT), Args: filterArgs(), Description: "distinct peers of this pod",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return uniquePeers(filterEdges(ix.byPod[p.Source.(graph.Pod).ID()], parseFilter(p.Args))), nil
				}},
			"seenBy": {Type: graphql.NewList(edgeT), Args: filterArgs(),
				Description: "edges observed on OTHER pods whose peer is this pod; the only evidence for pods that were not probed",
				Resolve: func(p graphql.ResolveParams) (any, error) {
					return filterEdges(ix.toPod[p.Source.(graph.Pod).ID()], parseFilter(p.Args)), nil
				}},
		}
	})})
	peerT = graphql.NewObject(graphql.ObjectConfig{Name: "Peer", Description: "a pod, service, node or external address on the far side of an edge",
		Fields: graphql.FieldsThunk(func() graphql.Fields {
			return graphql.Fields{
				"id":        {Type: graphql.NewNonNull(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Peer).ID(), nil }},
				"kind":      {Type: graphql.NewNonNull(graphql.String), Resolve: func(p graphql.ResolveParams) (any, error) { return string(p.Source.(graph.Peer).Kind), nil }},
				"namespace": {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Peer).Namespace, nil }},
				"name":      {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Peer).Name, nil }},
				"ip":        {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Peer).IP, nil }},
				"podRange": {Type: graphql.NewNonNull(graphql.Boolean), Description: "a node found by its pod range, not its IP: the node's own pod-network address",
					Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Peer).PodRange, nil }},
				"pod": {Type: podT, Resolve: func(p graphql.ResolveParams) (any, error) {
					pr := p.Source.(graph.Peer)
					if pod, ok := ix.pods[pr.ID()]; ok && pr.Kind == graph.PeerPod {
						return pod, nil
					}
					return nil, nil
				}},
				"service": {Type: serviceT, Resolve: func(p graphql.ResolveParams) (any, error) {
					pr := p.Source.(graph.Peer)
					if s, ok := ix.services[pr.Namespace+"/"+pr.Name]; ok && pr.Kind == graph.PeerService {
						return s, nil
					}
					return nil, nil
				}},
			}
		})})
	edgeT = graphql.NewObject(graphql.ObjectConfig{Name: "Edge", Fields: graphql.FieldsThunk(func() graphql.Fields {
		return graphql.Fields{
			"pod": {Type: podT, Resolve: func(p graphql.ResolveParams) (any, error) { return ix.pods[p.Source.(graph.Edge).Pod], nil }},
			"direction": {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) {
				return string(p.Source.(graph.Edge).Direction), nil
			}},
			"peer":        {Type: peerT, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Peer, nil }},
			"port":        {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return int(p.Source.(graph.Edge).Port), nil }},
			"protocol":    {Type: graphql.String, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Protocol, nil }},
			"connections": {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Connections, nil }},
			"samples":     {Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Samples, nil }},
			"open":        {Type: graphql.Boolean, Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Open, nil }},
			"failedConnections": {Type: graphql.Int, Description: "connections that never completed a handshake",
				Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).FailedConnections, nil }},
			"attempted": {Type: graphql.Boolean, Description: "only ever seen half-open (SYN_SENT): tried and never connected",
				Resolve: func(p graphql.ResolveParams) (any, error) { return p.Source.(graph.Edge).Attempted, nil }},
			"firstSeen": timeField(func(s any) time.Time { return s.(graph.Edge).FirstSeen }),
			"lastSeen":  timeField(func(s any) time.Time { return s.(graph.Edge).LastSeen }),
		}
	})})

	query := graphql.NewObject(graphql.ObjectConfig{Name: "Query", Fields: graphql.Fields{
		"window": {Type: windowT, Resolve: func(graphql.ResolveParams) (any, error) { return r.Window, nil }},
		"limits": {Type: graphql.NewList(graphql.String), Description: "what this capture could NOT have seen (sampling resolution, unconnected UDP, ClusterIP rewriting, no history)",
			Resolve: func(graphql.ResolveParams) (any, error) {
				if len(r.Limits) > 0 {
					return r.Limits, nil
				}
				return graph.ComputeLimits(r), nil
			}},
		"pods": {Type: graphql.NewList(podT),
			Args: graphql.FieldConfigArgument{
				"namespace": {Type: graphql.String},
				"status":    {Type: graphql.String, Description: "probe status: observed, failed, skipped, not-targeted"},
				"label":     {Type: graphql.String, Description: "key or key=value"},
			},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				ns, _ := p.Args["namespace"].(string)
				st, _ := p.Args["status"].(string)
				lbl, _ := p.Args["label"].(string)
				lk, lv, hasV := strings.Cut(lbl, "=")
				out := []graph.Pod{}
				for _, pod := range r.Pods {
					if ns != "" && pod.Namespace != ns || st != "" && string(pod.Probe.Status) != st {
						continue
					}
					if lbl != "" {
						v, ok := pod.Labels[lk]
						if !ok || hasV && v != lv {
							continue
						}
					}
					out = append(out, pod)
				}
				return out, nil
			}},
		"pod": {Type: podT, Description: "look up by id (\"ns/name\") or by namespace and name",
			Args: graphql.FieldConfigArgument{"id": {Type: graphql.String}, "namespace": {Type: graphql.String}, "name": {Type: graphql.String}},
			Resolve: func(p graphql.ResolveParams) (any, error) {
				id, _ := p.Args["id"].(string)
				if id == "" {
					ns, _ := p.Args["namespace"].(string)
					n, _ := p.Args["name"].(string)
					if ns == "" || n == "" {
						return nil, fmt.Errorf("pod: give id, or namespace and name")
					}
					id = ns + "/" + n
				}
				if pod, ok := ix.pods[id]; ok {
					return pod, nil
				}
				return nil, nil
			}},
		"edges": {Type: graphql.NewList(edgeT), Args: filterArgs(), Resolve: func(p graphql.ResolveParams) (any, error) {
			return filterEdges(r.Edges, parseFilter(p.Args)), nil
		}},
		"peers": {Type: graphql.NewList(peerT), Args: filterArgs(), Description: "every distinct peer referenced by any edge",
			Resolve: func(p graphql.ResolveParams) (any, error) {
				return uniquePeers(filterEdges(r.Edges, parseFilter(p.Args))), nil
			}},
		"services": {Type: graphql.NewList(serviceT), Resolve: func(graphql.ResolveParams) (any, error) { return r.Services, nil }},
	}})
	s, err := graphql.NewSchema(graphql.SchemaConfig{Query: query})
	if err != nil {
		return s, err
	}
	// The schema is cyclic (pod -> edges -> pod -> ...), so a short query can
	// ask for work exponential in its nesting. Every field resolution draws on
	// a per-query budget; once it is spent, fields stop expanding.
	for name, t := range s.TypeMap() {
		o, ok := t.(*graphql.Object)
		if !ok || strings.HasPrefix(name, "__") {
			continue
		}
		for _, f := range o.Fields() {
			if f.Resolve != nil {
				f.Resolve = budgeted(f.Resolve, zeroOf(f.Type))
			}
		}
	}
	return s, nil
}

// MaxFields bounds the field resolutions one query may cost. A full dump of
// a large capture stays well inside it; a query nesting the cycle to blow up
// does not.
var MaxFields int64 = 250000

type budgetKey struct{}

// budgeted makes a resolver draw on the query's budget. Once it is spent the
// field resolves to a cheap zero of its own type, so nothing expands further.
// Do then discards the data and answers one error: returning an error (with
// its full path) per refused field is what made a refusal itself huge, a
// 74 MB response at 430 MiB on a real capture.
func budgeted(next graphql.FieldResolveFn, zero any) graphql.FieldResolveFn {
	return func(p graphql.ResolveParams) (any, error) {
		if left, ok := p.Context.Value(budgetKey{}).(*atomic.Int64); ok && left.Add(-1) < 0 {
			return zero, nil
		}
		return next(p)
	}
}

// zeroOf is the cheapest value a field of type t can resolve to without
// expanding: an empty list, a zero scalar, or null for an object.
func zeroOf(t graphql.Output) any {
	if nn, ok := t.(*graphql.NonNull); ok {
		t = nn.OfType
	}
	switch tt := t.(type) {
	case *graphql.List:
		return []any{}
	case *graphql.Scalar:
		switch tt.Name() {
		case "Int":
			return 0
		case "Float":
			return 0.0
		case "Boolean":
			return false
		}
		return ""
	}
	return nil
}

// Do runs one query and returns the standard GraphQL response.
func Do(s graphql.Schema, query string, vars map[string]any) *graphql.Result {
	left := new(atomic.Int64)
	left.Store(MaxFields)
	ctx := context.WithValue(context.Background(), budgetKey{}, left)
	r := graphql.Do(graphql.Params{Schema: s, RequestString: query, VariableValues: vars, Context: ctx})
	if left.Load() < 0 {
		return &graphql.Result{Errors: []gqlerrors.FormattedError{gqlerrors.NewFormattedError(fmt.Sprintf(
			"query too large: it resolves more than %d fields; select fewer fields, nest less, or filter", MaxFields))}}
	}
	return r
}
