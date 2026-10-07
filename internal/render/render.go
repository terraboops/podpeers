// Package render turns a capture into human-facing views: a text report, a
// Graphviz DOT graph, and a self-contained interactive HTML page.
package render

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/terraboops/podpeers/internal/graph"
)

// Flow is an edge oriented from client to server, which is how traffic (and
// NetworkPolicy) reads: an outbound edge on A to B is A->B; an inbound edge on
// B from A is also A->B.
type Flow struct {
	From, To   string // node ids
	Port       uint16
	Protocol   string
	Open       bool
	ObservedOn string // pod whose sockets showed it
}

// Flows lists every edge as a client->server flow.
func Flows(r graph.Result) []Flow {
	var out []Flow
	for _, e := range r.Edges {
		f := Flow{Port: e.Port, Protocol: e.Protocol, Open: e.Open, ObservedOn: e.Pod}
		if e.Direction == graph.Outbound {
			f.From, f.To = e.Pod, e.Peer.ID()
		} else {
			f.From, f.To = e.Peer.ID(), e.Pod
		}
		out = append(out, f)
	}
	return out
}

func probeMark(p graph.Probe) string {
	switch p.Status {
	case graph.ProbeObserved:
		if !p.Complete {
			return "observed (partial)"
		}
		return "observed"
	case graph.ProbeNotTargeted:
		return "peer only"
	}
	if p.Reason != "" {
		return string(p.Status) + ": " + p.Reason
	}
	return string(p.Status)
}

// Text writes a plain report: one block per targeted pod, its listeners and
// peers, then a summary of probe outcomes.
func Text(w io.Writer, r graph.Result) error {
	ns := r.Selector.Namespace
	if ns == "" {
		ns = "all namespaces"
	}
	fmt.Fprintf(w, "podpeers capture: selector %q in %s\n", r.Selector.LabelSelector, ns)
	fmt.Fprintf(w, "window: %s .. %s (sample every %s)\n\n",
		r.Window.Start.UTC().Format("2006-01-02 15:04:05Z"), r.Window.End.UTC().Format("15:04:05Z"), r.Window.Interval)

	byPod := map[string][]graph.Edge{}
	for _, e := range r.Edges {
		byPod[e.Pod] = append(byPod[e.Pod], e)
	}
	counts := map[graph.ProbeStatus]int{}
	for _, p := range r.Pods {
		counts[p.Probe.Status]++
		if p.Probe.Status == graph.ProbeNotTargeted {
			continue
		}
		fmt.Fprintf(w, "%s  [%s]\n", p.ID(), probeMark(p.Probe))
		if p.Probe.Status != graph.ProbeObserved {
			fmt.Fprintln(w)
			continue
		}
		if len(p.Listening) > 0 {
			var ls []string
			for _, l := range p.Listening {
				ls = append(ls, fmt.Sprintf("%s/%d", l.Protocol, l.Port))
			}
			fmt.Fprintf(w, "  listening: %s\n", strings.Join(ls, ", "))
		}
		es := byPod[p.ID()]
		if len(es) == 0 {
			fmt.Fprintf(w, "  no peers observed\n\n")
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  DIR\tPEER\tKIND\tPORT\tCONNS\tSTATE")
		for _, e := range es {
			arrow := "->"
			if e.Direction == graph.Inbound {
				arrow = "<-"
			}
			state := "open"
			if !e.Open {
				state = "closed in window"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s/%d\t%d\t%s\n", arrow, e.Peer.ID(), e.Peer.Kind, e.Protocol, e.Port, e.Connections, state)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "pods: %d observed, %d failed, %d skipped, %d peer-only; %d edges\n",
		counts[graph.ProbeObserved], counts[graph.ProbeFailed], counts[graph.ProbeSkipped], counts[graph.ProbeNotTargeted], len(r.Edges))
	return nil
}

// DOT writes a Graphviz digraph with one cluster per namespace. Flows observed
// from both ends are drawn once.
func DOT(w io.Writer, r graph.Result) error {
	type node struct{ id, label, shape, style, ns string }
	nodes := map[string]node{}
	for _, p := range r.Pods {
		style := "solid"
		switch p.Probe.Status {
		case graph.ProbeNotTargeted:
			style = "dashed"
		case graph.ProbeFailed, graph.ProbeSkipped:
			style = "dotted"
		}
		nodes[p.ID()] = node{p.ID(), p.Name, "box", style, p.Namespace}
	}
	for _, e := range r.Edges {
		id := e.Peer.ID()
		if _, ok := nodes[id]; ok {
			continue
		}
		switch e.Peer.Kind {
		case graph.PeerService:
			nodes[id] = node{id, e.Peer.Name, "ellipse", "solid", e.Peer.Namespace}
		case graph.PeerNode:
			nodes[id] = node{id, e.Peer.Name, "hexagon", "solid", ""}
		default:
			nodes[id] = node{id, e.Peer.IP, "diamond", "solid", ""}
		}
	}
	byNS := map[string][]node{}
	for _, n := range nodes {
		byNS[n.ns] = append(byNS[n.ns], n)
	}
	nss := make([]string, 0, len(byNS))
	for ns := range byNS {
		nss = append(nss, ns)
	}
	sort.Strings(nss)

	fmt.Fprintln(w, "digraph podpeers {")
	fmt.Fprintln(w, `  rankdir=LR; node [fontname="Helvetica"]; edge [fontname="Helvetica", fontsize=10];`)
	for i, ns := range nss {
		ns_ := byNS[ns]
		sort.Slice(ns_, func(a, b int) bool { return ns_[a].id < ns_[b].id })
		indent := "  "
		if ns != "" {
			fmt.Fprintf(w, "  subgraph cluster_%d {\n    label=%q; style=rounded;\n", i, "namespace "+ns)
			indent = "    "
		}
		for _, n := range ns_ {
			fmt.Fprintf(w, "%s%q [label=%q, shape=%s, style=%s];\n", indent, n.id, n.label, n.shape, n.style)
		}
		if ns != "" {
			fmt.Fprintln(w, "  }")
		}
	}
	seen := map[string]bool{}
	for _, f := range Flows(r) {
		k := fmt.Sprintf("%s|%s|%s|%d", f.From, f.To, f.Protocol, f.Port)
		if seen[k] {
			continue
		}
		seen[k] = true
		style := "solid"
		if !f.Open {
			style = "dashed"
		}
		fmt.Fprintf(w, "  %q -> %q [label=%q, style=%s];\n", f.From, f.To, fmt.Sprintf("%s/%d", f.Protocol, f.Port), style)
	}
	fmt.Fprintln(w, "}")
	return nil
}

//go:embed page.html
var pageTemplate string

// HTML writes a self-contained interactive page (no network fetches). When
// graphqlPath is non-empty the page also shows a query console that posts to it.
func HTML(w io.Writer, r graph.Result, graphqlPath string) error {
	data, err := json.Marshal(r) // escapes <, > and & so it is safe inside <script>
	if err != nil {
		return err
	}
	gp, _ := json.Marshal(graphqlPath)
	page := strings.Replace(pageTemplate, "/*__DATA__*/null", string(data), 1)
	page = strings.Replace(page, "/*__GRAPHQL__*/\"\"", string(gp), 1)
	_, err = io.WriteString(w, page)
	return err
}
