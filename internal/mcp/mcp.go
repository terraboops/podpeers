// Package mcp serves a capture over the Model Context Protocol (stdio
// transport, newline-delimited JSON-RPC 2.0), so an agent can query peers and
// policy suggestions directly.
//
// Every tool is read-only over capture files. There is deliberately no tool
// that runs a capture: launching debug containers in a cluster stays a
// deliberate, guarded CLI action, never something an agent can trigger through
// a tool call.
package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/terraboops/podpeers/internal/diff"
	"github.com/terraboops/podpeers/internal/gql"
	"github.com/terraboops/podpeers/internal/graph"
	"github.com/terraboops/podpeers/internal/policy"
	"github.com/terraboops/podpeers/internal/render"
)

// ProtocolVersion is the newest MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

var supportedVersions = map[string]bool{"2024-11-05": true, "2025-03-26": true, "2025-06-18": true}

// Server answers MCP requests about one capture file, re-read on every call so
// a fresh capture written to the same path is picked up without a restart.
type Server struct {
	CapturePath string
	Version     string
	out         io.Writer
	mu          sync.Mutex
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Serve reads requests from in until EOF.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	s.out = out
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.send(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error: " + err.Error()}})
			continue
		}
		if len(req.ID) == 0 { // notification: no reply
			continue
		}
		res, rerr := s.handle(req)
		s.send(response{JSONRPC: "2.0", ID: req.ID, Result: res, Error: rerr})
	}
	return sc.Err()
}

func (s *Server) send(r response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, _ := json.Marshal(r)
	s.out.Write(append(b, '\n'))
}

func (s *Server) handle(req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := ProtocolVersion
		if supportedVersions[p.ProtocolVersion] {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "podpeers", "version": s.Version},
			"instructions": "podpeers answers questions about one capture of observed pod network traffic: " +
				"which pods talk to which peers, and which NetworkPolicy would permit exactly that. Start with `summary`. " +
				"Policy suggestions carry reasoning and a NOT COVERED list; always relay the gaps. This server never touches a cluster.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params: " + err.Error()}
		}
		text, structured, err := s.call(p.Name, p.Arguments)
		if err != nil {
			if _, unknown := err.(unknownTool); unknown {
				return nil, &rpcError{-32602, err.Error()}
			}
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": err.Error()}}, "isError": true}, nil
		}
		res := map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
		if structured != nil {
			res["structuredContent"] = structured
		}
		return res, nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

type unknownTool string

func (u unknownTool) Error() string { return "unknown tool: " + string(u) }

func obj(props map[string]any, required ...string) map[string]any {
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var tools = []map[string]any{
	{"name": "summary", "description": "Human-readable report of the capture: window, every targeted pod, its listeners and peers, and probe failures.",
		"inputSchema": obj(map[string]any{})},
	{"name": "list_pods", "description": "Pods in the capture with probe status (observed, failed, skipped, not-targeted), workload, IP and labels.",
		"inputSchema": obj(map[string]any{"namespace": str("only this namespace"), "status": str("only this probe status")})},
	{"name": "peers", "description": "Every edge observed on one pod: direction, peer (pod, service, node or external), port, connection count, and whether it was open, closed during the window, or only attempted (SYN_SENT).",
		"inputSchema": obj(map[string]any{"pod": str("pod id, namespace/name"), "direction": str("inbound or outbound")}, "pod")},
	{"name": "query", "description": "Run a GraphQL query against the capture. Root fields: window, pods(namespace,status,label), pod(id), edges(direction,peerKind,protocol,port,open), peers, services. Pod has edges, peers, seenBy, listening, probe, labels, workload.",
		"inputSchema": obj(map[string]any{"query": str("GraphQL query"), "variables": map[string]any{"type": "object"}}, "query")},
	{"name": "suggest_policies", "description": "NetworkPolicy suggestions that permit exactly the observed traffic: ready-to-apply YAML, the reasoning for every rule, what each suggestion does NOT cover, and workloads refused because the evidence is too thin.",
		"inputSchema": obj(map[string]any{
			"namespace":   str("only workloads in this namespace"),
			"workload":    str("only this workload, Kind/name, e.g. Deployment/web"),
			"dns":         map[string]any{"type": "string", "enum": []string{"auto", "always", "never"}},
			"min_samples": map[string]any{"type": "integer", "minimum": 1},
			"allow_empty": map[string]any{"type": "boolean", "description": "emit deny-all for workloads with no observed traffic"},
		})},
	{"name": "diff_captures", "description": "Compare a capture taken before a policy change with one taken after. Reports flows now blocked (stuck in SYN_SENT), lost, or new, at workload level, with a BROKEN/OK verdict.",
		"inputSchema": obj(map[string]any{"before": str("path to the baseline capture JSON"), "after": str("path to the later capture JSON; defaults to the served capture")}, "before")},
}

func asJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) load() (graph.Result, error) {
	return graph.LoadFile(s.CapturePath)
}

func (s *Server) call(name string, args map[string]any) (string, any, error) {
	sarg := func(k string) string { v, _ := args[k].(string); return v }
	switch name {
	case "summary", "list_pods", "peers", "query", "suggest_policies", "diff_captures":
	default:
		return "", nil, unknownTool(name)
	}
	if name == "diff_captures" {
		before, err := graph.LoadFile(sarg("before"))
		if err != nil {
			return "", nil, err
		}
		afterPath := sarg("after")
		if afterPath == "" {
			afterPath = s.CapturePath
		}
		after, err := graph.LoadFile(afterPath)
		if err != nil {
			return "", nil, err
		}
		d := diff.Compare(before, after)
		var b bytes.Buffer
		d.Text(&b)
		return b.String(), map[string]any{"broken": d.Broken(), "changes": d.Changes, "unverifiable": d.Unverifiable}, nil
	}

	r, err := s.load()
	if err != nil {
		return "", nil, err
	}
	switch name {
	case "summary":
		var b bytes.Buffer
		render.Text(&b, r)
		return b.String(), nil, nil
	case "list_pods":
		pods := []graph.Pod{}
		for _, p := range r.Pods {
			if (sarg("namespace") == "" || p.Namespace == sarg("namespace")) && (sarg("status") == "" || string(p.Probe.Status) == sarg("status")) {
				pods = append(pods, p)
			}
		}
		return asJSON(pods), map[string]any{"pods": pods}, nil
	case "peers":
		id := sarg("pod")
		found := false
		for _, p := range r.Pods {
			found = found || p.ID() == id
		}
		if !found {
			return "", nil, fmt.Errorf("pod %q is not in the capture; use list_pods", id)
		}
		edges := []graph.Edge{}
		for _, e := range r.Edges {
			if e.Pod == id && (sarg("direction") == "" || string(e.Direction) == sarg("direction")) {
				edges = append(edges, e)
			}
		}
		return asJSON(edges), map[string]any{"edges": edges}, nil
	case "query":
		schema, err := gql.NewSchema(r)
		if err != nil {
			return "", nil, err
		}
		vars, _ := args["variables"].(map[string]any)
		res := gql.Do(schema, sarg("query"), vars)
		if res.HasErrors() {
			return "", nil, fmt.Errorf("graphql: %v", res.Errors)
		}
		return asJSON(res.Data), nil, nil
	case "suggest_policies":
		o := policy.Options{Namespace: sarg("namespace"), Workload: sarg("workload"), DNS: sarg("dns")}
		if n, ok := args["min_samples"].(float64); ok {
			o.MinSamples = int(n)
		}
		o.AllowEmpty, _ = args["allow_empty"].(bool)
		if o.DNS != "" && o.DNS != policy.DNSAuto && o.DNS != policy.DNSAlways && o.DNS != policy.DNSNever {
			return "", nil, fmt.Errorf("dns must be auto, always or never")
		}
		rep := policy.Suggest(r, o)
		y, err := rep.YAML()
		if err != nil {
			return "", nil, err
		}
		return y, rep, nil
	}
	return "", nil, unknownTool(name)
}
