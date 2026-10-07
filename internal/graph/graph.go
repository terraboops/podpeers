// Package graph turns per-pod socket samples into a peer graph: which pods talk
// to which pods, services, nodes and external addresses, on which ports, in
// which direction, and whether each connection was still open at the end of the
// measurement window.
//
// The Result type is podpeers' stable on-disk format (schema "podpeers/v1"); the
// renderers and the GraphQL interface read only this.
package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/terraboops/podpeers/internal/procnet"
)

const Schema = "podpeers/v1"

// Direction of an edge relative to the observed pod.
type Direction string

const (
	Inbound  Direction = "inbound"  // the peer connected to this pod
	Outbound Direction = "outbound" // this pod connected to the peer
)

// PeerKind classifies what a remote address resolved to.
type PeerKind string

const (
	PeerPod      PeerKind = "pod"
	PeerService  PeerKind = "service"
	PeerNode     PeerKind = "node"
	PeerExternal PeerKind = "external"
)

// ProbeStatus says what happened when podpeers tried to observe a pod.
type ProbeStatus string

const (
	ProbeObserved    ProbeStatus = "observed"     // sampler ran and produced samples
	ProbeFailed      ProbeStatus = "failed"       // debug container could not be added, start, or be read
	ProbeSkipped     ProbeStatus = "skipped"      // targeted but deliberately not probed (not Running, hostNetwork)
	ProbeNotTargeted ProbeStatus = "not-targeted" // known only as a peer of a targeted pod
)

// Result is a complete capture.
type Result struct {
	Schema   string    `json:"schema"`
	Window   Window    `json:"window"`
	Selector Selector  `json:"selector"`
	Pods     []Pod     `json:"pods"`
	Services []Service `json:"services"`
	Edges    []Edge    `json:"edges"`
}

type Window struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Interval string    `json:"interval"`
}

type Selector struct {
	Namespace     string `json:"namespace"` // "" = all namespaces
	LabelSelector string `json:"labelSelector"`
}

type Pod struct {
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	IP          string            `json:"ip,omitempty"`
	Node        string            `json:"node,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	HostNetwork bool              `json:"hostNetwork,omitempty"`
	Probe       Probe             `json:"probe"`
	Listening   []Listener        `json:"listening,omitempty"`
}

func (p Pod) ID() string { return p.Namespace + "/" + p.Name }

type Probe struct {
	Status  ProbeStatus `json:"status"`
	Reason  string      `json:"reason,omitempty"`
	Samples int         `json:"samples,omitempty"`
	// Complete is false when the sampler's log ended before its window did.
	Complete bool `json:"complete,omitempty"`
}

type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
}

type Service struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	ClusterIPs []string          `json:"clusterIPs,omitempty"`
	Selector   map[string]string `json:"selector,omitempty"`
}

func (s Service) ID() string { return s.Namespace + "/" + s.Name }

// Peer is the far end of an edge.
type Peer struct {
	Kind      PeerKind `json:"kind"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	IP        string   `json:"ip"`
}

// ID is a stable identifier: "ns/name" for pods (matching Pod.ID),
// "svc/ns/name" for services (a pod and a service may share a name),
// "node/name" for nodes, and the bare IP for external addresses.
func (p Peer) ID() string {
	switch p.Kind {
	case PeerPod:
		return p.Namespace + "/" + p.Name
	case PeerService:
		return "svc/" + p.Namespace + "/" + p.Name
	case PeerNode:
		return "node/" + p.Name
	}
	return p.IP
}

// Edge aggregates every connection between one observed pod and one peer on
// one service port.
type Edge struct {
	Pod       string    `json:"pod"` // observed pod, "ns/name"
	Direction Direction `json:"direction"`
	Peer      Peer      `json:"peer"`
	// Port is the service port of the connection: the pod's own listening port
	// for inbound edges, the peer's port for outbound edges.
	Port        uint16    `json:"port"`
	Protocol    string    `json:"protocol"`
	Connections int       `json:"connections"` // distinct socket 4-tuples seen
	FirstSeen   time.Time `json:"firstSeen"`
	LastSeen    time.Time `json:"lastSeen"`
	Samples     int       `json:"samples"` // samples in which the edge was present
	// Open is true when a connection on this edge was ESTABLISHED in the pod's
	// final sample. False means it closed during the window.
	Open bool `json:"open"`
}

// Inventory is what the cluster API said existed during the capture; it is how
// remote IPs are resolved to names.
type Inventory struct {
	Pods     []Pod
	Services []Service
	Nodes    []Node
}

type Node struct {
	Name string
	IPs  []string
}

// Observation is the sampler output for one targeted pod.
type Observation struct {
	Pod     string // "ns/name"
	Samples []procnet.Sample
}

// Resolver maps an IP address to the peer it belongs to.
type Resolver struct {
	pods     map[netip.Addr]Pod
	services map[netip.Addr]Service
	nodes    map[netip.Addr]string
}

// NewResolver indexes an inventory. Host-network pods share their node's IP, so
// they are left out of the pod index: such an address resolves to the node.
func NewResolver(inv Inventory) *Resolver {
	r := &Resolver{
		pods:     map[netip.Addr]Pod{},
		services: map[netip.Addr]Service{},
		nodes:    map[netip.Addr]string{},
	}
	for _, p := range inv.Pods {
		if p.HostNetwork || p.IP == "" {
			continue
		}
		if a, err := netip.ParseAddr(p.IP); err == nil {
			r.pods[a.Unmap()] = p
		}
	}
	for _, s := range inv.Services {
		for _, ip := range s.ClusterIPs {
			if a, err := netip.ParseAddr(ip); err == nil {
				r.services[a.Unmap()] = s
			}
		}
	}
	for _, n := range inv.Nodes {
		for _, ip := range n.IPs {
			if a, err := netip.ParseAddr(ip); err == nil {
				r.nodes[a.Unmap()] = n.Name
			}
		}
	}
	return r
}

func (r *Resolver) Resolve(a netip.Addr) Peer {
	a = a.Unmap()
	if p, ok := r.pods[a]; ok {
		return Peer{Kind: PeerPod, Namespace: p.Namespace, Name: p.Name, IP: a.String()}
	}
	if s, ok := r.services[a]; ok {
		return Peer{Kind: PeerService, Namespace: s.Namespace, Name: s.Name, IP: a.String()}
	}
	if n, ok := r.nodes[a]; ok {
		return Peer{Kind: PeerNode, Name: n, IP: a.String()}
	}
	return Peer{Kind: PeerExternal, IP: a.String()}
}

type listenKey struct {
	proto procnet.Protocol
	port  uint16
}

type edgeKey struct {
	dir   Direction
	ip    netip.Addr
	port  uint16
	proto procnet.Protocol
}

type connKey struct {
	proto         procnet.Protocol
	local, remote netip.AddrPort
}

// Analyze derives the listeners and edges of one observed pod from its samples.
//
// Direction inference mirrors how an operator reads netstat: a connection whose
// local port is one the pod listens on (in any sample) is inbound; anything else
// is outbound. Loopback traffic stays inside the pod and is ignored, as are
// sockets with no remote address.
func Analyze(pod string, samples []procnet.Sample, res *Resolver) ([]Listener, []Edge) {
	listening := map[listenKey]bool{}
	listeners := map[Listener]bool{}
	for _, s := range samples {
		for _, k := range s.Sockets {
			if k.IsListener() {
				listening[listenKey{k.Protocol, k.Local.Port()}] = true
				listeners[Listener{string(k.Protocol), k.Local.Addr().String(), k.Local.Port()}] = true
			}
		}
	}

	type agg struct {
		edge  Edge
		conns map[connKey]bool
		seen  map[int]bool
	}
	edges := map[edgeKey]*agg{}
	last := len(samples) - 1
	for i, s := range samples {
		for _, k := range s.Sockets {
			if k.IsListener() || !k.HasRemote() {
				continue
			}
			if k.Remote.Addr().IsLoopback() || k.Local.Addr().IsLoopback() {
				continue
			}
			ek := edgeKey{proto: k.Protocol, ip: k.Remote.Addr().Unmap()}
			if listening[listenKey{k.Protocol, k.Local.Port()}] {
				ek.dir, ek.port = Inbound, k.Local.Port()
			} else {
				ek.dir, ek.port = Outbound, k.Remote.Port()
			}
			a := edges[ek]
			if a == nil {
				a = &agg{
					edge: Edge{Pod: pod, Direction: ek.dir, Peer: res.Resolve(ek.ip), Port: ek.port,
						Protocol: string(k.Protocol), FirstSeen: s.Time},
					conns: map[connKey]bool{},
					seen:  map[int]bool{},
				}
				edges[ek] = a
			}
			a.conns[connKey{k.Protocol, k.Local, k.Remote}] = true
			a.seen[i] = true
			if s.Time.After(a.edge.LastSeen) {
				a.edge.LastSeen = s.Time
			}
			if i == last && (k.State == procnet.Established || k.Protocol == procnet.UDP) {
				a.edge.Open = true
			}
		}
	}

	var outL []Listener
	for l := range listeners {
		outL = append(outL, l)
	}
	sort.Slice(outL, func(i, j int) bool {
		if outL[i].Protocol != outL[j].Protocol {
			return outL[i].Protocol < outL[j].Protocol
		}
		if outL[i].Port != outL[j].Port {
			return outL[i].Port < outL[j].Port
		}
		return outL[i].Address < outL[j].Address
	})
	var outE []Edge
	for _, a := range edges {
		a.edge.Connections = len(a.conns)
		a.edge.Samples = len(a.seen)
		outE = append(outE, a.edge)
	}
	SortEdges(outE)
	return outL, outE
}

// SortEdges orders edges deterministically for stable output and diffs.
func SortEdges(es []Edge) {
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Peer.ID() != b.Peer.ID() {
			return a.Peer.ID() < b.Peer.ID()
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Peer.IP < b.Peer.IP
	})
}

// Build assembles a Result. targets carries the probe outcome of every pod the
// selector matched (observed, failed or skipped); obs holds the samples of the
// observed ones. Pods that appear only as peers are added as not-targeted so
// that every pod ID referenced by an edge exists in Result.Pods.
func Build(sel Selector, win Window, inv Inventory, targets []Pod, obs []Observation) (Result, error) {
	res := NewResolver(inv)
	byID := map[string]*Pod{}
	var order []string
	for i := range targets {
		p := targets[i]
		if _, dup := byID[p.ID()]; dup {
			return Result{}, fmt.Errorf("graph: pod %s targeted twice", p.ID())
		}
		byID[p.ID()] = &p
		order = append(order, p.ID())
	}
	var edges []Edge
	for _, o := range obs {
		p := byID[o.Pod]
		if p == nil {
			return Result{}, fmt.Errorf("graph: observation for untargeted pod %s", o.Pod)
		}
		var es []Edge
		p.Listening, es = Analyze(o.Pod, o.Samples, res)
		edges = append(edges, es...)
	}

	invPods := map[string]Pod{}
	for _, p := range inv.Pods {
		invPods[p.ID()] = p
	}
	usedSvc := map[string]bool{}
	for _, e := range edges {
		switch e.Peer.Kind {
		case PeerPod:
			id := e.Peer.ID()
			if _, ok := byID[id]; !ok {
				p := invPods[id]
				p.Probe = Probe{Status: ProbeNotTargeted}
				byID[id] = &p
				order = append(order, id)
			}
		case PeerService:
			usedSvc[e.Peer.Namespace+"/"+e.Peer.Name] = true
		}
	}
	out := Result{Schema: Schema, Window: win, Selector: sel, Edges: edges}
	sort.Strings(order)
	for _, id := range order {
		out.Pods = append(out.Pods, *byID[id])
	}
	for _, s := range inv.Services {
		if usedSvc[s.ID()] {
			out.Services = append(out.Services, s)
		}
	}
	sort.Slice(out.Services, func(i, j int) bool { return out.Services[i].ID() < out.Services[j].ID() })
	SortEdges(out.Edges)
	return out, nil
}

// Load decodes a capture file and checks its schema version.
func Load(r io.Reader) (Result, error) {
	var res Result
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return Result{}, fmt.Errorf("reading capture: %w", err)
	}
	if res.Schema != Schema {
		return Result{}, fmt.Errorf("capture schema %q is not %q", res.Schema, Schema)
	}
	return res, nil
}

// LoadFile reads a capture from disk.
func LoadFile(path string) (Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	return Load(f)
}
