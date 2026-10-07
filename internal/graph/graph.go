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
	// Workload is the controller that owns the pod, "Kind/name" (a pod owned by
	// a ReplicaSet reports its Deployment), or "Pod/<name>" for a bare pod. It is
	// stable across pod restarts, unlike the pod name.
	Workload  string     `json:"workload,omitempty"`
	Probe     Probe      `json:"probe"`
	Listening []Listener `json:"listening,omitempty"`
}

func (p Pod) ID() string { return p.Namespace + "/" + p.Name }

// WorkloadID is "ns/Kind/name", falling back to the pod itself.
func (p Pod) WorkloadID() string {
	if p.Workload == "" {
		return p.Namespace + "/Pod/" + p.Name
	}
	return p.Namespace + "/" + p.Workload
}

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
	Ports      []ServicePort     `json:"ports,omitempty"`
}

// ServicePort maps a service port to the pod port traffic is DNATed to.
// TargetPort is a number or a container port name, as in the Service spec.
type ServicePort struct {
	Protocol   string `json:"protocol"`
	Port       uint16 `json:"port"`
	TargetPort string `json:"targetPort"`
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
	// FailedConnections counts connections that never completed a handshake
	// (only ever SYN_SENT, SYN_RECV, or CLOSE after a refused connect).
	FailedConnections int `json:"failedConnections,omitempty"`
	// Attempted is true when connections on this edge failed and none was
	// ever seen ESTABLISHED in the window: something kept trying and never got
	// through. A NetworkPolicy that drops or rejects traffic produces exactly
	// this. (TIME_WAIT leftovers from before the window do not count as
	// getting through: they predate it.)
	Attempted bool `json:"attempted,omitempty"`
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
		edge        Edge
		conns       map[connKey]bool // value: the connection completed a handshake
		seen        map[int]bool
		established bool // some connection was seen ESTABLISHED (or UDP)
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
			ck := connKey{k.Protocol, k.Local, k.Remote}
			a.conns[ck] = a.conns[ck] || k.Protocol == procnet.UDP || handshakeDone(k.State)
			a.seen[i] = true
			if s.Time.After(a.edge.LastSeen) {
				a.edge.LastSeen = s.Time
			}
			if k.Protocol == procnet.UDP || k.State == procnet.Established {
				a.established = true
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
		for _, ok := range a.conns {
			if !ok {
				a.edge.FailedConnections++
			}
		}
		a.edge.Attempted = a.edge.FailedConnections > 0 && !a.established
		a.edge.Samples = len(a.seen)
		outE = append(outE, a.edge)
	}
	SortEdges(outE)
	return outL, outE
}

// handshakeDone reports whether a TCP state can only be reached after the
// three-way handshake completed. SYN_SENT and SYN_RECV are mid-handshake, and
// CLOSE with a remote address is what a connect() refused by a REJECT rule or a
// RST leaves behind, so none of those prove the connection ever worked.
func handshakeDone(s procnet.State) bool {
	switch s {
	case procnet.Established, procnet.FinWait1, procnet.FinWait2, procnet.TimeWait,
		procnet.CloseWait, procnet.LastAck, procnet.Closing:
		return true
	}
	return false
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

// Flow is an edge oriented from client to server, which is how traffic and
// NetworkPolicy read: an outbound edge on A to B is A->B, and an inbound edge on
// B from A is also A->B.
type Flow struct {
	From, To   string // pod IDs, or Peer.ID() for non-pod peers
	Port       uint16
	Protocol   string
	Open       bool
	Attempted  bool
	ObservedOn string // pod whose sockets showed it
}

// Flows lists every edge as a client->server flow.
func (r Result) Flows() []Flow {
	var out []Flow
	for _, e := range r.Edges {
		f := Flow{Port: e.Port, Protocol: e.Protocol, Open: e.Open, Attempted: e.Attempted, ObservedOn: e.Pod}
		if e.Direction == Outbound {
			f.From, f.To = e.Pod, e.Peer.ID()
		} else {
			f.From, f.To = e.Peer.ID(), e.Pod
		}
		out = append(out, f)
	}
	return out
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
