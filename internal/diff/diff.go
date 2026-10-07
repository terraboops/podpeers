// Package diff compares two captures, typically one taken before a
// NetworkPolicy was applied and one taken after, to tell whether the policy
// broke anything.
//
// Flows are compared at workload level ("ns/Deployment/web"), not pod level,
// so pods restarting between the captures do not show up as changes.
package diff

import (
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/terraboops/podpeers/internal/graph"
)

// Kind of change.
const (
	Blocked = "blocked" // after: only ever half-open (SYN_SENT). The strongest signal of a policy drop.
	Lost    = "lost"    // seen before, absent after, although the observing workload was observed after
	New     = "new"     // absent before, established after
	// Preexisting: seen after, but only on connections that were already open
	// when the after-window began. They predate the policy change, and CNIs
	// do not re-evaluate established connections, so they prove nothing about
	// whether the policy allows this flow.
	Preexisting = "preexisting"
	// Glimpsed: absent after, but before it was only a single short
	// connection caught in a single sample (a DNS lookup, a one-off call).
	// Its absence is expected sampling noise, not evidence of a block.
	Glimpsed = "glimpsed"
)

type Change struct {
	Kind     string `json:"kind"`
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Detail   string `json:"detail"`
}

func (c Change) String() string {
	return fmt.Sprintf("%-7s %s -> %s %s/%d  (%s)", c.Kind, c.From, c.To, c.Protocol, c.Port, c.Detail)
}

type Result struct {
	Changes []Change `json:"changes"`
	// Unverifiable lists before-flows whose observing workload was not observed
	// in the after capture, so their absence proves nothing either way.
	Unverifiable []string `json:"unverifiable,omitempty"`
}

// Inconclusive reports whether some flow was only seen on connections that
// predate the after-window, so the policy was never exercised for it.
func (r Result) Inconclusive() bool {
	for _, c := range r.Changes {
		if c.Kind == Preexisting {
			return true
		}
	}
	return false
}

// Broken reports whether anything was blocked or lost.
func (r Result) Broken() bool {
	for _, c := range r.Changes {
		if c.Kind == Blocked || c.Kind == Lost {
			return true
		}
	}
	return false
}

type key struct {
	from, to, proto string
	port            uint16
}

type flowInfo struct {
	established bool // at least one observation got past the handshake
	attempted   bool // at least one observation was handshake-only
	newConns    int  // connections opened during the window
	samples     int  // most samples any observer saw it in
	conns       int  // connections across observers
	observers   map[string]bool
}

// Options refine a comparison.
type Options struct {
	// ChangedAt is when the change under test (a NetworkPolicy) took effect.
	// A connection involving a pod that started after it was necessarily
	// opened under the change, even if it was already open when the window
	// began. Zero means unknown: only connections opened during the window
	// count as exercising the change.
	ChangedAt time.Time
}

// workloadFlows aggregates a capture's flows by workload endpoints.
func workloadFlows(r graph.Result, o Options) (map[key]*flowInfo, map[string]bool) {
	wl := map[string]string{}
	observed := map[string]bool{}
	started := map[string]time.Time{}
	for _, p := range r.Pods {
		started[p.ID()] = p.StartTime
		wl[p.ID()] = p.WorkloadID()
		if p.Probe.Status == graph.ProbeObserved {
			observed[p.WorkloadID()] = true
		}
	}
	name := func(id string) string {
		if w, ok := wl[id]; ok {
			return w
		}
		return id
	}
	out := map[key]*flowInfo{}
	for _, f := range r.Flows() {
		k := key{name(f.From), name(f.To), f.Protocol, f.Port}
		fi := out[k]
		if fi == nil {
			fi = &flowInfo{observers: map[string]bool{}}
			out[k] = fi
		}
		if f.Attempted {
			fi.attempted = true
		} else {
			fi.established = true
		}
		fi.newConns += f.New
		fi.conns += f.Conns
		if f.Samples > fi.samples {
			fi.samples = f.Samples
		}
		if !o.ChangedAt.IsZero() && (started[f.From].After(o.ChangedAt) || started[f.To].After(o.ChangedAt)) {
			fi.newConns++ // an endpoint pod started under the change
		}
		fi.observers[name(f.ObservedOn)] = true
	}
	return out, observed
}

// Compare reports what changed from before to after.
func Compare(before, after graph.Result) Result { return CompareWith(before, after, Options{}) }

// CompareWith is Compare with options.
func CompareWith(before, after graph.Result, o Options) Result {
	bf, _ := workloadFlows(before, Options{})
	af, aObserved := workloadFlows(after, o)
	var res Result
	for k, a := range af {
		b := bf[k]
		switch {
		case a.attempted && !a.established:
			detail := "only half-open or refused after (SYN_SENT/CLOSE); never connected"
			if b != nil && b.established {
				detail = "connected before, never completes a handshake after: dropped or rejected"
			}
			res.Changes = append(res.Changes, Change{Blocked, k.from, k.to, k.proto, k.port, detail})
		case b == nil || !b.established:
			res.Changes = append(res.Changes, Change{New, k.from, k.to, k.proto, k.port, "not seen before"})
		case a.newConns == 0:
			res.Changes = append(res.Changes, Change{Preexisting, k.from, k.to, k.proto, k.port,
				"only connections already open before the window; the policy was never exercised for this flow"})
		}
	}
	for k, b := range bf {
		if !b.established {
			continue
		}
		if _, ok := af[k]; ok {
			continue
		}
		verifiable := false
		for o := range b.observers {
			if aObserved[o] {
				verifiable = true
			}
		}
		if !verifiable {
			res.Unverifiable = append(res.Unverifiable, fmt.Sprintf("%s -> %s %s/%d", k.from, k.to, k.proto, k.port))
			continue
		}
		if b.samples < 2 && b.conns < 2 {
			res.Changes = append(res.Changes, Change{Glimpsed, k.from, k.to, k.proto, k.port,
				"absent after, but before it was one short connection in one sample; sampling noise, not evidence of a block"})
			continue
		}
		res.Changes = append(res.Changes, Change{Lost, k.from, k.to, k.proto, k.port,
			"seen before, not at all after (blocked, or simply idle during the second window)"})
	}
	order := map[string]int{Blocked: 0, Lost: 1, Preexisting: 2, New: 3, Glimpsed: 4}
	sort.Slice(res.Changes, func(i, j int) bool {
		a, b := res.Changes[i], res.Changes[j]
		if a.Kind != b.Kind {
			return order[a.Kind] < order[b.Kind]
		}
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Port < b.Port
	})
	sort.Strings(res.Unverifiable)
	return res
}

// Text writes a human report.
func (r Result) Text(w io.Writer) {
	if len(r.Changes) == 0 {
		fmt.Fprintln(w, "no changes: every flow seen before was seen after, and nothing was blocked")
	}
	for _, c := range r.Changes {
		fmt.Fprintln(w, c.String())
	}
	for _, u := range r.Unverifiable {
		fmt.Fprintf(w, "unverifiable %s  (its observer was not observed in the second capture)\n", u)
	}
	switch {
	case r.Broken():
		fmt.Fprintln(w, "\nVERDICT: BROKEN - traffic that worked before is blocked or missing")
	case r.Inconclusive():
		fmt.Fprintln(w, "\nVERDICT: INCONCLUSIVE - some flows were only seen on connections opened before the policy;"+
			" restart those workloads so they reconnect under it, then capture again")
	default:
		fmt.Fprintln(w, "\nVERDICT: OK - nothing blocked or lost")
	}
}
