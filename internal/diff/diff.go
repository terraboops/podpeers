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
	"math"
	"sort"
	"strings"

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
	// Glimpsed: absent after, but before it was seen so rarely that missing
	// it in every sample after is likely by chance alone (a DNS lookup, a
	// one-off call). Its absence is sampling noise, not evidence of a block.
	Glimpsed = "glimpsed"
)

// MissChance is the threshold for calling an absent flow lost: a flow seen in
// a fraction p of the observer's samples before goes unseen in all N samples
// after with probability (1-p)^N even when nothing changed. Only when that is
// below MissChance is its absence evidence. Short UDP exchanges (DNS) are
// sampled rarely: seen in 2 of 31 samples before, 31 empty samples after
// happen 13% of the time.
const MissChance = 0.01

type Change struct {
	Kind     string `json:"kind"`
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
	Detail   string `json:"detail"`
}

func (c Change) String() string {
	return fmt.Sprintf("%-7s %s -> %s %s/%d  (%s)", c.Kind, graph.Printable(c.From), graph.Printable(c.To), c.Protocol, c.Port, c.Detail)
}

type Result struct {
	Changes []Change `json:"changes"`
	// Unverifiable lists before-flows whose observing workload was not observed
	// in the after capture, so their absence proves nothing either way.
	Unverifiable []string `json:"unverifiable,omitempty"`
}

// Inconclusive reports whether some flow was only seen on connections that
// predate the after-window, so the policy was never exercised for it, or
// whether some flow's observer went unobserved, so nothing was checked at all.
func (r Result) Inconclusive() bool {
	if len(r.Unverifiable) > 0 {
		return true
	}
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
	newConns    int  // connections opened during the window that completed
	newFailed   int  // connections opened during the window that never completed
	samples     int  // most samples any observer saw it in
	conns       int  // connections across observers
	observers   map[string]bool
	samplesBy   map[string]int // observing workload -> most samples it saw the flow in
}

// Options refine a comparison.
type Options struct {
	// ExistingPods lists the pods ("ns/name") that existed when the change
	// under test (a NetworkPolicy) took effect. A connection involving a pod
	// that is not on the list, in a namespace that is, was necessarily opened
	// under the change, even if it was already open when the window began.
	// Comparing pod identity rather than timestamps keeps this exact and
	// immune to clock skew between the operator's machine and the cluster.
	// Nil means unknown: only connections opened during the window count.
	ExistingPods map[string]bool
}

// startedAfterChange reports whether pod id provably did not exist when the
// change took effect.
func (o Options) startedAfterChange(id string, known map[string]bool) bool {
	if o.ExistingPods == nil || !known[id] || o.ExistingPods[id] {
		return false
	}
	ns, _, _ := strings.Cut(id, "/")
	for p := range o.ExistingPods {
		if strings.HasPrefix(p, ns+"/") {
			return true // the namespace was listed, and this pod was not in it
		}
	}
	return false
}

// workloadFlows aggregates a capture's flows by workload endpoints. It also
// returns, per observed workload, the most samples any of its pods took.
func workloadFlows(r graph.Result, o Options) (map[key]*flowInfo, map[string]bool, map[string]int) {
	wl := map[string]string{}
	observed := map[string]bool{}
	known := map[string]bool{}
	total := map[string]int{}
	for _, p := range r.Pods {
		known[p.ID()] = true
		wl[p.ID()] = p.WorkloadID()
		if p.Probe.Status == graph.ProbeObserved {
			observed[p.WorkloadID()] = true
			if p.Probe.Samples > total[p.WorkloadID()] {
				total[p.WorkloadID()] = p.Probe.Samples
			}
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
			fi = &flowInfo{observers: map[string]bool{}, samplesBy: map[string]int{}}
			out[k] = fi
		}
		if f.Attempted {
			fi.attempted = true
		} else {
			fi.established = true
		}
		fi.newConns += f.New
		fi.newFailed += f.NewFailed
		fi.conns += f.Conns
		if f.Samples > fi.samples {
			fi.samples = f.Samples
		}
		if !f.Attempted && (o.startedAfterChange(f.From, known) || o.startedAfterChange(f.To, known)) {
			fi.newConns++ // an endpoint pod started under the change, and this edge connected
		}
		fi.observers[name(f.ObservedOn)] = true
		if f.Samples > fi.samplesBy[name(f.ObservedOn)] {
			fi.samplesBy[name(f.ObservedOn)] = f.Samples
		}
	}
	return out, observed, total
}

// missChance is the probability that a flow seen before goes unseen in every
// sample after by chance alone, judged by the observer with the strongest
// evidence; -1 when sample totals are unknown (older captures).
func missChance(b *flowInfo, before, after map[string]int, aObserved map[string]bool) (chance float64, seen, of, afterN int) {
	chance = -1
	for o, s := range b.samplesBy {
		tb, ta := before[o], after[o]
		if tb == 0 || ta == 0 || !aObserved[o] {
			continue
		}
		p := math.Min(1, float64(s)/float64(tb))
		if m := math.Pow(1-p, float64(ta)); chance < 0 || m < chance {
			chance, seen, of, afterN = m, s, tb, ta
		}
	}
	return
}

// Compare reports what changed from before to after.
func Compare(before, after graph.Result) Result { return CompareWith(before, after, Options{}) }

// CompareWith is Compare with options.
func CompareWith(before, after graph.Result, o Options) Result {
	bf, _, bTotal := workloadFlows(before, Options{})
	af, aObserved, aTotal := workloadFlows(after, o)
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
		case a.newConns == 0 && a.newFailed > 0:
			res.Changes = append(res.Changes, Change{Blocked, k.from, k.to, k.proto, k.port,
				"every connection opened under the policy failed (SYN_SENT/CLOSE); only connections opened before it still work"})
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
			res.Unverifiable = append(res.Unverifiable, fmt.Sprintf("%s -> %s %s/%d", graph.Printable(k.from), graph.Printable(k.to), k.proto, k.port))
			continue
		}
		chance, seen, of, afterN := missChance(b, bTotal, aTotal, aObserved)
		if chance >= MissChance {
			res.Changes = append(res.Changes, Change{Glimpsed, k.from, k.to, k.proto, k.port, fmt.Sprintf(
				"absent after, but before it was seen in only %d of %d samples: missing it in all %d samples after happens by chance %.0f%% of the time; sampling noise, not evidence of a block",
				seen, of, afterN, chance*100)})
			continue
		}
		if chance < 0 && b.samples < 2 && b.conns < 2 {
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
	if len(r.Changes) == 0 && len(r.Unverifiable) == 0 {
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
		fmt.Fprintln(w, "\nVERDICT: INCONCLUSIVE - some flows were only seen on connections opened before the policy,"+
			" or their observer was not observed after; restart those workloads so they run under it, then capture again")
	default:
		fmt.Fprintln(w, "\nVERDICT: OK - nothing blocked or lost")
	}
}
