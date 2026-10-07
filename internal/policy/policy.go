// Package policy turns a capture into NetworkPolicy suggestions: for each
// observed workload, a ready-to-apply policy that permits exactly the traffic
// that was observed, the reasoning behind every rule, and an explicit list of
// what the measurement did not cover.
//
// It is deliberately conservative. A quiet window is not evidence that a
// workload never talks to anything, so where the observation is too thin the
// suggestion is refused with a reason instead of guessed.
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/yaml"

	"github.com/terraboops/podpeers/internal/graph"
)

// DNS handling modes.
const (
	DNSAuto   = "auto"   // add DNS egress for workloads with any outbound traffic
	DNSAlways = "always" // add DNS egress to every policy
	DNSNever  = "never"  // never add DNS egress unless it was observed
)

// Options tune the suggestion.
type Options struct {
	Namespace  string // only workloads in this namespace ("" = all)
	Workload   string // only this workload, "Kind/name" ("" = all)
	DNS        string
	MinSamples int           // refuse below this many samples per pod
	MinWindow  time.Duration // warn (loudly) below this window
	AllowEmpty bool          // emit a deny-all policy for a workload with no observed traffic
}

func (o *Options) defaults() {
	if o.DNS == "" {
		o.DNS = DNSAuto
	}
	if o.MinSamples <= 0 {
		o.MinSamples = 3
	}
	if o.MinWindow <= 0 {
		o.MinWindow = 24 * time.Hour
	}
}

// Reason explains one rule of a suggested policy.
type Reason struct {
	Rule      string   `json:"rule"`      // e.g. "ingress[0]"
	Direction string   `json:"direction"` // ingress or egress
	Peer      string   `json:"peer"`      // what the rule's peer selects, in words
	Ports     []string `json:"ports"`     // "tcp/9000"
	Evidence  []string `json:"evidence"`  // the observed edges this rule covers
	Assumed   bool     `json:"assumed,omitempty"`
}

// Suggestion is the outcome for one workload.
type Suggestion struct {
	Namespace string               `json:"namespace"`
	Workload  string               `json:"workload"`
	Pods      []string             `json:"pods"`
	Selector  map[string]string    `json:"selector,omitempty"`
	Policy    *netv1.NetworkPolicy `json:"policy,omitempty"`
	Reasons   []Reason             `json:"reasons,omitempty"`
	Gaps      []string             `json:"gaps"`
	// Refused is set, and Policy is nil, when the observation was too thin
	// to suggest a policy safely.
	Refused string `json:"refused,omitempty"`
}

// Report is every suggestion for a capture.
type Report struct {
	Window      graph.Window `json:"window"`
	Suggestions []Suggestion `json:"suggestions"`
	Gaps        []string     `json:"gaps"` // apply to the whole capture
}

// volatileLabels differ between pods of one workload or between runs of a
// CronJob, so they must never appear in a selector.
var volatileLabels = map[string]bool{
	"pod-template-hash": true, "controller-revision-hash": true, "pod-template-generation": true,
	"statefulset.kubernetes.io/pod-name": true, "apps.kubernetes.io/pod-index": true,
	"controller-uid": true, "batch.kubernetes.io/controller-uid": true,
	"job-name": true, "batch.kubernetes.io/job-name": true, "batch.kubernetes.io/job-completion-index": true,
}

// commonLabels is the set of stable labels every pod shares, with equal values.
func commonLabels(pods []graph.Pod) map[string]string {
	if len(pods) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range pods[0].Labels {
		if !volatileLabels[k] {
			out[k] = v
		}
	}
	for _, p := range pods[1:] {
		for k, v := range out {
			if p.Labels[k] != v {
				delete(out, k)
			}
		}
	}
	return out
}

func selectorString(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, ",")
}

type port struct {
	proto  string
	target string // number or named port
}

func (p port) String() string { return p.proto + "/" + p.target }

// ruleAcc accumulates one rule: one peer, any number of ports.
type ruleAcc struct {
	peer     netv1.NetworkPolicyPeer
	desc     string
	ports    map[port]bool
	evidence []string
	assumed  bool
}

type builder struct {
	res       graph.Result
	byWL      map[string][]graph.Pod // workload id -> pods (targets and peers)
	pods      map[string]graph.Pod
	services  map[string]graph.Service
	kubeDNSNS string
}

func newBuilder(r graph.Result) *builder {
	b := &builder{res: r, byWL: map[string][]graph.Pod{}, pods: map[string]graph.Pod{}, services: map[string]graph.Service{}, kubeDNSNS: "kube-system"}
	for _, p := range r.Pods {
		b.pods[p.ID()] = p
		b.byWL[p.WorkloadID()] = append(b.byWL[p.WorkloadID()], p)
	}
	for _, s := range r.Services {
		b.services[s.Namespace+"/"+s.Name] = s
	}
	return b
}

func nsSelector(ns string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": ns}}
}

func ipBlock(ip string) (*netv1.IPBlock, string) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, ""
	}
	bits := 32
	if a.Is6() {
		bits = 128
	}
	cidr := fmt.Sprintf("%s/%d", a, bits)
	return &netv1.IPBlock{CIDR: cidr}, cidr
}

// podPeer builds a peer selecting the workload a peer pod belongs to.
func (b *builder) podPeer(peerID, policyNS string) (netv1.NetworkPolicyPeer, string, string) {
	pp, ok := b.pods[peerID]
	if !ok {
		return netv1.NetworkPolicyPeer{}, "", fmt.Sprintf("peer pod %s is not in the capture's inventory; no rule written for it", peerID)
	}
	labels := commonLabels(b.byWL[pp.WorkloadID()])
	if len(labels) == 0 {
		return netv1.NetworkPolicyPeer{}, "", fmt.Sprintf("peer pod %s has no stable labels to select it by; its traffic is NOT allowed (label it, then re-run)", peerID)
	}
	peer := netv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}
	desc := fmt.Sprintf("pods %s (%s)", selectorString(labels), pp.WorkloadID())
	if pp.Namespace != policyNS {
		peer.NamespaceSelector = nsSelector(pp.Namespace)
		desc = fmt.Sprintf("pods %s in namespace %s (%s)", selectorString(labels), pp.Namespace, pp.WorkloadID())
	}
	return peer, desc, ""
}

// Suggest builds suggestions for every observed workload in scope.
func Suggest(r graph.Result, o Options) Report {
	o.defaults()
	b := newBuilder(r)
	rep := Report{Window: r.Window}

	// Workloads in scope: those with at least one targeted pod.
	groups := map[string][]graph.Pod{}
	var order []string
	for _, p := range r.Pods {
		if p.Probe.Status == graph.ProbeNotTargeted {
			continue
		}
		if o.Namespace != "" && p.Namespace != o.Namespace {
			continue
		}
		wl := p.Workload
		if wl == "" {
			wl = "Pod/" + p.Name
		}
		if o.Workload != "" && wl != o.Workload {
			continue
		}
		id := p.WorkloadID()
		if _, ok := groups[id]; !ok {
			order = append(order, id)
		}
		groups[id] = append(groups[id], p)
	}
	sort.Strings(order)
	for _, id := range order {
		rep.Suggestions = append(rep.Suggestions, b.suggest(groups[id], o))
	}

	dur := r.Window.End.Sub(r.Window.Start).Round(time.Second)
	rep.Gaps = append(rep.Gaps,
		fmt.Sprintf("Observation window: %s (%s .. %s), one sample every %s. Anything that did not happen inside it is absent from every suggestion.",
			dur, r.Window.Start.UTC().Format(time.RFC3339), r.Window.End.UTC().Format(time.RFC3339), r.Window.Interval),
		"Pods that were not captured get no policy and stay unrestricted; nothing here is a namespace-wide default-deny.",
		"How strictly policies are enforced (and whether kubelet health probes from the node are subject to them) depends on your CNI; test before relying on it.")
	if dur < o.MinWindow {
		rep.Gaps = append(rep.Gaps, fmt.Sprintf(
			"The window (%s) is shorter than %s: nightly, weekly and failover-only traffic was almost certainly not seen. Capture for longer, or across the busiest and the rarest operations, before enforcing.",
			dur, o.MinWindow))
	}
	if len(rep.Suggestions) == 0 {
		rep.Gaps = append(rep.Gaps, "No targeted workload is in scope, so there is nothing to suggest.")
	}
	return rep
}

func (b *builder) suggest(pods []graph.Pod, o Options) Suggestion {
	first := pods[0]
	s := Suggestion{Namespace: first.Namespace, Workload: strings.TrimPrefix(first.WorkloadID(), first.Namespace+"/"), Gaps: []string{}}
	ids := map[string]bool{}
	var observed []graph.Pod
	for _, p := range pods {
		s.Pods = append(s.Pods, p.Name)
		ids[p.ID()] = true
		if p.Probe.Status == graph.ProbeObserved {
			observed = append(observed, p)
		} else {
			reason := p.Probe.Reason
			if reason == "" {
				reason = string(p.Probe.Status)
			}
			s.Gaps = append(s.Gaps, fmt.Sprintf("Pod %s was not observed (%s); the policy will still apply to it.", p.Name, reason))
		}
	}
	sort.Strings(s.Pods)

	switch {
	case first.HostNetwork:
		s.Refused = "hostNetwork pods use the node's network namespace and are not subject to NetworkPolicy."
		return s
	case len(observed) == 0:
		s.Refused = "no pod of this workload was observed, so there is no evidence to base a policy on."
		return s
	}
	for _, p := range observed {
		if p.Probe.Samples < o.MinSamples {
			s.Refused = fmt.Sprintf("pod %s has only %d sample(s) (minimum %d); too thin to suggest a policy safely.", p.Name, p.Probe.Samples, o.MinSamples)
			return s
		}
		if !p.Probe.Complete {
			s.Gaps = append(s.Gaps, fmt.Sprintf("Pod %s's sampler did not run its whole window; its observation is partial.", p.Name))
		}
	}
	s.Selector = commonLabels(pods)
	if len(s.Selector) == 0 {
		s.Refused = "the workload's pods share no stable labels, so the only possible podSelector is {}, which would select every pod in the namespace."
		return s
	}

	var edges []graph.Edge
	for _, e := range b.res.Edges {
		if ids[e.Pod] {
			edges = append(edges, e)
		}
	}
	listeners := map[port]bool{}
	for _, p := range observed {
		for _, l := range p.Listening {
			listeners[port{l.Protocol, fmt.Sprint(l.Port)}] = true
		}
	}

	ingress, egress := map[string]*ruleAcc{}, map[string]*ruleAcc{}
	var ingressOrder, egressOrder []string
	add := func(m map[string]*ruleAcc, order *[]string, key string, peer netv1.NetworkPolicyPeer, desc string, p port, ev string, assumed bool) {
		r := m[key]
		if r == nil {
			r = &ruleAcc{peer: peer, desc: desc, ports: map[port]bool{}, assumed: assumed}
			m[key] = r
			*order = append(*order, key)
		}
		r.ports[p] = true
		if ev != "" {
			r.evidence = append(r.evidence, ev)
		}
	}
	gap := func(g string) {
		for _, x := range s.Gaps {
			if x == g {
				return
			}
		}
		s.Gaps = append(s.Gaps, g)
	}
	usedListeners := map[port]bool{}
	egressCount := 0

	for _, e := range edges {
		_, podName, _ := strings.Cut(e.Pod, "/")
		state := "open at window end"
		if !e.Open {
			state = "closed during the window"
		}
		ev := fmt.Sprintf("%s %s %s %s/%d: %d connection(s), seen in %d sample(s), %s",
			podName, map[graph.Direction]string{graph.Inbound: "<-", graph.Outbound: "->"}[e.Direction],
			e.Peer.ID(), e.Protocol, e.Port, e.Connections, e.Samples, state)
		if e.Attempted {
			gap(fmt.Sprintf("%s: %s %s/%d was only ever seen half-open (SYN_SENT): it was attempted and never connected. Not allowed; investigate whether something already blocks it.",
				podName, e.Peer.ID(), e.Protocol, e.Port))
			continue
		}
		p := port{e.Protocol, fmt.Sprint(e.Port)}
		if e.Direction == graph.Inbound {
			usedListeners[p] = true
			switch e.Peer.Kind {
			case graph.PeerPod:
				peer, desc, g := b.podPeer(e.Peer.ID(), s.Namespace)
				if g != "" {
					gap(g)
					continue
				}
				add(ingress, &ingressOrder, "pod:"+desc, peer, desc, p, ev, false)
			default:
				blk, cidr := ipBlock(e.Peer.IP)
				if blk == nil {
					gap(fmt.Sprintf("cannot express peer %q as an address; not allowed", e.Peer.IP))
					continue
				}
				desc := fmt.Sprintf("%s %s", e.Peer.Kind, cidr)
				if e.Peer.Kind == graph.PeerNode {
					desc = fmt.Sprintf("node %s (%s)", e.Peer.Name, cidr)
					gap(fmt.Sprintf("Ingress from node %s is allowed by its IP (%s); node IPs change when nodes are replaced.", e.Peer.Name, cidr))
				} else {
					gap(fmt.Sprintf("Ingress from %s did not resolve to any pod, service or node; it is allowed as the single address %s. If it was a pod that has since been replaced, this rule is wrong.", e.Peer.IP, cidr))
				}
				add(ingress, &ingressOrder, "ip:"+cidr, netv1.NetworkPolicyPeer{IPBlock: blk}, desc, p, ev, false)
			}
			continue
		}
		egressCount++
		switch e.Peer.Kind {
		case graph.PeerPod:
			peer, desc, g := b.podPeer(e.Peer.ID(), s.Namespace)
			if g != "" {
				gap(g)
				continue
			}
			add(egress, &egressOrder, "pod:"+desc, peer, desc, p, ev, false)
		case graph.PeerService:
			svc, ok := b.services[e.Peer.Namespace+"/"+e.Peer.Name]
			if !ok {
				gap(fmt.Sprintf("Service %s/%s is not in the capture's inventory; its traffic is NOT allowed.", e.Peer.Namespace, e.Peer.Name))
				continue
			}
			if len(svc.Selector) == 0 {
				gap(fmt.Sprintf("Service %s/%s has no pod selector (manual endpoints, ExternalName, or the API server); NetworkPolicy cannot follow it, so %s/%d to it is NOT allowed. Add an ipBlock for its real endpoints by hand.",
					svc.Namespace, svc.Name, e.Protocol, e.Port))
				continue
			}
			target := ""
			for _, sp := range svc.Ports {
				if sp.Port == e.Port && sp.Protocol == e.Protocol {
					target = sp.TargetPort
				}
			}
			if target == "" {
				gap(fmt.Sprintf("Service %s/%s has no %s/%d port in the inventory; that traffic is NOT allowed.", svc.Namespace, svc.Name, e.Protocol, e.Port))
				continue
			}
			peer := netv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: svc.Selector}}
			desc := fmt.Sprintf("pods behind service %s/%s (%s)", svc.Namespace, svc.Name, selectorString(svc.Selector))
			if svc.Namespace != s.Namespace {
				peer.NamespaceSelector = nsSelector(svc.Namespace)
			}
			ev += fmt.Sprintf(" (service port %d -> target port %s)", e.Port, target)
			add(egress, &egressOrder, "svc:"+desc, peer, desc, port{e.Protocol, target}, ev, false)
		default:
			blk, cidr := ipBlock(e.Peer.IP)
			if blk == nil {
				gap(fmt.Sprintf("cannot express peer %q as an address; not allowed", e.Peer.IP))
				continue
			}
			desc := fmt.Sprintf("%s %s", e.Peer.Kind, cidr)
			if e.Peer.Kind == graph.PeerNode {
				desc = fmt.Sprintf("node %s (%s)", e.Peer.Name, cidr)
			}
			gap(fmt.Sprintf("Egress to %s is allowed as the single address %s. External endpoints behind DNS (CDNs, cloud APIs) change address; expect this rule to go stale.", e.Peer.ID(), cidr))
			add(egress, &egressOrder, "ip:"+cidr, netv1.NetworkPolicyPeer{IPBlock: blk}, desc, p, ev, false)
		}
	}

	// DNS: lookups are short UDP exchanges that sampling rarely catches.
	wantDNS := o.DNS == DNSAlways || (o.DNS == DNSAuto && egressCount > 0)
	if wantDNS {
		// If DNS was observed (via the kube-dns service), widen that rule to
		// both protocols instead of adding a second, overlapping one.
		observed := ""
		for _, k := range egressOrder {
			r := egress[k]
			if r.peer.PodSelector != nil && len(r.peer.PodSelector.MatchLabels) == 1 &&
				r.peer.PodSelector.MatchLabels["k8s-app"] == "kube-dns" &&
				r.peer.NamespaceSelector != nil && r.peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] == b.kubeDNSNS {
				observed = k
			}
		}
		if observed != "" {
			r := egress[observed]
			for _, p := range []port{{"udp", "53"}, {"tcp", "53"}} {
				if !r.ports[p] {
					r.ports[p] = true
					r.evidence = append(r.evidence, fmt.Sprintf("%s ASSUMED, not observed: DNS falls back to TCP for large answers", p))
				}
			}
		} else {
			peer := netv1.NetworkPolicyPeer{NamespaceSelector: nsSelector(b.kubeDNSNS),
				PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}}}
			desc := "cluster DNS (pods k8s-app=kube-dns in kube-system)"
			add(egress, &egressOrder, "dns", peer, desc, port{"udp", "53"}, "", true)
			add(egress, &egressOrder, "dns", peer, desc, port{"tcp", "53"}, "", true)
		}
	} else if egressCount > 0 {
		gap("DNS egress was not added (--dns=never) and DNS lookups are rarely observable; name resolution will fail under this policy unless another policy allows it.")
	}

	np := &netv1.NetworkPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      policyName(s.Workload),
			Namespace: s.Namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "podpeers"},
			Annotations: map[string]string{
				"podpeers.io/observed-window": fmt.Sprintf("%s/%s", b.res.Window.Start.UTC().Format(time.RFC3339), b.res.Window.End.UTC().Format(time.RFC3339)),
				"podpeers.io/workload":        s.Workload,
			},
		},
		Spec: netv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: s.Selector},
			PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeIngress, netv1.PolicyTypeEgress},
			Ingress:     []netv1.NetworkPolicyIngressRule{},
			Egress:      []netv1.NetworkPolicyEgressRule{},
		},
	}
	for i, k := range ingressOrder {
		r := ingress[k]
		np.Spec.Ingress = append(np.Spec.Ingress, netv1.NetworkPolicyIngressRule{From: []netv1.NetworkPolicyPeer{r.peer}, Ports: npPorts(r.ports)})
		s.Reasons = append(s.Reasons, reason(fmt.Sprintf("ingress[%d]", i), "ingress", r))
	}
	for i, k := range egressOrder {
		r := egress[k]
		np.Spec.Egress = append(np.Spec.Egress, netv1.NetworkPolicyEgressRule{To: []netv1.NetworkPolicyPeer{r.peer}, Ports: npPorts(r.ports)})
		s.Reasons = append(s.Reasons, reason(fmt.Sprintf("egress[%d]", i), "egress", r))
	}

	if len(np.Spec.Ingress) == 0 && len(np.Spec.Egress) == 0 && !o.AllowEmpty {
		s.Refused = "no traffic at all was observed for this workload. The resulting policy would deny everything, and a quiet window is not evidence that it never talks to anything. Capture for longer (or pass --allow-empty to emit deny-all deliberately)."
		return s
	}

	// What the workload would lose.
	var unmatched []string
	for l := range listeners {
		if !usedListeners[l] {
			unmatched = append(unmatched, l.String())
		}
	}
	sort.Strings(unmatched)
	if len(unmatched) > 0 {
		gap(fmt.Sprintf("Listens on %s but no client was observed there: ingress to those ports will be DROPPED for everyone (health checks from other pods, metrics scrapers, rare callers).",
			strings.Join(unmatched, ", ")))
	}
	if len(np.Spec.Ingress) == 0 {
		gap("No inbound traffic was observed: this policy denies ALL ingress to the workload.")
	}
	lose := []string{"any service or pod not listed under egress (dependencies that were idle during the window)"}
	if !hasKind(edges, graph.PeerExternal) {
		lose = append(lose, "every address outside the cluster (none was contacted during the window)")
	}
	if !talksToAPIServer(edges) {
		lose = append(lose, "the Kubernetes API server (if this workload uses its service account; the API is not a selectable pod)")
	}
	if !wantDNS {
		lose = append(lose, "DNS")
	}
	gap("Egress is now limited to the rules above. The workload would LOSE: " + strings.Join(lose, "; ") + ".")
	gap(fmt.Sprintf("podSelector %s also selects any other pod in %s carrying these labels; check with: kubectl get pods -n %s -l %s",
		selectorString(s.Selector), s.Namespace, s.Namespace, selectorString(s.Selector)))
	s.Policy = np
	return s
}

func hasKind(es []graph.Edge, k graph.PeerKind) bool {
	for _, e := range es {
		if e.Peer.Kind == k && e.Direction == graph.Outbound {
			return true
		}
	}
	return false
}

func talksToAPIServer(es []graph.Edge) bool {
	for _, e := range es {
		if e.Direction == graph.Outbound && e.Peer.Kind == graph.PeerService && e.Peer.Namespace == "default" && e.Peer.Name == "kubernetes" {
			return true
		}
	}
	return false
}

func npPorts(ps map[port]bool) []netv1.NetworkPolicyPort {
	keys := make([]port, 0, len(ps))
	for p := range ps {
		keys = append(keys, p)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].proto != keys[j].proto {
			return keys[i].proto > keys[j].proto // tcp before udp
		}
		return keys[i].target < keys[j].target
	})
	var out []netv1.NetworkPolicyPort
	for _, p := range keys {
		proto := corev1.Protocol(strings.ToUpper(p.proto))
		v := intstr.FromString(p.target) // a named container port
		if n, err := strconv.Atoi(p.target); err == nil {
			v = intstr.FromInt32(int32(n))
		}
		out = append(out, netv1.NetworkPolicyPort{Protocol: &proto, Port: &v})
	}
	return out
}

func reason(rule, dir string, r *ruleAcc) Reason {
	var ports []string
	for _, p := range npPorts(r.ports) {
		ports = append(ports, strings.ToLower(string(*p.Protocol))+"/"+p.Port.String())
	}
	ev := r.evidence
	if r.assumed {
		ev = []string{"ASSUMED, not observed: DNS lookups are short UDP exchanges that socket sampling rarely catches, and the observed outbound connections used names"}
	}
	return Reason{Rule: rule, Direction: dir, Peer: r.desc, Ports: ports, Evidence: ev, Assumed: r.assumed}
}

// policyName derives a DNS-1123 name from a workload "Kind/name".
func policyName(workload string) string {
	name := workload
	if i := strings.Index(workload, "/"); i >= 0 {
		name = workload[i+1:]
	}
	n := "podpeers-" + strings.ToLower(name)
	if len(n) > 63 {
		n = strings.TrimRight(n[:63], "-.")
	}
	return n
}

// YAML renders every suggestion as one multi-document stream that can be
// passed straight to kubectl apply -f. Reasoning and gaps are YAML comments;
// refused workloads appear as comments only.
func (rep Report) YAML() (string, error) {
	var b strings.Builder
	b.WriteString("# NetworkPolicy suggestions generated by podpeers from observed traffic.\n")
	b.WriteString("# Review every rule and every NOT COVERED item before applying.\n#\n")
	for _, g := range rep.Gaps {
		writeComment(&b, "", g)
	}
	for _, s := range rep.Suggestions {
		b.WriteString("---\n")
		fmt.Fprintf(&b, "# %s in namespace %s (pods: %s)\n", s.Workload, s.Namespace, strings.Join(s.Pods, ", "))
		if s.Refused != "" {
			writeComment(&b, "NO POLICY SUGGESTED: ", s.Refused)
			for _, g := range s.Gaps {
				writeComment(&b, "  - ", g)
			}
			continue
		}
		fmt.Fprintf(&b, "# selects: %s\n#\n# WHY each rule exists:\n", selectorString(s.Selector))
		for _, r := range s.Reasons {
			fmt.Fprintf(&b, "#   %s allows %s on %s\n", r.Rule, r.Peer, strings.Join(r.Ports, ", "))
			for _, e := range r.Evidence {
				writeComment(&b, "      ", e)
			}
		}
		b.WriteString("#\n# NOT COVERED by this observation:\n")
		for _, g := range s.Gaps {
			writeComment(&b, "  - ", g)
		}
		y, err := yaml.Marshal(s.Policy)
		if err != nil {
			return "", err
		}
		for _, line := range strings.Split(strings.TrimRight(string(y), "\n"), "\n") {
			if strings.TrimSpace(line) == "creationTimestamp: null" {
				continue
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String(), nil
}

// writeComment wraps text at ~100 columns as YAML comments; continuation
// lines are indented under the prefix.
func writeComment(b *strings.Builder, prefix, text string) {
	line, cont := "# "+prefix, "# "+strings.Repeat(" ", len(prefix))
	fresh := true
	for _, w := range strings.Fields(text) {
		if !fresh && len(line)+1+len(w) > 100 {
			b.WriteString(line + "\n")
			line, fresh = cont, true
		}
		if !fresh {
			line += " "
		}
		line, fresh = line+w, false
	}
	b.WriteString(line + "\n")
}

// Ready lists the policies that were suggested (not refused).
func (rep Report) Ready() []*netv1.NetworkPolicy {
	var out []*netv1.NetworkPolicy
	for _, s := range rep.Suggestions {
		if s.Policy != nil {
			out = append(out, s.Policy)
		}
	}
	return out
}
