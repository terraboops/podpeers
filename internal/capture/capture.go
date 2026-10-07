// Package capture runs a measurement: it adds a short-lived ephemeral debug
// container to every targeted pod, lets each one sample the pod's socket tables
// for the window, reads the samples back from the container logs, and hands
// them to the graph builder.
//
// Footprint: nothing is installed in the cluster. Each sampler exits by itself
// at the end of the window even if podpeers is interrupted. The Kubernetes API
// does not allow ephemeral containers to be removed, so a terminated
// "podpeers-<run>" entry stays in each probed pod's status until that pod is
// next replaced.
package capture

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"

	"github.com/terraboops/podpeers/internal/graph"
	"github.com/terraboops/podpeers/internal/procnet"
)

// Options configure a capture.
type Options struct {
	Namespace     string // "" with AllNamespaces=false means "default"
	AllNamespaces bool
	LabelSelector string
	Duration      time.Duration // measurement window per pod
	Interval      time.Duration // time between samples
	StartTimeout  time.Duration // how long a debug container may take to start
	Image         string        // debug image; needs sh, cat, date, sleep
	RunID         string        // unique suffix for the container name; generated if empty
	PollInterval  time.Duration
	Concurrency   int
	Logf          func(format string, args ...any)
}

func (o *Options) defaults() {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Second
	}
	if o.StartTimeout <= 0 {
		o.StartTimeout = 60 * time.Second
	}
	if o.Image == "" {
		o.Image = "busybox:1.36"
	}
	if o.RunID == "" {
		o.RunID = NewRunID(time.Now())
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 10
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	// Injection runs concurrently; serialize logging so callers' loggers
	// need not be goroutine-safe.
	logf, mu := o.Logf, &sync.Mutex{}
	o.Logf = func(f string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		logf(f, a...)
	}
	if !o.AllNamespaces && o.Namespace == "" {
		o.Namespace = "default"
	}
}

func (o Options) listNamespace() string {
	if o.AllNamespaces {
		return metav1.NamespaceAll
	}
	return o.Namespace
}

// Validate rejects option combinations that cannot produce a useful capture.
func (o Options) Validate() error {
	if o.Duration <= 0 {
		return errors.New("duration must be positive")
	}
	if o.Interval > o.Duration {
		return fmt.Errorf("interval %s is longer than the %s window", o.Interval, o.Duration)
	}
	if o.LabelSelector == "" {
		return errors.New("a label selector is required: podpeers will not probe every pod by accident (use a selector such as 'app' or 'app in (a,b)')")
	}
	return nil
}

// NewRunID returns a short unique ID for this run's container names.
func NewRunID(now time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(fmt.Sprintf("%s%s", strconvBase36(now.Unix()), hex.EncodeToString(b[:])))
}

func strconvBase36(n int64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{digits[n%36]}, out...)
		n /= 36
	}
	return string(out)
}

// ContainerName is the ephemeral container name used for a run.
func ContainerName(runID string) string { return "podpeers-" + runID }

// DebugContainer builds the ephemeral container spec. It runs as an
// unprivileged user with every capability dropped, so it is admitted under the
// "restricted" Pod Security Standard; reading /proc/net needs no privilege.
func DebugContainer(name, image string, duration, interval time.Duration) corev1.EphemeralContainer {
	no, yes := false, true
	nobody := int64(65534)
	return corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
		Name:                     name,
		Image:                    image,
		ImagePullPolicy:          corev1.PullIfNotPresent,
		Command:                  []string{"sh", "-c", procnet.SamplerScript(duration, interval)},
		TerminationMessagePolicy: corev1.TerminationMessageReadFile,
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot:             &yes,
			RunAsUser:                &nobody,
			AllowPrivilegeEscalation: &no,
			ReadOnlyRootFilesystem:   &yes,
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}}
}

// SkipReason says why a targeted pod should not be probed, or "" to probe it.
func SkipReason(p *corev1.Pod) string {
	switch {
	case p.DeletionTimestamp != nil:
		return "pod is terminating"
	case p.Spec.HostNetwork:
		return "hostNetwork pod: its sockets are the node's, not the pod's"
	case p.Status.Phase != corev1.PodRunning:
		return fmt.Sprintf("pod phase is %s, not Running", p.Status.Phase)
	}
	return ""
}

// ContainerProgress classifies an ephemeral container's state while waiting.
type ContainerProgress int

const (
	Waiting  ContainerProgress = iota // not started yet, still within the start timeout
	Running                           // sampling
	Finished                          // terminated; logs can be read
	Failed                            // will not produce samples
)

// Progress inspects the ephemeral container status of pod p. A container that
// has not started by injectedAt+startTimeout has failed; a container that is
// still running at hardDeadline is treated as finished so its partial log is
// read rather than waited on forever.
func Progress(p *corev1.Pod, name string, injectedAt, now time.Time, startTimeout time.Duration, hardDeadline time.Time) (ContainerProgress, string) {
	var st *corev1.ContainerStatus
	for i := range p.Status.EphemeralContainerStatuses {
		if p.Status.EphemeralContainerStatuses[i].Name == name {
			st = &p.Status.EphemeralContainerStatuses[i]
		}
	}
	if p.DeletionTimestamp != nil {
		return Failed, "pod was deleted during the window"
	}
	switch {
	case st != nil && st.State.Terminated != nil:
		t := st.State.Terminated
		if t.ExitCode != 0 {
			return Finished, fmt.Sprintf("sampler exited %d (%s)", t.ExitCode, t.Reason)
		}
		return Finished, ""
	case st != nil && st.State.Running != nil:
		if now.After(hardDeadline) {
			return Finished, "sampler still running at deadline; reading partial log"
		}
		return Running, ""
	}
	reason := "debug container not created"
	if st != nil && st.State.Waiting != nil {
		reason = st.State.Waiting.Reason
		if m := st.State.Waiting.Message; m != "" {
			reason += ": " + m
		}
	}
	if now.Sub(injectedAt) > startTimeout {
		return Failed, fmt.Sprintf("debug container did not start within %s (%s)", startTimeout, reason)
	}
	return Waiting, reason
}

// target tracks one pod through the capture.
type target struct {
	pod        *corev1.Pod
	probe      graph.Probe
	injectedAt time.Time
	done       bool
	note       string
}

func (t *target) id() string { return t.pod.Namespace + "/" + t.pod.Name }

// Run performs a capture. nodes is the node inventory already fetched for the
// safety check.
func Run(ctx context.Context, cs kubernetes.Interface, nodes []corev1.Node, opts Options) (graph.Result, error) {
	opts.defaults()
	if err := opts.Validate(); err != nil {
		return graph.Result{}, err
	}
	start := time.Now().UTC()
	list, err := cs.CoreV1().Pods(opts.listNamespace()).List(ctx, metav1.ListOptions{LabelSelector: opts.LabelSelector})
	if err != nil {
		return graph.Result{}, fmt.Errorf("listing target pods: %w", err)
	}
	if len(list.Items) == 0 {
		return graph.Result{}, fmt.Errorf("selector %q matched no pods in %s", opts.LabelSelector, nsLabel(opts))
	}
	opts.Logf("selector %q matched %d pod(s) in %s", opts.LabelSelector, len(list.Items), nsLabel(opts))

	var targets []*target
	for i := range list.Items {
		p := &list.Items[i]
		t := &target{pod: p}
		if r := SkipReason(p); r != "" {
			t.probe = graph.Probe{Status: graph.ProbeSkipped, Reason: r}
			t.done = true
			opts.Logf("  skip %s: %s", t.id(), r)
		}
		targets = append(targets, t)
	}

	// Inventory at the start too: pods that are replaced during the window
	// (rollouts, restarts) would otherwise resolve as bare IPs.
	startInv := inventory(ctx, cs, list.Items, nodes, opts)

	name := ContainerName(opts.RunID)
	inject(ctx, cs, targets, name, opts)
	hardDeadline := time.Now().Add(opts.StartTimeout + opts.Duration + 30*time.Second)
	if err := wait(ctx, cs, targets, name, opts, hardDeadline); err != nil {
		return graph.Result{}, err
	}
	obs := collect(ctx, cs, targets, name, opts)
	end := time.Now().UTC()

	inv := mergeInventory(startInv, inventory(ctx, cs, list.Items, nodes, opts))
	var tpods []graph.Pod
	for _, t := range targets {
		gp := toGraphPod(t.pod)
		gp.Probe = t.probe
		tpods = append(tpods, gp)
	}
	return graph.Build(
		graph.Selector{Namespace: opts.listNamespace(), LabelSelector: opts.LabelSelector},
		graph.Window{Start: start, End: end, Interval: opts.Interval.String()},
		inv, tpods, obs)
}

func nsLabel(o Options) string {
	if o.AllNamespaces {
		return "all namespaces"
	}
	return "namespace " + o.Namespace
}

func inject(ctx context.Context, cs kubernetes.Interface, targets []*target, name string, opts Options) {
	spec := DebugContainer(name, opts.Image, opts.Duration, opts.Interval)
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	for _, t := range targets {
		if t.done {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t *target) {
			defer wg.Done()
			defer func() { <-sem }()
			err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				cur, err := cs.CoreV1().Pods(t.pod.Namespace).Get(ctx, t.pod.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				cur.Spec.EphemeralContainers = append(cur.Spec.EphemeralContainers, spec)
				_, err = cs.CoreV1().Pods(t.pod.Namespace).UpdateEphemeralContainers(ctx, t.pod.Name, cur, metav1.UpdateOptions{})
				return err
			})
			t.injectedAt = time.Now()
			if err != nil {
				t.done = true
				t.probe = graph.Probe{Status: graph.ProbeFailed, Reason: "adding debug container: " + describeErr(err)}
				opts.Logf("  fail %s: %s", t.id(), t.probe.Reason)
				return
			}
			opts.Logf("  probe %s: added %s", t.id(), name)
		}(t)
	}
	wg.Wait()
}

// describeErr shortens API errors to something an operator can act on.
func describeErr(err error) string {
	switch {
	case apierrors.IsForbidden(err) && strings.Contains(err.Error(), "violates PodSecurity"):
		// Same HTTP 403 as an RBAC denial, but an admission policy: pointing
		// the operator at RBAC would send them the wrong way.
		return "rejected by Pod Security admission (the namespace's policy, not your RBAC): " + err.Error()
	case apierrors.IsForbidden(err):
		return "forbidden: your credentials may not add ephemeral containers here (needs update on pods/ephemeralcontainers): " + err.Error()
	case apierrors.IsNotFound(err):
		return "pod disappeared: " + err.Error()
	}
	return err.Error()
}

func wait(ctx context.Context, cs kubernetes.Interface, targets []*target, name string, opts Options, hardDeadline time.Time) error {
	tick := time.NewTicker(opts.PollInterval)
	defer tick.Stop()
	lastLog := time.Time{}
	for {
		pending := 0
		for _, t := range targets {
			if !t.done {
				pending++
			}
		}
		if pending == 0 {
			return nil
		}
		if time.Since(lastLog) > 10*time.Second {
			opts.Logf("waiting for %d sampler(s) (window %s)...", pending, opts.Duration)
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		list, err := cs.CoreV1().Pods(opts.listNamespace()).List(ctx, metav1.ListOptions{LabelSelector: opts.LabelSelector})
		if err != nil {
			return fmt.Errorf("polling pods: %w", err)
		}
		current := map[string]*corev1.Pod{}
		for i := range list.Items {
			current[list.Items[i].Namespace+"/"+list.Items[i].Name] = &list.Items[i]
		}
		now := time.Now()
		for _, t := range targets {
			if t.done {
				continue
			}
			p, ok := current[t.id()]
			if !ok {
				t.done = true
				t.probe = graph.Probe{Status: graph.ProbeFailed, Reason: "pod disappeared during the window"}
				continue
			}
			t.pod = p
			switch prog, note := Progress(p, name, t.injectedAt, now, opts.StartTimeout, hardDeadline); prog {
			case Finished:
				t.done, t.note = true, note
			case Failed:
				t.done = true
				t.probe = graph.Probe{Status: graph.ProbeFailed, Reason: note}
				opts.Logf("  fail %s: %s", t.id(), note)
			}
		}
	}
}

func collect(ctx context.Context, cs kubernetes.Interface, targets []*target, name string, opts Options) []graph.Observation {
	var obs []graph.Observation
	for _, t := range targets {
		if t.probe.Status != "" { // skipped or failed already
			continue
		}
		raw, err := cs.CoreV1().Pods(t.pod.Namespace).GetLogs(t.pod.Name, &corev1.PodLogOptions{Container: name}).DoRaw(ctx)
		if err != nil {
			t.probe = graph.Probe{Status: graph.ProbeFailed, Reason: "reading sampler log: " + describeErr(err)}
			opts.Logf("  fail %s: %s", t.id(), t.probe.Reason)
			continue
		}
		out, err := procnet.ParseSamplerOutput(bytes.NewReader(raw))
		if err == nil && len(out.Samples) == 0 {
			err = errors.New("sampler produced no samples")
		}
		if err != nil {
			reason := "parsing sampler log: " + err.Error()
			if t.note != "" {
				reason += " (" + t.note + ")"
			}
			t.probe = graph.Probe{Status: graph.ProbeFailed, Reason: reason}
			opts.Logf("  fail %s: %s", t.id(), reason)
			continue
		}
		t.probe = graph.Probe{Status: graph.ProbeObserved, Samples: len(out.Samples), Complete: out.Complete, Reason: t.note}
		opts.Logf("  done %s: %d sample(s)", t.id(), len(out.Samples))
		obs = append(obs, graph.Observation{Pod: t.id(), Samples: out.Samples})
	}
	return obs
}

// inventory fetches what remote IPs may resolve to. Cluster-wide reads are
// preferred; when the credentials only reach the target namespace, the
// namespaced view is used and peers elsewhere resolve as external addresses.
func inventory(ctx context.Context, cs kubernetes.Interface, targets []corev1.Pod, nodes []corev1.Node, opts Options) graph.Inventory {
	var inv graph.Inventory
	pods, err := cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil && !opts.AllNamespaces {
		opts.Logf("note: cannot list pods cluster-wide (%v); peers outside %s will show as addresses", shortErr(err), opts.Namespace)
		pods, err = cs.CoreV1().Pods(opts.Namespace).List(ctx, metav1.ListOptions{})
	}
	if err == nil {
		for i := range pods.Items {
			inv.Pods = append(inv.Pods, toGraphPod(&pods.Items[i]))
		}
	} else {
		for i := range targets {
			inv.Pods = append(inv.Pods, toGraphPod(&targets[i]))
		}
	}
	svcs, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil && !opts.AllNamespaces {
		svcs, err = cs.CoreV1().Services(opts.Namespace).List(ctx, metav1.ListOptions{})
	}
	if err == nil {
		for _, s := range svcs.Items {
			ips := s.Spec.ClusterIPs
			if len(ips) == 0 && s.Spec.ClusterIP != "" {
				ips = []string{s.Spec.ClusterIP}
			}
			var keep []string
			for _, ip := range ips {
				if ip != corev1.ClusterIPNone {
					keep = append(keep, ip)
				}
			}
			var ports []graph.ServicePort
			for _, sp := range s.Spec.Ports {
				tp := sp.TargetPort.String()
				if sp.TargetPort.IntValue() == 0 && sp.TargetPort.StrVal == "" {
					tp = fmt.Sprint(sp.Port) // unset targetPort defaults to port
				}
				ports = append(ports, graph.ServicePort{Protocol: strings.ToLower(string(sp.Protocol)), Port: uint16(sp.Port), TargetPort: tp})
			}
			inv.Services = append(inv.Services, graph.Service{Namespace: s.Namespace, Name: s.Name, ClusterIPs: keep, Selector: s.Spec.Selector, Ports: ports})
		}
	} else {
		opts.Logf("note: cannot list services (%v); service IPs will show as addresses", shortErr(err))
	}
	for _, n := range nodes {
		gn := graph.Node{Name: n.Name}
		for _, a := range n.Status.Addresses {
			if a.Type == corev1.NodeInternalIP || a.Type == corev1.NodeExternalIP {
				gn.IPs = append(gn.IPs, a.Address)
			}
		}
		inv.Nodes = append(inv.Nodes, gn)
	}
	return inv
}

func shortErr(err error) string {
	if apierrors.IsForbidden(err) {
		return "forbidden"
	}
	return err.Error()
}

func toGraphPod(p *corev1.Pod) graph.Pod {
	gp := graph.Pod{Namespace: p.Namespace, Name: p.Name, IP: p.Status.PodIP, Node: p.Spec.NodeName,
		HostNetwork: p.Spec.HostNetwork, Workload: Workload(p)}
	if p.Status.StartTime != nil {
		gp.StartTime = p.Status.StartTime.UTC()
	}
	for k, v := range p.Labels {
		// Controller bookkeeping labels add noise without helping policy.
		if k == "pod-template-hash" || k == "controller-revision-hash" || k == "pod-template-generation" {
			continue
		}
		if gp.Labels == nil {
			gp.Labels = map[string]string{}
		}
		gp.Labels[k] = v
	}
	return gp
}

// Workload names the controller that owns a pod: "Deployment/x" for a pod of a
// ReplicaSet created by a Deployment (recognised by the pod-template-hash
// suffix), "<Kind>/<name>" for any other controller, "Pod/<name>" otherwise.
func Workload(p *corev1.Pod) string {
	for _, o := range p.OwnerReferences {
		if o.Controller == nil || !*o.Controller {
			continue
		}
		if o.Kind == "ReplicaSet" {
			if h := p.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
				return "Deployment/" + strings.TrimSuffix(o.Name, "-"+h)
			}
		}
		return o.Kind + "/" + o.Name
	}
	return "Pod/" + p.Name
}

// mergeInventory combines the inventories taken at the start and the end of
// the window. Pods and services present at either time are kept; where both
// have the same object, or an IP was reused, the end of the window wins.
func mergeInventory(start, end graph.Inventory) graph.Inventory {
	out := graph.Inventory{Nodes: end.Nodes}
	endPods, endIPs := map[string]bool{}, map[string]bool{}
	for _, p := range end.Pods {
		endPods[p.ID()] = true
		if p.IP != "" {
			endIPs[p.IP] = true
		}
	}
	for _, p := range start.Pods {
		if !endPods[p.ID()] && (p.IP == "" || !endIPs[p.IP]) {
			out.Pods = append(out.Pods, p)
		}
	}
	out.Pods = append(out.Pods, end.Pods...)
	endSvc := map[string]bool{}
	for _, s := range end.Services {
		endSvc[s.ID()] = true
	}
	for _, s := range start.Services {
		if !endSvc[s.ID()] {
			out.Services = append(out.Services, s)
		}
	}
	out.Services = append(out.Services, end.Services...)
	if len(out.Nodes) == 0 {
		out.Nodes = start.Nodes
	}
	return out
}
