package capture

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/terraboops/podpeers/internal/graph"
	"github.com/terraboops/podpeers/internal/procnet"
)

func TestValidate(t *testing.T) {
	ok := Options{Duration: 30 * time.Second, Interval: 5 * time.Second, LabelSelector: "app"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid options rejected: %v", err)
	}
	cases := map[string]Options{
		"zero duration":      {Duration: 0, Interval: time.Second, LabelSelector: "app"},
		"interval > window":  {Duration: time.Second, Interval: 5 * time.Second, LabelSelector: "app"},
		"no selector":        {Duration: 30 * time.Second, Interval: time.Second},
		"interval too short": {Duration: 30 * time.Second, Interval: 50 * time.Millisecond, LabelSelector: "app"},
		"zero interval":      {Duration: 30 * time.Second, Interval: 0, LabelSelector: "app"},
		"sub-ms interval":    {Duration: 30 * time.Second, Interval: 100*time.Millisecond + 500*time.Microsecond, LabelSelector: "app"},
		"sub-10ms duration":  {Duration: 30*time.Second + 5*time.Millisecond, Interval: time.Second, LabelSelector: "app"},
	}
	for name, o := range cases {
		if err := o.Validate(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestRunIDAndContainerName(t *testing.T) {
	now := time.Unix(1700000000, 0)
	a, b := NewRunID(now), NewRunID(now)
	if a == b {
		t.Error("run IDs must differ between runs started in the same second")
	}
	if !strings.HasPrefix(a, strconvBase36(now.Unix())) || strings.ToLower(a) != a {
		t.Errorf("run id %q", a)
	}
	if n := ContainerName(a); !strings.HasPrefix(n, "podpeers-") || len(n) > 63 {
		t.Errorf("container name %q", n)
	}
	if strconvBase36(0) != "0" || strconvBase36(35) != "z" || strconvBase36(36) != "10" {
		t.Error("base36 encoding wrong")
	}
}

func TestDebugContainerIsRestrictedAndSelfTerminating(t *testing.T) {
	c := DebugContainer("podpeers-x", "busybox:1.36", 30*time.Second, 5*time.Second)
	sc := c.SecurityContext
	if sc == nil || !*sc.RunAsNonRoot || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" ||
		sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("security context not restricted: %+v", sc)
	}
	if sc.Privileged != nil || len(sc.Capabilities.Add) != 0 {
		t.Fatal("debug container must not request privilege")
	}
	if c.TargetContainerName != "" {
		t.Error("no process-namespace targeting is needed for /proc/net")
	}
	script := strings.Join(c.Command, " ")
	if !strings.Contains(script, "+ 3000 ))") || !strings.Contains(script, "next + 500 ))") || !strings.Contains(script, "break") {
		t.Fatalf("sampler must stop by itself after the window: %s", script)
	}
}

func pod(ns, name string, phase corev1.PodPhase, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Status:     corev1.PodStatus{Phase: phase, PodIP: "192.0.2.10"},
	}
}

func TestSkipReason(t *testing.T) {
	running := pod("a", "b", corev1.PodRunning, nil)
	if r := SkipReason(running); r != "" {
		t.Errorf("running pod skipped: %s", r)
	}
	pending := pod("a", "b", corev1.PodPending, nil)
	if r := SkipReason(pending); !strings.Contains(r, "Pending") {
		t.Errorf("pending: %q", r)
	}
	hostNet := pod("a", "b", corev1.PodRunning, nil)
	hostNet.Spec.HostNetwork = true
	if r := SkipReason(hostNet); !strings.Contains(r, "hostNetwork") {
		t.Errorf("hostNetwork: %q", r)
	}
	deleting := pod("a", "b", corev1.PodRunning, nil)
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if r := SkipReason(deleting); !strings.Contains(r, "terminating") {
		t.Errorf("terminating: %q", r)
	}
}

func withStatus(st corev1.ContainerState) *corev1.Pod {
	p := pod("a", "b", corev1.PodRunning, nil)
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{
		{Name: "other", State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}},
		{Name: "pp", State: st},
	}
	return p
}

func TestProgress(t *testing.T) {
	inj := time.Unix(1000, 0)
	hard := inj.Add(2 * time.Minute)
	early, late, after := inj.Add(5*time.Second), inj.Add(90*time.Second), hard.Add(time.Second)
	to := time.Minute

	cases := []struct {
		name string
		pod  *corev1.Pod
		now  time.Time
		want ContainerProgress
		note string
	}{
		{"not yet reported", pod("a", "b", corev1.PodRunning, nil), early, Waiting, "not created"},
		{"never reported", pod("a", "b", corev1.PodRunning, nil), late, Failed, "did not start within 1m0s"},
		{"pulling", withStatus(corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ContainerCreating"}}), early, Waiting, "ContainerCreating"},
		{"image pull failure", withStatus(corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff", Message: "back-off"}}), late, Failed, "ImagePullBackOff: back-off"},
		{"running", withStatus(corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}), late, Running, ""},
		{"running past deadline", withStatus(corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}), after, Finished, "partial"},
		{"finished", withStatus(corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}), late, Finished, ""},
		{"finished non-zero", withStatus(corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 137, Reason: "Error"}}), late, Finished, "exited 137"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, note := Progress(c.pod, "pp", inj, c.now, to, hard)
			if got != c.want || !strings.Contains(note, c.note) {
				t.Fatalf("Progress = %v %q; want %v %q", got, note, c.want, c.note)
			}
		})
	}
	deleted := withStatus(corev1.ContainerState{Running: &corev1.ContainerStateRunning{}})
	ts := metav1.Now()
	deleted.DeletionTimestamp = &ts
	if got, _ := Progress(deleted, "pp", inj, early, to, hard); got != Failed {
		t.Error("deleted pod should fail")
	}
}

// TestRunOrchestration drives Run against client-go's in-memory fake clientset.
// The fake never starts containers, so this exercises the bookkeeping paths
// (skip, forbidden injection, start timeout, inventory, exit status); the real
// sampling path is covered by the end-to-end suite against a real cluster.
func TestRunOrchestration(t *testing.T) {
	sel := map[string]string{"pp": "target"}
	running := pod("shop", "api", corev1.PodRunning, sel)
	locked := pod("shop", "vault", corev1.PodRunning, sel)
	pending := pod("shop", "queued", corev1.PodPending, sel)
	other := pod("shop", "excluded", corev1.PodRunning, map[string]string{"pp": "no"})
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"},
		Spec: corev1.ServiceSpec{ClusterIP: "192.0.2.200"}}
	cs := fake.NewSimpleClientset(running, locked, pending, other, svc)

	var injected []string
	var mu sync.Mutex // the reactor runs on capture's concurrent inject goroutines
	cs.PrependReactor("update", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "ephemeralcontainers" {
			return false, nil, nil
		}
		p := a.(k8stesting.UpdateAction).GetObject().(*corev1.Pod)
		if p.Name == "vault" {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods/ephemeralcontainers"}, p.Name, errors.New("denied"))
		}
		mu.Lock()
		injected = append(injected, p.Name)
		mu.Unlock()
		if n := len(p.Spec.EphemeralContainers); n != 1 || !strings.HasPrefix(p.Spec.EphemeralContainers[0].Name, "podpeers-") {
			t.Errorf("unexpected ephemeral containers on %s: %+v", p.Name, p.Spec.EphemeralContainers)
		}
		return false, nil, nil // let the tracker store it
	})

	var logs []string
	res, err := Run(context.Background(), cs, nil, Options{
		Namespace: "shop", LabelSelector: "pp=target",
		Duration: 2 * time.Second, Interval: time.Second,
		StartTimeout: 50 * time.Millisecond, PollInterval: 10 * time.Millisecond,
		Logf: func(f string, a ...any) { logs = append(logs, f) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(injected) != 1 || injected[0] != "api" {
		t.Fatalf("injected into %v; want only api (excluded and pending must be untouched)", injected)
	}
	status := map[string]graph.Probe{}
	for _, p := range res.Pods {
		status[p.Name] = p.Probe
	}
	if _, ok := status["excluded"]; ok {
		t.Error("pod outside the selector appeared as a target")
	}
	if s := status["queued"]; s.Status != graph.ProbeSkipped || !strings.Contains(s.Reason, "Pending") {
		t.Errorf("queued = %+v", s)
	}
	if s := status["vault"]; s.Status != graph.ProbeFailed || !strings.Contains(s.Reason, "forbidden") {
		t.Errorf("vault = %+v", s)
	}
	if s := status["api"]; s.Status != graph.ProbeFailed || !strings.Contains(s.Reason, "did not start") {
		t.Errorf("api = %+v", s)
	}
	if res.Selector.Namespace != "shop" || res.Selector.LabelSelector != "pp=target" || res.Schema != graph.Schema {
		t.Errorf("header = %+v", res.Selector)
	}
	if len(res.Edges) != 0 {
		t.Errorf("no samples were taken, yet edges = %+v", res.Edges)
	}
}

func TestRunEmptySelection(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"app": "api"}))
	_, err := Run(context.Background(), cs, nil, Options{Namespace: "shop", LabelSelector: "app=nothing", Duration: time.Second, Interval: time.Second})
	if err == nil || !strings.Contains(err.Error(), "matched no pods") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunListForbidden(t *testing.T) {
	cs := fake.NewSimpleClientset()
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "", errors.New("denied"))
	})
	_, err := Run(context.Background(), cs, nil, Options{Namespace: "sealed", LabelSelector: "app", Duration: time.Second, Interval: time.Second})
	if err == nil || !apierrors.IsForbidden(errors.Unwrap(err)) {
		t.Fatalf("err = %v", err)
	}
}

func TestDescribeErr(t *testing.T) {
	f := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x", errors.New("no"))
	if !strings.Contains(describeErr(f), "pods/ephemeralcontainers") {
		t.Error("forbidden should name the missing permission")
	}
	psa := apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "x",
		errors.New(`violates PodSecurity "restricted:latest": allowPrivilegeEscalation != false`))
	if d := describeErr(psa); !strings.Contains(d, "Pod Security admission") || strings.Contains(d, "your credentials") {
		t.Errorf("an admission rejection must not be blamed on RBAC: %s", d)
	}
	nf := apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "x")
	if !strings.Contains(describeErr(nf), "disappeared") {
		t.Error("not found should say the pod went away")
	}
}

func TestToGraphPodDropsBookkeepingLabels(t *testing.T) {
	p := pod("a", "b", corev1.PodRunning, map[string]string{"app": "x", "pod-template-hash": "abc"})
	gp := toGraphPod(p)
	if len(gp.Labels) != 1 || gp.Labels["app"] != "x" {
		t.Fatalf("labels = %v", gp.Labels)
	}
	if toGraphPod(pod("a", "b", corev1.PodRunning, nil)).Labels != nil {
		t.Error("no labels should stay nil")
	}
}

func TestWorkload(t *testing.T) {
	yes := true
	own := func(kind, name string) []metav1.OwnerReference {
		return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
	}
	cases := []struct {
		labels map[string]string
		owners []metav1.OwnerReference
		want   string
	}{
		{map[string]string{"pod-template-hash": "7d9f8"}, own("ReplicaSet", "web-7d9f8"), "Deployment/web"},
		{nil, own("ReplicaSet", "hand-made"), "ReplicaSet/hand-made"},
		{nil, own("StatefulSet", "db"), "StatefulSet/db"},
		{nil, own("Job", "migrate"), "Job/migrate"},
		{nil, []metav1.OwnerReference{{Kind: "ConfigMap", Name: "x"}}, "Pod/p"}, // not a controller
		{nil, nil, "Pod/p"},
	}
	for _, c := range cases {
		p := pod("a", "p", corev1.PodRunning, c.labels)
		p.OwnerReferences = c.owners
		if got := Workload(p); got != c.want {
			t.Errorf("Workload(%v %v) = %q; want %q", c.labels, c.owners, got, c.want)
		}
	}
}

func TestMergeInventoryKeepsPodsReplacedDuringTheWindow(t *testing.T) {
	start := graph.Inventory{
		Pods: []graph.Pod{
			{Namespace: "shop", Name: "web-old", IP: "192.0.2.5", Workload: "Deployment/web"},
			{Namespace: "shop", Name: "api", IP: "192.0.2.6"},
			{Namespace: "shop", Name: "gone", IP: "192.0.2.9"}, // IP reused below
		},
		Services: []graph.Service{{Namespace: "shop", Name: "old-svc"}},
		Nodes:    []graph.Node{{Name: "n"}},
	}
	end := graph.Inventory{
		Pods: []graph.Pod{
			{Namespace: "shop", Name: "web-new", IP: "192.0.2.7", Workload: "Deployment/web"},
			{Namespace: "shop", Name: "api", IP: "192.0.2.6"},
			{Namespace: "shop", Name: "reuser", IP: "192.0.2.9"},
		},
	}
	m := mergeInventory(start, end)
	r := graph.NewResolver(m)
	if p := r.Resolve(netip.MustParseAddr("192.0.2.5")); p.Name != "web-old" {
		t.Errorf("replaced pod should still resolve: %+v", p)
	}
	if p := r.Resolve(netip.MustParseAddr("192.0.2.9")); p.Name != "reuser" {
		t.Errorf("reused IP should resolve to the current pod: %+v", p)
	}
	if len(m.Pods) != 4 || len(m.Services) != 1 || len(m.Nodes) != 1 {
		t.Errorf("merged = %+v", m)
	}
}

func TestSubSecondIntervalsAreAccepted(t *testing.T) {
	for _, iv := range []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 1500 * time.Millisecond} {
		o := Options{Duration: 30 * time.Second, Interval: iv, LabelSelector: "app"}
		if err := o.Validate(); err != nil {
			t.Errorf("%s rejected: %v", iv, err)
		}
	}
	if c := SamplingCost(100 * time.Millisecond); !strings.HasPrefix(c, "20 process starts per second") || !strings.Contains(c, "about 60 millicores") {
		t.Errorf("cost at 100ms = %q", c)
	}
	if c := SamplingCost(time.Second); !strings.HasPrefix(c, "2 process starts per second") {
		t.Errorf("cost at 1s = %q", c)
	}
}

func TestBestPicksTheMoreCompleteLog(t *testing.T) {
	complete := procnet.SamplerOutput{Complete: true, Samples: make([]procnet.Sample, 3)}
	partialMore := procnet.SamplerOutput{Samples: make([]procnet.Sample, 5)}
	partialLess := procnet.SamplerOutput{Samples: make([]procnet.Sample, 2)}
	bad := errors.New("x")
	if o, err := best(partialMore, nil, complete, nil); err != nil || !o.Complete {
		t.Error("complete beats partial")
	}
	if o, _ := best(partialLess, nil, partialMore, nil); len(o.Samples) != 5 {
		t.Error("more samples beats fewer when neither is complete")
	}
	if o, err := best(procnet.SamplerOutput{}, bad, partialLess, nil); err != nil || len(o.Samples) != 2 {
		t.Error("a working read beats a failed one")
	}
	if _, err := best(procnet.SamplerOutput{}, bad, procnet.SamplerOutput{}, bad); err == nil {
		t.Error("both failed: error")
	}
}
