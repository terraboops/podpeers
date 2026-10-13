package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	fakerest "k8s.io/client-go/rest/fake"
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
		"blank selector":     {Duration: 30 * time.Second, Interval: time.Second, LabelSelector: " \t"}, // parses as "everything"
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
		{map[string]string{"pod-template-hash": "abc12"}, own("ReplicaSet", "web-7d9f8"), "ReplicaSet/web-7d9f8"}, // hash not its suffix
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
	if o, err := best(complete, nil, partialMore, nil); err != nil || !o.Complete {
		t.Error("complete beats partial, either way round")
	}
	if o, _ := best(partialLess, nil, partialMore, nil); len(o.Samples) != 5 {
		t.Error("more samples beats fewer when neither is complete")
	}
	if o, err := best(procnet.SamplerOutput{}, bad, partialLess, nil); err != nil || len(o.Samples) != 2 {
		t.Error("a working read beats a failed one")
	}
	// A failed read loses even when what it got looks better: complete, and
	// longer. The comparison must not reach it.
	looksBetter := procnet.SamplerOutput{Complete: true, Samples: make([]procnet.Sample, 9)}
	if o, err := best(looksBetter, bad, partialLess, nil); err != nil || o.Complete || len(o.Samples) != 2 {
		t.Error("a failed read loses, first or second")
	}
	if o, err := best(partialLess, nil, looksBetter, bad); err != nil || o.Complete || len(o.Samples) != 2 {
		t.Error("a failed read loses, first or second")
	}
	if _, err := best(procnet.SamplerOutput{}, bad, procnet.SamplerOutput{}, bad); err == nil {
		t.Error("both failed: error")
	}
}

func TestCronJobPodsAreNamedAfterTheCronJob(t *testing.T) {
	yes := true
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "report-29315467",
		OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "report", Controller: &yes}}}}
	plain := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "migrate"}}
	no := false
	notController := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "adopted",
		OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "report", Controller: &no}}}}
	unset := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "loose",
		OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "report"}}}}
	otherKind := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "step-1",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Workflow", Name: "pipeline", Controller: &yes}}}}
	cs := fake.NewSimpleClientset(job, plain, notController, unset, otherKind)
	var notes []string
	cron := cronJobOwners(context.Background(), cs, Options{Logf: func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }})
	for in, want := range map[string]string{
		"Job/report-29315467": "CronJob/report", // a CronJob run
		"Job/migrate":         "Job/migrate",    // a Job nobody owns
		"Job/adopted":         "Job/adopted",    // a CronJob ref that is not its controller
		"Job/loose":           "Job/loose",      // a ref that does not say
		"Job/step-1":          "Job/step-1",     // controlled, but not by a CronJob
		"Job/vanished":        "Job/vanished",   // a Job that no longer exists
		"Deployment/web":      "Deployment/web", // untouched
	} {
		if got := cron("shop", in); got != want {
			t.Errorf("%s -> %s; want %s", in, got, want)
		}
	}
	// Forbidden: keep the per-run name and say why, once.
	denied := fake.NewSimpleClientset()
	denied.PrependReactor("list", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "batch", Resource: "jobs"}, "", errors.New("no"))
	})
	notes = nil
	cron = cronJobOwners(context.Background(), denied, Options{Logf: func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }})
	if got := cron("shop", "Job/report-1"); got != "Job/report-1" || len(notes) != 1 || !strings.Contains(notes[0], "grouped per run") {
		t.Errorf("forbidden: got %s, notes %v", got, notes)
	}
}

// Without a namespace, options mean "default", never "every namespace": an
// empty namespace would list pods cluster-wide.
func TestDefaultsNeverWidenToAllNamespaces(t *testing.T) {
	o := Options{Duration: time.Minute, Interval: time.Second, LabelSelector: "app"}
	o.defaults()
	if o.Namespace != "default" || o.listNamespace() == "" {
		t.Fatalf("defaults left namespace %q (lists %q)", o.Namespace, o.listNamespace())
	}
}

// Run validates its own options, for callers other than the CLI: invalid
// options fail before the cluster is touched (the nil clientset proves it).
func TestRunValidatesItsOptions(t *testing.T) {
	if _, err := Run(context.Background(), nil, nil, Options{Duration: time.Minute, Interval: time.Second}); err == nil || !strings.Contains(err.Error(), "label selector is required") {
		t.Fatalf("Run without a selector: %v", err)
	}
}

// A pod's every address is kept (dual-stack: the IPv6 one is not the primary),
// and so is its start time.
func TestToGraphPodKeepsEveryAddressAndStartTime(t *testing.T) {
	start := metav1.NewTime(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"},
		Status: corev1.PodStatus{PodIP: "192.0.2.10", PodIPs: []corev1.PodIP{{IP: "192.0.2.10"}, {IP: "2001:db8::10"}}, StartTime: &start}}
	g := toGraphPod(p)
	if len(g.IPs) != 1 || g.IPs[0] != "2001:db8::10" || !g.StartTime.Equal(start.Time) {
		t.Fatalf("toGraphPod = IPs %v, start %v", g.IPs, g.StartTime)
	}
}

// inventory keeps what it lists: Services in every namespace even when the
// capture is scoped to one, every cluster IP of a dual-stack Service, a
// numeric target port that differs from the port, every pod CIDR of a node,
// and the legacy single-value fields where the lists are empty.
func TestInventoryKeepsWhatItLists(t *testing.T) {
	api := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "api"}, Spec: corev1.ServiceSpec{
		ClusterIP: "192.0.2.200", ClusterIPs: []string{"192.0.2.200", "2001:db8::200"},
		Ports: []corev1.ServicePort{
			{Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromInt(8080)},
			{Protocol: corev1.ProtocolUDP, Port: 53},
			{Protocol: corev1.ProtocolTCP, Port: 443, TargetPort: intstr.FromString("https")},
		}}}
	legacy := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "db"}, Spec: corev1.ServiceSpec{ClusterIP: "192.0.2.201"}}
	headless := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "peers"}, Spec: corev1.ServiceSpec{
		ClusterIP: corev1.ClusterIPNone, ClusterIPs: []string{corev1.ClusterIPNone}}}
	elsewhere := pod("other", "db-0", corev1.PodRunning, nil)
	cs := fake.NewSimpleClientset(api, legacy, headless, elsewhere)
	nodes := []corev1.Node{
		{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: corev1.NodeSpec{PodCIDR: "192.0.2.0/26", PodCIDRs: []string{"192.0.2.0/26", "2001:db8:1::/64"}},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"},
				{Type: corev1.NodeHostName, Address: "a"}, {Type: corev1.NodeExternalIP, Address: "198.51.100.1"}}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "b"}, Spec: corev1.NodeSpec{PodCIDR: "192.0.2.64/26"}},
	}
	inv := inventory(context.Background(), cs, nil, nodes, Options{Namespace: "shop", Logf: func(string, ...any) {}})
	svc := map[string]graph.Service{}
	for _, s := range inv.Services {
		svc[s.ID()] = s
	}
	if len(inv.Pods) != 1 || inv.Pods[0].Namespace != "other" {
		t.Errorf("pods are listed cluster-wide: %+v", inv.Pods)
	}
	if s, ok := svc["other/db"]; !ok || fmt.Sprint(s.ClusterIPs) != "[192.0.2.201]" {
		t.Errorf("a Service outside the capture's namespace, by its legacy clusterIP, is kept: %+v", inv.Services)
	}
	if got := fmt.Sprint(svc["shop/api"].ClusterIPs); got != "[192.0.2.200 2001:db8::200]" {
		t.Errorf("both cluster IPs of a dual-stack Service: %s", got)
	}
	if got := fmt.Sprint(svc["shop/api"].Ports); got != "[{tcp 80 8080} {udp 53 53} {tcp 443 https}]" {
		t.Errorf("ports, with target ports: %s", got)
	}
	if got := svc["shop/peers"].ClusterIPs; len(got) != 0 {
		t.Errorf("a headless Service has no cluster IP: %v", got)
	}
	if fmt.Sprint(inv.Nodes) != "[{a [192.0.2.10 198.51.100.1] [192.0.2.0/26 2001:db8:1::/64]} {b [] [192.0.2.64/26]}]" {
		t.Errorf("nodes: %+v", inv.Nodes)
	}
}

// A sampler that finished is read: its log is fetched and parsed. (The fake
// clientset's log is "fake logs", which does not parse.)
// finishedSamplers answers the capture's polling with every debug container
// already terminated with exit, as samplers that ran to the end.
func finishedSamplers(cs *fake.Clientset, exit int32, reason string) {
	podsGVR := schema.GroupVersionResource{Version: "v1", Resource: "pods"}
	podsGVK := schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := cs.Tracker().List(podsGVR, podsGVK, "shop")
		if err != nil {
			return false, nil, nil
		}
		list := obj.(*corev1.PodList).DeepCopy()
		for i := range list.Items {
			p := &list.Items[i]
			for _, c := range p.Spec.EphemeralContainers {
				p.Status.EphemeralContainerStatuses = append(p.Status.EphemeralContainerStatuses, corev1.ContainerStatus{
					Name: c.Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: exit, Reason: reason}}})
			}
		}
		return true, list, nil
	})
}

func TestFinishedSamplerIsRead(t *testing.T) {
	sel := map[string]string{"pp": "target"}
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, sel))
	finishedSamplers(cs, 0, "")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, cs, nil, Options{Namespace: "shop", LabelSelector: "pp=target", Duration: time.Second, Interval: time.Second,
		StartTimeout: time.Second, PollInterval: 10 * time.Millisecond, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Pods) != 1 || res.Pods[0].Probe.Status != graph.ProbeFailed || !strings.HasPrefix(res.Pods[0].Probe.Reason, "parsing sampler log") {
		t.Fatalf("a finished sampler's log is read and parsed: %+v", res.Pods)
	}
}

// logs serves each sampler log read from read (follow: the stream, else the
// plain read); the fake clientset answers every one with "fake logs".
type logs struct {
	kubernetes.Interface
	read func(follow bool) (string, error)
}

func (l logs) CoreV1() corev1client.CoreV1Interface {
	return logsCore{l.Interface.CoreV1(), l.read}
}

type logsCore struct {
	corev1client.CoreV1Interface
	read func(follow bool) (string, error)
}

func (c logsCore) Pods(ns string) corev1client.PodInterface {
	return logsPods{c.CoreV1Interface.Pods(ns), c.read}
}

type logsPods struct {
	corev1client.PodInterface
	read func(follow bool) (string, error)
}

func (p logsPods) GetLogs(name string, o *corev1.PodLogOptions) *rest.Request {
	body, err := p.read(o.Follow)
	return (&fakerest.RESTClient{
		Client: fakerest.CreateHTTPClient(func(*http.Request) (*http.Response, error) {
			if err != nil {
				return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(err.Error()))}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
		}),
		NegotiatedSerializer: scheme.Codecs.WithoutConversion(),
		GroupVersion:         corev1.SchemeGroupVersion,
		VersionedAPIPath:     "/api/v1/namespaces/shop/pods/" + name + "/log",
	}).Request()
}

// How a sampler's log is read: the stream, and a plain read when the stream
// did not reach the end, whichever is more complete.
func TestSamplerLogFallbacks(t *testing.T) {
	const (
		v1     = "@@podpeers v1\n"
		one    = "@@sample 1700000000\n@@file tcp\n"
		two    = one + "@@sample 1700000005\n@@file tcp\n"
		end    = "@@end\n"
		denied = "denied"
		// A log whose beginning kubelet rotated away: no header, each sample
		// carrying its own anchor.
		rotated = "@@sample 1000.00 1700000000 1000.00\n@@file tcp\n@@sample 1005.00 1700000000 1000.00\n@@file tcp\n" + end
	)
	for _, c := range []struct {
		name, stream, plain string
		status              graph.ProbeStatus
		samples             int
		complete            bool
		reason              string
		plainReads          int
	}{
		{"the stream reached the end", v1 + two + end, "", graph.ProbeObserved, 2, true, "", 0},
		{"a stream cut short is read again in full", v1 + one, v1 + two + end, graph.ProbeObserved, 2, true, "", 1},
		// A sample counts once the next marker shows it whole: a log cut after
		// two sample markers holds one sample.
		{"a cut stream is kept when the plain read fails", v1 + two, denied, graph.ProbeObserved, 1, false, "", 1},
		{"a cut stream is kept over a shorter plain read", v1 + two, v1 + one, graph.ProbeObserved, 1, false, "", 1},
		{"a sampler with no samples failed", v1 + end, "", graph.ProbeFailed, 0, false, "parsing sampler log: sampler produced no samples", 0},
		// A rotated log is never whole, so it is read again too.
		{"a rotated log says what was lost", rotated, rotated, graph.ProbeObserved, 2, false, "only the latest samples survived: the log's beginning was lost (kubelet log rotation?)", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"pp": "target"}))
			finishedSamplers(cs, 0, "")
			var plainReads atomic.Int64
			lc := logs{cs, func(follow bool) (string, error) {
				if follow {
					return c.stream, nil
				}
				plainReads.Add(1)
				if c.plain == denied {
					return "", errors.New("pods/log is forbidden")
				}
				return c.plain, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res, err := Run(ctx, lc, nil, Options{Namespace: "shop", LabelSelector: "pp=target", Duration: time.Second, Interval: time.Second,
				StartTimeout: time.Second, PollInterval: 10 * time.Millisecond, Logf: func(string, ...any) {}})
			if err != nil {
				t.Fatal(err)
			}
			p := res.Pods[0].Probe
			if p.Status != c.status || p.Samples != c.samples || p.Complete != c.complete || p.Reason != c.reason || plainReads.Load() != int64(c.plainReads) {
				t.Fatalf("probe %+v after %d plain read(s); want %s, %d sample(s), complete %v, reason %q, %d plain read(s)",
					p, plainReads.Load(), c.status, c.samples, c.complete, c.reason, c.plainReads)
			}
		})
	}
}

// Every option left at zero gets its default.
func TestZeroOptionsGetDefaults(t *testing.T) {
	o := Options{}
	o.defaults()
	if o.Interval <= 0 || o.StartTimeout <= 0 || o.PollInterval <= 0 {
		t.Fatalf("zero options were not defaulted: %+v", o)
	}
	// The documented defaults (docs/method.md): a 5-minute window, a sample a second.
	if o.Interval != time.Second || DefaultInterval != time.Second || DefaultDuration != 5*time.Minute {
		t.Errorf("defaults: interval %s (%s), duration %s; want 1s and 5m", o.Interval, DefaultInterval, DefaultDuration)
	}
}

// A zero duration is not a capture: it is refused, not defaulted.
func TestZeroDurationIsRefused(t *testing.T) {
	if err := (Options{Duration: 0, Interval: time.Second}).Validate(); err == nil || !strings.Contains(err.Error(), "duration must be positive") {
		t.Fatalf("zero duration: %v", err)
	}
}

// A pod list that fails mid-window ends the capture with that error; it is
// not taken for an empty namespace.
func TestPollingFailureEndsTheCapture(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"pp": "t"}))
	var lists atomic.Int32
	cs.PrependReactor("list", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if lists.Add(1) > 1 {
			return true, nil, errors.New("apiserver went away")
		}
		return false, nil, nil
	})
	_, err := Run(context.Background(), cs, nil, Options{Namespace: "shop", LabelSelector: "pp=t",
		Duration: time.Second, Interval: time.Second, StartTimeout: time.Second, PollInterval: 10 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "polling pods") || !strings.Contains(err.Error(), "apiserver went away") {
		t.Fatalf("err = %v", err)
	}
}

// Without permission to list Services, the capture goes on and says what that
// costs.
func TestServicesThatCannotBeListedAreANote(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"pp": "target"}))
	finishedSamplers(cs, 0, "")
	cs.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", errors.New("denied"))
	})
	var mu sync.Mutex
	var logged []string
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := Run(ctx, cs, nil, Options{Namespace: "shop", LabelSelector: "pp=target", Duration: time.Second, Interval: time.Second,
		StartTimeout: time.Second, PollInterval: 10 * time.Millisecond, Logf: func(f string, a ...any) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, fmt.Sprintf(f, a...))
		}})
	if err != nil {
		t.Fatal(err)
	}
	if all := strings.Join(logged, "\n"); !strings.Contains(all, "note: cannot list services (forbidden); service IPs will show as addresses") {
		t.Fatalf("no note about services:\n%s", all)
	}
}

// Interrupted mid-window, a capture returns the interruption, not a result.
func TestInterruptedCaptureFails(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"pp": "target"}))
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	res, err := Run(ctx, cs, nil, Options{Namespace: "shop", LabelSelector: "pp=target", Duration: time.Minute, Interval: time.Second,
		StartTimeout: time.Minute, PollInterval: 10 * time.Millisecond, Logf: func(string, ...any) {}})
	if !errors.Is(err, context.Canceled) || len(res.Pods) != 0 {
		t.Fatalf("err %v, %d pod(s)", err, len(res.Pods))
	}
}

// A sampler that ended badly and left no readable log fails with how it ended.
func TestASamplersExitIsNamedWhenItsLogFails(t *testing.T) {
	cs := fake.NewSimpleClientset(pod("shop", "api", corev1.PodRunning, map[string]string{"pp": "target"}))
	finishedSamplers(cs, 137, "OOMKilled")
	lc := logs{cs, func(bool) (string, error) { return "", nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := Run(ctx, lc, nil, Options{Namespace: "shop", LabelSelector: "pp=target", Duration: time.Second, Interval: time.Second,
		StartTimeout: time.Second, PollInterval: 10 * time.Millisecond, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	if p := res.Pods[0].Probe; p.Status != graph.ProbeFailed || p.Reason != "parsing sampler log: procnet: no podpeers header in sampler output (sampler exited 137 (OOMKilled))" {
		t.Fatalf("probe %+v", p)
	}
}
