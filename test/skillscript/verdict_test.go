package skillscript

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The script's decisions, without a cluster: podpeers, helm, kubectl and
// sleep are shims that record every call and play the outcome each case
// asks for (capture and diff exit codes, helm test, what the policy file
// holds). The real-cluster skill workflow (test/e2e) proves the same paths
// against real tools; this proves every branch of the decision table.

type fake struct {
	dir, calls string
	env        []string
}

func newFake(t *testing.T) fake {
	t.Helper()
	dir := t.TempDir()
	f := fake{dir: dir, calls: filepath.Join(dir, "calls.log")}
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	shims := map[string]string{
		"podpeers": `echo "podpeers $*" >> "$CALLS"
cmd="$1"; shift
out=""; prev=""
for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
case "$cmd" in
  check-context) exit "${FAKE_CHECK:-0}" ;;
  capture) [ -n "$out" ] && echo '{}' > "$out"; exit "${FAKE_CAPTURE:-0}" ;;
  suggest) [ -n "$out" ] && echo '# suggested' > "$out"; exit 0 ;;
  render) echo "rendered"; exit 0 ;;
  diff) echo "VERDICT: from the fake diff"; exit "${FAKE_DIFF:-0}" ;;
esac
exit 0`,
		"helm": `echo "helm $*" >> "$CALLS"
[ "$1" = test ] && exit "${FAKE_HELM_TEST:-0}"
exit 0`,
		"kubectl": `echo "kubectl $*" >> "$CALLS"
case " $* " in
  *" --dry-run=client "*) [ -n "${FAKE_UNPARSABLE:-}" ] && exit 1; printf '%b' "${FAKE_OBJS-networkpolicy.networking.k8s.io/podpeers-web\n}"; exit 0 ;;
  *" get deployment "*) printf '%b' "${FAKE_DEPLOYS:-}"; exit 0 ;;
  *" get pods "*) echo "shop/web-1"; exit 0 ;;
esac
exit 0`,
		"sleep": `echo "sleep $*" >> "$CALLS"`,
	}
	for name, body := range shims {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	f.env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PODPEERS="+filepath.Join(bin, "podpeers"), "CALLS="+f.calls, "KUBECONFIG=")
	return f
}

func (f fake) run(t *testing.T, env []string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(f.env, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(f.calls)
	return code, string(out), string(calls)
}

// files makes a baseline and a policy file to verify against.
func (f fake) files(t *testing.T) (baseline, policy string) {
	baseline = filepath.Join(f.dir, "run", "baseline.json")
	os.MkdirAll(filepath.Dir(baseline), 0o755)
	os.WriteFile(baseline, []byte("{}"), 0o644)
	policy = filepath.Join(f.dir, "policy.yaml")
	os.WriteFile(policy, []byte("kind: NetworkPolicy\n"), 0o644)
	return
}

var common = []string{"--release", "shop", "--namespace", "shop", "--context", "k3d-dev"}

func TestVerifyVerdicts(t *testing.T) {
	for _, c := range []struct {
		name    string
		env     []string
		code    int
		verdict string
	}{
		{"everything held", nil, 0, "verdict: OK"},
		{"helm test failed", []string{"FAKE_HELM_TEST=1"}, 5, "verdict: BROKEN: helm test failed"},
		{"traffic blocked or lost", []string{"FAKE_DIFF=4"}, 4, "verdict: BROKEN: helm test passed, but traffic"},
		{"flows not exercised", []string{"FAKE_DIFF=5"}, 7, "verdict: INCONCLUSIVE: helm test passed, but some flows were never exercised"},
		{"a pod not observed, diff clean", []string{"FAKE_CAPTURE=3"}, 7, "verdict: INCONCLUSIVE: helm test passed, but some pods could not be observed"},
		{"helm test failure outranks the diff", []string{"FAKE_HELM_TEST=1", "FAKE_DIFF=4"}, 5, "verdict: BROKEN: helm test failed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			baseline, policy := f.files(t)
			code, out, _ := f.run(t, c.env, append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)...)
			if code != c.code || !strings.Contains(out, c.verdict) {
				t.Fatalf("exit %d, want %d with %q:\n%s", code, c.code, c.verdict, out)
			}
			if strings.Contains(strings.Join(c.env, " "), "FAKE_CAPTURE=3") != strings.Contains(out, "capture is partial (some pods could not be observed)") {
				t.Fatalf("a partial capture, and only a partial one, is said so:\n%s", out)
			}
			if !strings.Contains(out, "policy:  "+policy) {
				t.Fatalf("the summary should name the policy it applied:\n%s", out)
			}
			verdict, err := os.ReadFile(filepath.Join(filepath.Dir(baseline), "verdict.txt"))
			if err != nil || !strings.Contains(string(verdict), c.verdict) {
				t.Fatalf("verdict.txt next to the baseline should hold the verdict: %v %q", err, verdict)
			}
		})
	}
}

func TestVerifyFailuresStopTheScript(t *testing.T) {
	for _, c := range []struct {
		name, msg string
		env       []string
	}{
		{"capture failed", "capture failed (exit 1)", []string{"FAKE_CAPTURE=1"}},
		{"diff failed", "diff failed (exit 1)", []string{"FAKE_DIFF=1"}},
		{"policy holds something else", "contains objects that are not NetworkPolicies", []string{`FAKE_OBJS=networkpolicy.networking.k8s.io/a\nconfigmap/b\n`}},
		{"policy holds nothing", "contains no NetworkPolicy", []string{"FAKE_OBJS="}},
		{"policy does not parse", "cannot parse", []string{"FAKE_UNPARSABLE=1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			baseline, policy := f.files(t)
			code, out, calls := f.run(t, c.env, append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)...)
			if code != 1 || !strings.Contains(out, c.msg) {
				t.Fatalf("exit %d, want 1 with %q:\n%s", code, c.msg, out)
			}
			if strings.Contains(c.name, "policy") && strings.Contains(calls, "--dry-run=server") {
				t.Fatal("a refused policy file reached the server-side dry run")
			}
		})
	}
}

func TestVerifyArgumentChecks(t *testing.T) {
	f := newFake(t)
	baseline, policy := f.files(t)
	for _, c := range []struct {
		msg  string
		args []string
	}{
		{"--context is required", []string{"verify", "--release", "shop", "--namespace", "shop", "--policy", policy, "--baseline", baseline}},
		{"--namespace is required", []string{"verify", "--release", "shop", "--context", "k3d-dev", "--policy", policy, "--baseline", baseline}},
		{"--release is required", []string{"verify", "--namespace", "shop", "--context", "k3d-dev", "--policy", policy, "--baseline", baseline}},
		{"--release is required", []string{"baseline", "--namespace", "shop", "--context", "k3d-dev"}},
		{"--baseline file not found", append([]string{"verify", "--policy", policy, "--baseline", filepath.Join(f.dir, "nope.json")}, common...)},
		{"--policy file not found", append([]string{"verify", "--policy", filepath.Join(f.dir, "nope.yaml"), "--baseline", baseline}, common...)},
		{"--rollback-on-fail needs --policy", append([]string{"verify", "--no-apply", "--rollback-on-fail", "--baseline", baseline}, common...)},
		{"--policy file not found", []string{"rollback", "--namespace", "shop", "--context", "k3d-dev", "--policy", filepath.Join(f.dir, "nope.yaml")}},
	} {
		if code, out, _ := f.run(t, nil, c.args...); code != 1 || !strings.Contains(out, c.msg) {
			t.Errorf("%v: exit %d, want 1 with %q:\n%s", c.args, code, c.msg, out)
		}
	}
	if code, out, calls := newFake(t).run(t, nil, append([]string{"verify", "--no-such-flag"}, common...)...); code != 1 || !strings.Contains(out, "unknown argument: --no-such-flag") || calls != "" {
		t.Errorf("an unknown argument: exit %d, want 1 before any call:\n%s\n%s", code, out, calls)
	}
	if code, out, _ := f.run(t, nil, append([]string{"deploy"}, common...)...); code != 1 || !strings.Contains(out, "Exit codes: 0 OK") {
		t.Errorf("an unknown subcommand: exit %d, want 1 with the usage:\n%s", code, out)
	}
	if code, out, _ := f.run(t, nil); code != 1 || !strings.Contains(out, "Exit codes: 0 OK") {
		t.Errorf("no arguments: exit %d, want 1 with the usage:\n%s", code, out)
	}
	if code, out, calls := newFake(t).run(t, nil, "verify", "-h"); code != 0 || !strings.Contains(out, "Exit codes: 0 OK") || calls != "" {
		t.Errorf("-h: exit %d, want 0 with the usage and no calls:\n%s\n%s", code, out, calls)
	}
}

func TestVerifyRollsBackOnlyWhenAskedAndBroken(t *testing.T) {
	for _, c := range []struct {
		env      []string
		rollback bool
		deleted  bool
	}{
		{[]string{"FAKE_DIFF=4"}, true, true},
		{[]string{"FAKE_DIFF=4"}, false, false},
		{nil, true, false},
	} {
		f := newFake(t)
		baseline, policy := f.files(t)
		args := append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)
		if c.rollback {
			args = append(args, "--rollback-on-fail")
		}
		_, _, calls := f.run(t, c.env, args...)
		if got := strings.Contains(calls, "kubectl --context k3d-dev delete -n shop -f "+policy); got != c.deleted {
			t.Errorf("%v rollback=%v: deleted=%v, want %v\n%s", c.env, c.rollback, got, c.deleted, calls)
		}
	}
}

func TestVerifyRestartsWorkloadsUnlessTold(t *testing.T) {
	for _, noRestart := range []bool{false, true} {
		f := newFake(t)
		baseline, policy := f.files(t)
		args := append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)
		if noRestart {
			args = append(args, "--no-restart")
		}
		_, _, calls := f.run(t, []string{`FAKE_DEPLOYS=deployment.apps/web\n`}, args...)
		if got := strings.Contains(calls, "rollout restart -n shop deployment.apps/web"); got == noRestart {
			t.Errorf("--no-restart=%v: restarted=%v\n%s", noRestart, got, calls)
		}
	}
}

func TestVerifyNoApplyAppliesNothing(t *testing.T) {
	f := newFake(t)
	baseline, _ := f.files(t)
	code, out, calls := f.run(t, nil, append([]string{"verify", "--no-apply", "--baseline", baseline}, common...)...)
	if code != 0 || strings.Contains(calls, " apply ") || !strings.Contains(out, "policy:  already in the cluster (--no-apply)") {
		t.Fatalf("exit %d; --no-apply must apply nothing:\n%s\n%s", code, calls, out)
	}
}

func TestVerifyNoteWhenHelmTestFailsButTheDiffIsClean(t *testing.T) {
	f := newFake(t)
	baseline, policy := f.files(t)
	_, out, _ := f.run(t, []string{"FAKE_HELM_TEST=1"}, append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)...)
	if !strings.Contains(out, "note: the traffic diff has no evidence either way here") {
		t.Fatalf("the note should explain a clean diff next to a failed helm test:\n%s", out)
	}
	f = newFake(t)
	baseline, policy = f.files(t)
	_, out, _ = f.run(t, []string{"FAKE_HELM_TEST=1", "FAKE_DIFF=4"}, append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)...)
	if strings.Contains(out, "note: the traffic diff has no evidence") {
		t.Fatalf("no such note when the diff found something:\n%s", out)
	}
}

func TestBaselineStopsWhenHelmTestAlreadyFails(t *testing.T) {
	f := newFake(t)
	out := filepath.Join(f.dir, "out")
	code, text, calls := f.run(t, []string{"FAKE_HELM_TEST=1"}, append([]string{"baseline", "--out", out}, common...)...)
	if code != 6 || strings.Contains(calls, "podpeers suggest") || !strings.Contains(text, "helm test FAILS without any new policy") {
		t.Fatalf("exit %d, want 6 before any suggestion:\n%s\n%s", code, calls, text)
	}
	f = newFake(t)
	code, _, calls = f.run(t, nil, append([]string{"baseline", "--out", out}, common...)...)
	if code != 0 || !strings.Contains(calls, "podpeers suggest -n shop -o "+filepath.Join(out, "policy.yaml")) {
		t.Fatalf("exit %d; a passing baseline should suggest policies:\n%s", code, calls)
	}
}

func TestArgumentsReachTheTools(t *testing.T) {
	f := newFake(t)
	baseline, policy := f.files(t)
	kc := filepath.Join(f.dir, "kc")
	_, _, calls := f.run(t, nil, append([]string{"verify", "--policy", policy, "--baseline", baseline,
		"--kubeconfig", kc, "--allow-context", "k3d-dev", "--image", "mirror.example.test/busybox:1",
		"--selector", "app=web", "--duration", "7s", "--interval", "500ms", "--settle", "3"}, common...)...)
	for _, want := range []string{
		"kubectl --context k3d-dev --kubeconfig " + kc,
		"-l app=web --image mirror.example.test/busybox:1 --duration 7s --interval 500ms", // --selector, --duration, --interval
		"sleep 3", // --settle                                             // kubeconfig reaches kubectl
		"helm test --kube-context k3d-dev --kubeconfig " + kc,                                      // and helm
		"podpeers check-context --context k3d-dev --kubeconfig " + kc + " --allow-context k3d-dev", // and podpeers, with the opt-in
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("calls lack %q:\n%s", want, calls)
		}
	}
}

func TestRollbackDeletesThePolicy(t *testing.T) {
	f := newFake(t)
	_, policy := f.files(t)
	code, _, calls := f.run(t, nil, "rollback", "--namespace", "shop", "--context", "k3d-dev", "--policy", policy)
	if code != 0 || !strings.Contains(calls, "kubectl --context k3d-dev delete -n shop -f "+policy) {
		t.Fatalf("exit %d:\n%s", code, calls)
	}
}

// The default selector is the release's instance label.
func TestDefaultSelectorIsTheRelease(t *testing.T) {
	f := newFake(t)
	baseline, policy := f.files(t)
	_, _, calls := f.run(t, nil, append([]string{"verify", "--policy", policy, "--baseline", baseline}, common...)...)
	if !strings.Contains(calls, "-l app.kubernetes.io/instance=shop ") {
		t.Fatalf("calls:\n%s", calls)
	}
}

// podpeers judged the context; a HELM_KUBE* override would point helm at a
// cluster it never saw. Each one refuses before anything is touched.
func TestHelmOverridesRefuseBeforeTouchingAnything(t *testing.T) {
	for _, v := range []string{"HELM_KUBEAPISERVER", "HELM_KUBETOKEN", "HELM_KUBEASUSER", "HELM_KUBEASGROUPS", "HELM_KUBECAFILE",
		"HELM_KUBEINSECURE_SKIP_TLS_VERIFY", "HELM_KUBETLS_SERVER_NAME", "HELM_KUBECONTEXT"} {
		f := newFake(t)
		code, out, calls := f.run(t, []string{v + "=elsewhere"}, append([]string{"baseline"}, common...)...)
		if code != 2 || !strings.Contains(out, v+" is set") || strings.Contains(calls, "helm ") || strings.Contains(calls, "kubectl ") {
			t.Errorf("%s set: exit %d, want 2 before any helm or kubectl call\n%s\n%s", v, code, out, calls)
		}
	}
}
