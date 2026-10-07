// Package skillscript tests the podpeers-netpol skill script's safety property
// without a cluster: for a context podpeers refuses, every subcommand must
// exit 2 before running kubectl or helm even once.
//
// kubectl and helm are replaced by shims that record every invocation, so
// "touched nothing" is observed, not assumed. A positive control shows the
// shims do record calls when the guard lets the script through.
package skillscript

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const script = "../../skills/podpeers-netpol/scripts/netpol-check.sh"

type env struct {
	dir, kubeconfig, calls, podpeers string
}

func setup(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	e := env{dir: dir, kubeconfig: filepath.Join(dir, "kubeconfig"), calls: filepath.Join(dir, "calls.log"),
		podpeers: filepath.Join(dir, "podpeers")}
	if out, err := exec.Command("go", "build", "-o", e.podpeers, "../../cmd/podpeers").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// An invented production-like cluster on an unresolvable host.
	os.WriteFile(e.kubeconfig, []byte(`apiVersion: v1
kind: Config
clusters: [{name: prod, cluster: {server: "https://cluster.example.invalid:6443"}}]
users: [{name: me, user: {token: not-a-real-token}}]
contexts: [{name: prod-like, context: {cluster: prod, user: me}}]
current-context: prod-like
`), 0o600)
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	for _, tool := range []string{"kubectl", "helm"} {
		os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho \""+tool+" $*\" >> "+e.calls+"\nexit 1\n"), 0o755)
	}
	return e
}

func (e env) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(e.dir, "bin")+":"+os.Getenv("PATH"),
		"PODPEERS="+e.podpeers, "KUBECONFIG=")
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func (e env) recorded(t *testing.T) string {
	b, err := os.ReadFile(e.calls)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestScriptRefusesBeforeTouchingAnything(t *testing.T) {
	e := setup(t)
	common := []string{"--kubeconfig", e.kubeconfig, "--context", "prod-like", "--namespace", "shop"}
	// Policy and baseline files deliberately do not exist: refusal must come
	// before any other check, so the exit code is 2, not a file error.
	cases := map[string][]string{
		"baseline": {"baseline", "--release", "shop"},
		"verify":   {"verify", "--release", "shop", "--policy", "missing.yaml", "--baseline", "missing.json"},
		"rollback": {"rollback", "--policy", "missing.yaml"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := e.run(t, append(args, common...)...)
			if calls := e.recorded(t); calls != "" {
				t.Errorf("the script touched the cluster despite the refused context:\n%s", calls)
			}
			if code != 2 || !strings.Contains(out, "refused context 'prod-like'") {
				t.Fatalf("want refusal exit 2, got %d:\n%s", code, out)
			}
		})
	}
}

func TestShimsRecordCallsWhenTheGuardAllows(t *testing.T) {
	// Positive control: with an explicit, named opt-in the guard passes, and
	// the script's first cluster call reaches the kubectl shim. Without this,
	// "no calls recorded" above could be vacuous.
	e := setup(t)
	policy := filepath.Join(e.dir, "policy.yaml")
	os.WriteFile(policy, []byte("# empty\n"), 0o644)
	code, out := e.run(t, "rollback", "--policy", policy, "--kubeconfig", e.kubeconfig,
		"--context", "prod-like", "--namespace", "shop", "--allow-context", "prod-like")
	calls := e.recorded(t)
	if !strings.Contains(calls, "kubectl --context prod-like") || !strings.Contains(calls, "delete") {
		t.Fatalf("expected the kubectl shim to record a delete; exit %d calls %q\n%s", code, calls, out)
	}
}
