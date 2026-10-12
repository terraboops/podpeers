// Package tooling tests the repo's own cluster-safety stops: the checks that
// keep the e2e tooling off any cluster but the throwaway one it created. Each
// is run against an invented production-like context and must refuse before
// it acts; a positive control shows the same run goes on when the context is
// the local one, so a refusal is the check and not a broken setup. No cluster
// is needed: k3d, kubectl and docker are shims that record every call.
package tooling

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const prodLike = `apiVersion: v1
kind: Config
clusters: [{name: prod, cluster: {server: "https://cluster.example.invalid:6443"}}]
users: [{name: me, user: {token: not-a-real-token}}]
contexts: [{name: prod-like, context: {cluster: prod, user: me}}]
current-context: prod-like
`

// shims writes k3d, kubectl and docker that record their calls. kubectl's
// current-context answers $FAKE_CTX; k3d's kubeconfig get prints $FAKE_KCFG.
func shims(t *testing.T, dir string) (bin, calls string) {
	bin, calls = filepath.Join(dir, "bin"), filepath.Join(dir, "calls.log")
	os.MkdirAll(bin, 0o755)
	for name, body := range map[string]string{
		"k3d": `case "$1 $2" in
  "cluster list") echo "${FAKE_LIST:-[]}" ;;
  "kubeconfig get") cat "$FAKE_KCFG" ;;
  "node list") echo '[]' ;;
esac`,
		"kubectl": `case "$*" in *"config current-context"*) echo "$FAKE_CTX" ;; esac`,
		"docker":  ``,
		"colima":  `[ "$1" = status ] && exit "${FAKE_COLIMA_STATUS:-0}"`,
	} {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\necho \""+name+" $*\" >> \""+calls+"\"\n"+body+"\nexit 0\n"), 0o755)
	}
	return
}

func run(t *testing.T, env []string, name string, args ...string) (int, string) {
	t.Helper()
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), env...)
	out, err := c.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, string(out)
}

func read(p string) string { b, _ := os.ReadFile(p); return string(b) }

// copyScript puts a hack/ script in a scratch repo root, so what it writes
// under its ROOT (.e2e/) lands there and not in this checkout.
func copyScript(t *testing.T, name string) (root, script string) {
	root = t.TempDir()
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	b, err := os.ReadFile(filepath.Join("..", "..", "hack", name))
	if err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(root, "hack", name)
	os.WriteFile(script, b, 0o755)
	return
}

// e2e-cluster.sh writes the kubeconfig k3d hands it, then checks its current
// context is the cluster it made before it waits on (or touches) anything.
func TestClusterScriptRefusesAForeignContext(t *testing.T) {
	for _, c := range []struct {
		ctx    string
		refuse bool
	}{{"prod-like", true}, {"k3d-podpeers-e2e", false}} {
		root, script := copyScript(t, "e2e-cluster.sh")
		bin, calls := shims(t, root)
		kcfg := filepath.Join(root, "from-k3d")
		os.WriteFile(kcfg, []byte(prodLike), 0o600)
		code, out := run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_CTX=" + c.ctx, "FAKE_KCFG=" + kcfg, "KUBECONFIG="}, "bash", script, "up")
		waited := strings.Contains(read(calls), "kubectl --kubeconfig "+filepath.Join(root, ".e2e", "kubeconfig")+" wait")
		if c.refuse && (code != 1 || !strings.Contains(out, "refusing: isolated kubeconfig has unexpected context 'prod-like'") || waited) {
			t.Fatalf("context %s: want refusal before kubectl wait; exit %d waited=%v\n%s\n%s", c.ctx, code, waited, out, read(calls))
		}
		if !c.refuse && (code != 0 || !waited) {
			t.Fatalf("control, context %s: want it to go on to kubectl wait; exit %d\n%s\n%s", c.ctx, code, out, read(calls))
		}
	}
}

// mutants.sh --e2e checks .e2e/kubeconfig's context before anything else.
func TestMutantsRefusesAForeignContext(t *testing.T) {
	for _, c := range []struct {
		ctx    string
		refuse bool
	}{{"prod-like", true}, {"k3d-podpeers-e2e", false}} {
		root, script := copyScript(t, "mutants.sh")
		bin, calls := shims(t, root)
		code, out := run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_CTX=" + c.ctx, "KUBECONFIG=", "GIT_DIR=" + filepath.Join(root, "no-git")}, "bash", script, "--e2e")
		refused := strings.Contains(out, "refusing: .e2e/kubeconfig is not the local e2e cluster")
		if c.refuse && (code != 1 || !refused) {
			t.Fatalf("context %s: want refusal; exit %d\n%s", c.ctx, code, out)
		}
		// The control gets past the check and stops at the snapshot (there
		// is no git repo here): proof the check, not the setup, refused.
		if !c.refuse && (refused || !strings.Contains(out, "could not snapshot the working tree")) {
			t.Fatalf("control, context %s: want it past the check; exit %d\n%s", c.ctx, code, out)
		}
		if !strings.Contains(read(calls), "kubectl --kubeconfig "+filepath.Join(root, ".e2e", "kubeconfig")+" config current-context") {
			t.Fatalf("the check should read .e2e/kubeconfig:\n%s", read(calls))
		}
	}
}

// The e2e suite's own hard stop: run directly with go test (no make), against
// a kubeconfig whose context is not a local cluster, it runs no test at all.
func TestE2ESuiteRefusesAForeignContext(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	os.WriteFile(kc, []byte(prodLike), 0o600)
	for _, c := range []struct {
		name string
		env  []string
	}{
		{"current context is not the expected one", []string{"PODPEERS_E2E_KUBECONFIG=" + kc}},
		{"expected context is not a local one", []string{"PODPEERS_E2E_KUBECONFIG=" + kc, "PODPEERS_E2E_CONTEXT=prod-like"}},
	} {
		code, out := run(t, append(c.env, "PODPEERS_E2E_OUT="+dir), "go", "test", "-tags", "e2e", "-count=1", "-v", "-run", "^TestE2E$", "../e2e/")
		if code == 0 || !strings.Contains(out, "e2e: REFUSING: kubeconfig current-context is \"prod-like\"") || strings.Contains(out, "=== RUN") {
			t.Fatalf("%s: want a refusal before any test runs; exit %d\n%s", c.name, code, out)
		}
	}
}

// up creates the cluster only when it is not there yet; down deletes it and
// its kubeconfig, and on colima hands freed blocks back to the host.
func TestClusterScriptUpAndDown(t *testing.T) {
	for _, exists := range []bool{false, true} {
		root, script := copyScript(t, "e2e-cluster.sh")
		bin, calls := shims(t, root)
		kcfg := filepath.Join(root, "from-k3d")
		os.WriteFile(kcfg, []byte(prodLike), 0o600)
		list := "[]"
		if exists {
			list = `[{"name":"podpeers-e2e"}]`
		}
		run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_CTX=k3d-podpeers-e2e", "FAKE_KCFG=" + kcfg, "FAKE_LIST=" + list, "KUBECONFIG="}, "bash", script, "up")
		if created := strings.Contains(read(calls), "k3d cluster create podpeers-e2e"); created == exists {
			t.Errorf("cluster exists=%v: created=%v\n%s", exists, created, read(calls))
		}
	}
	root, script := copyScript(t, "e2e-cluster.sh")
	bin, calls := shims(t, root)
	os.MkdirAll(filepath.Join(root, ".e2e"), 0o755)
	os.WriteFile(filepath.Join(root, ".e2e", "kubeconfig"), []byte(prodLike), 0o600)
	code, _ := run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "KUBECONFIG="}, "bash", script, "down")
	// A colima that is installed but not running is not asked to trim.
	root2, script2 := copyScript(t, "e2e-cluster.sh")
	bin2, calls2 := shims(t, root2)
	run(t, []string{"PATH=" + bin2 + ":" + os.Getenv("PATH"), "KUBECONFIG=", "FAKE_COLIMA_STATUS=1"}, "bash", script2, "down")
	if strings.Contains(read(calls2), "fstrim") {
		t.Errorf("a stopped colima was asked to trim:\n%s", read(calls2))
	}
	if _, err := os.Stat(filepath.Join(root, ".e2e", "kubeconfig")); code != 0 || err == nil ||
		!strings.Contains(read(calls), "k3d cluster delete podpeers-e2e") || !strings.Contains(read(calls), "colima ssh -- sudo fstrim -a") {
		t.Fatalf("down: exit %d; want the cluster and its kubeconfig gone, and colima trimmed\n%s", code, read(calls))
	}
}

// Anything but up or down is a usage error, and touches nothing.
func TestClusterScriptRejectsUnknownSubcommands(t *testing.T) {
	root, script := copyScript(t, "e2e-cluster.sh")
	bin, calls := shims(t, root)
	code, out := run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "KUBECONFIG="}, "bash", script, "destroy")
	if code != 2 || !strings.Contains(out, "usage:") || read(calls) != "" {
		t.Fatalf("destroy: exit %d, want 2 with the usage and no calls\n%s\n%s", code, out, read(calls))
	}
}

// docs/demo/make-demo.sh records the demo against .e2e/kubeconfig, and its
// tapes run a bare `kubectl apply` with KUBECONFIG set to that file: its
// check is all that keeps the demo off whatever that file points at.
func TestDemoScriptRefusesAForeignContext(t *testing.T) {
	for _, c := range []struct {
		ctx    string
		refuse bool
	}{{"prod-like", true}, {"k3d-podpeers-e2e", false}} {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "docs", "demo"), 0o755)
		b, err := os.ReadFile("../../docs/demo/make-demo.sh")
		if err != nil {
			t.Fatal(err)
		}
		script := filepath.Join(root, "docs", "demo", "make-demo.sh")
		os.WriteFile(script, b, 0o755)
		bin, calls := shims(t, root)
		// The control runs to the first recording, which stops it; by then the
		// output directory must exist.
		stubs := map[string]string{
			"make":  "exit 0",
			"sleep": "exit 0",
			"vhs":   "[ -d .e2e/demo/browser ] && echo 'vhs: output dir ready' >> \"" + calls + "\"; exit 1",
		}
		for tool, body := range stubs {
			os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\necho \""+tool+" $*\" >> \""+calls+"\"\n"+body+"\n"), 0o755)
		}
		code, out := run(t, []string{"PATH=" + bin + ":" + os.Getenv("PATH"), "FAKE_CTX=" + c.ctx, "KUBECONFIG="}, "bash", script)
		got := read(calls)
		refused := strings.Contains(out, "refusing: .e2e/kubeconfig is not the local e2e cluster")
		if c.refuse && (code != 1 || !refused || strings.Contains(got, "make") || strings.Count(got, "\n") != 1) {
			t.Fatalf("context %s: want refusal before anything but the context check; exit %d\n%s\n%s", c.ctx, code, out, got)
		}
		if !c.refuse && (refused || !strings.Contains(got, "make build") ||
			!strings.Contains(got, "kubectl --kubeconfig .e2e/kubeconfig --context k3d-podpeers-e2e apply -f docs/demo/app.yaml") ||
			!strings.Contains(got, "vhs: output dir ready")) {
			t.Fatalf("control, context %s: want it past the check, applying only to the e2e context, to a ready recording; exit %d\n%s\n%s", c.ctx, code, out, got)
		}
	}
}
