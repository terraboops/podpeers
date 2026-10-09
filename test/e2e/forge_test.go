//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// forged is the node identity each exact-name local tool gives its cluster,
// as the node gate's accept-list has it (internal/guard). colima's was also
// observed on a real colima; the others' tools are not installed here.
var forged = []struct{ context, providerID string }{
	{"rancher-desktop", "k3s://lima-rancher-desktop"},
	{"orbstack", "k3s://orbstack"},
	{"docker-desktop", "kind://docker/desktop/desktop-control-plane"},
	{"colima", "k3s://colima"},
}

// TestForgedToolIdentities forges, on a throwaway local k3d cluster, the node
// identity each exact-name tool reports (k3s's own cloud controller off, the
// kubelet told the provider ID), and asserts what the node gate does with it:
// allowed under that tool's context name, and refused under every other local
// name. This proves how the gate treats each identity string; it cannot prove
// that the real tool reports that string (see the README's evidence table).
// It also shows the same-identity residual from the other side: whatever
// cluster reports a tool's identity passes under that tool's name.
func TestForgedToolIdentities(t *testing.T) {
	if _, err := exec.LookPath("k3d"); err != nil {
		t.Fatal("k3d is required to forge node identities")
	}
	const name = "pp-forge"
	others := []string{"minikube", "k3d-" + name}
	for _, f := range forged {
		others = append(others, f.context)
	}
	for _, f := range forged {
		t.Run(f.context, func(t *testing.T) {
			exec.Command("k3d", "cluster", "delete", name).Run()
			defer exec.Command("k3d", "cluster", "delete", name).Run()
			out, err := exec.Command("k3d", "cluster", "create", name, "--image", "rancher/k3s:v1.31.5-k3s1",
				"--servers", "1", "--agents", "0", "--no-lb", "--api-port", "127.0.0.1:6552",
				"--k3s-arg", "--disable=traefik@server:0", "--k3s-arg", "--disable=servicelb@server:0",
				"--k3s-arg", "--disable=metrics-server@server:0", "--k3s-arg", "--disable-cloud-controller@server:0",
				"--k3s-arg", "--kubelet-arg=provider-id="+f.providerID+"@server:0",
				"--kubeconfig-update-default=false", "--kubeconfig-switch-context=false", "--wait").CombinedOutput()
			if err != nil {
				t.Fatalf("creating the forging cluster: %v\n%s", err, out)
			}
			kc, err := exec.Command("k3d", "kubeconfig", "get", name).Output()
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := clientcmd.Load(kc)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.TrimSpace(kubectlWith(t, cfg, "k3d-"+name, "get", "nodes", "-o", "jsonpath={.items[*].spec.providerID}"))
			if got != f.providerID {
				t.Fatalf("precondition: the forged node reports %q, want %q", got, f.providerID)
			}
			for _, as := range others {
				c := *cfg.DeepCopy()
				c.Contexts[as] = c.Contexts["k3d-"+name]
				c.CurrentContext = as
				p := filepath.Join(t.TempDir(), as+".kubeconfig")
				if err := clientcmd.WriteToFile(c, p); err != nil {
					t.Fatal(err)
				}
				r := podpeers(context.Background(), t, "check-context", "--kubeconfig", p)
				switch {
				case as == f.context && r.code != 0:
					t.Errorf("%s under its own name %q: want allowed, got exit %d: %s", f.providerID, as, r.code, r.stderr)
				case as != f.context && (r.code != 2 || !strings.Contains(r.stderr, "nodes of a different cluster")):
					t.Errorf("%s under %q: want refusal by the node gate (exit 2), got %d: %s", f.providerID, as, r.code, r.stderr)
				}
			}
			t.Logf("%s: allowed only as %q, refused as every other local name", f.providerID, f.context)
		})
	}
}

// kubectlWith runs kubectl against a kubeconfig held in memory (written to a
// temporary file), never the default one.
func kubectlWith(t *testing.T, cfg *clientcmdapi.Config, ctx string, args ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := clientcmd.WriteToFile(*cfg, p); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("kubectl", append([]string{"--kubeconfig", p, "--context", ctx}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %v: %v\n%s", args, err, out)
	}
	os.Remove(p)
	return string(out)
}

// TestTwinClusterCarryingLocalIdentity pins the node gate's same-identity
// residual with a genuinely different cluster, not a tunnel back to the same
// one: a KWOK cluster (its own etcd and API server, its own CA) given one fake
// node named exactly like the e2e cluster's server, under the e2e cluster's
// context name, is allowed. Node IDs are names, and this is what that means.
// The README says so; if podpeers ever tells such a twin apart, this fails
// and the README must change with it.
func TestTwinClusterCarryingLocalIdentity(t *testing.T) {
	if _, err := exec.LookPath("kwokctl"); err != nil {
		t.Fatal("kwokctl is required to stand up the twin cluster (go install sigs.k8s.io/kwok/cmd/kwokctl)")
	}
	const name = "pp-twin"
	// kwokctl writes its kubeconfig (and switches its current context) in
	// ~/.kube/config unless told otherwise: always give it this file.
	kc := filepath.Join(t.TempDir(), "twin.kubeconfig")
	kwokctl := func(args ...string) ([]byte, error) {
		c := exec.Command("kwokctl", append(args, "--name", name, "--kubeconfig", kc)...)
		c.Env = append(os.Environ(), "KUBECONFIG="+kc)
		return c.CombinedOutput()
	}
	// And prove it: the default kubeconfig is byte-for-byte untouched.
	home, _ := os.UserHomeDir()
	defaultKC := filepath.Join(home, ".kube", "config")
	before, _ := os.ReadFile(defaultKC)
	defer func() {
		if after, _ := os.ReadFile(defaultKC); string(after) != string(before) {
			t.Errorf("kwokctl changed %s", defaultKC)
		}
	}()
	kwokctl("delete", "cluster")
	defer kwokctl("delete", "cluster")
	if out, err := kwokctl("create", "cluster", "--runtime", "docker", "--wait", "2m"); err != nil {
		t.Fatalf("creating the KWOK twin: %v\n%s", err, out)
	}
	twin, err := clientcmd.LoadFromFile(kc)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := clientcmd.LoadFromFile(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	node := strings.TrimPrefix(kubeCtx, "k3d-") + "-server-0"
	node = "k3d-" + node
	if string(twin.Clusters["kwok-"+name].CertificateAuthorityData) == string(ours.Clusters[ours.Contexts[kubeCtx].Cluster].CertificateAuthorityData) {
		t.Fatal("precondition: the twin should be a different cluster, with its own CA")
	}
	nodeYAML := filepath.Join(t.TempDir(), "node.yaml")
	os.WriteFile(nodeYAML, []byte(`apiVersion: v1
kind: Node
metadata:
  name: `+node+`
  annotations: {kwok.x-k8s.io/node: fake}
spec:
  providerID: k3s://`+node+`
`), 0o644)
	if out, err := exec.Command("kubectl", "--kubeconfig", kc, "--context", "kwok-"+name, "apply", "-f", nodeYAML).CombinedOutput(); err != nil {
		t.Fatalf("creating the twin's node: %v\n%s", err, out)
	}
	twin.Contexts[kubeCtx] = twin.Contexts["kwok-"+name]
	twin.CurrentContext = kubeCtx
	as := filepath.Join(t.TempDir(), "as-local.kubeconfig")
	if err := clientcmd.WriteToFile(*twin, as); err != nil {
		t.Fatal(err)
	}
	r := podpeers(context.Background(), t, "check-context", "--kubeconfig", as)
	t.Logf("a KWOK twin (own API server and CA) whose node is named %s, as context %q: exit=%d %s", node, kubeCtx, r.code, strings.TrimSpace(r.stderr))
	if r.code != 0 || strings.TrimSpace(r.stdout) != "allowed" {
		t.Fatalf("the documented residual changed: a different cluster carrying the local identity was not allowed (exit %d); update the README", r.code)
	}
	// Control: the same twin under a name its node does not carry is refused.
	twin.Contexts["k3d-elsewhere"] = twin.Contexts[kubeCtx]
	twin.CurrentContext = "k3d-elsewhere"
	if err := clientcmd.WriteToFile(*twin, as); err != nil {
		t.Fatal(err)
	}
	if r := podpeers(context.Background(), t, "check-context", "--kubeconfig", as); r.code != 2 || !strings.Contains(r.stderr, "nodes of a different cluster") {
		t.Fatalf("control: the twin as k3d-elsewhere should be refused by the node gate, got %d", r.code)
	}
}
