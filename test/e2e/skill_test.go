//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	netv1 "k8s.io/api/networking/v1"
	"sigs.k8s.io/yaml"

	"github.com/terraboops/podpeers/internal/policy"
)

const helmNS = "pp-helm"

func helm(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"--kubeconfig", kubeconfig, "--kube-context", kubeCtx}, args...)
	out, err := exec.Command("helm", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// skill runs the skill's own script, exactly as an agent following SKILL.md would.
func skill(t *testing.T, args ...string) result {
	t.Helper()
	script, _ := filepath.Abs("../../skills/podpeers-netpol/scripts/netpol-check.sh")
	base := []string{"--kubeconfig", kubeconfig, "--context", kubeCtx, "--namespace", helmNS}
	cmd := exec.Command(script, append(args, base...)...)
	cmd.Env = append(os.Environ(), "PODPEERS="+binary)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{code: code, stdout: string(out)}
}

// editPolicies rewrites a suggestion file, applying fn to each policy.
func editPolicies(t *testing.T, in, out string, fn func(*netv1.NetworkPolicy)) {
	t.Helper()
	b, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var docs []string
	for _, d := range strings.Split(string(b), "\n---\n")[1:] {
		var np netv1.NetworkPolicy
		if err := yaml.Unmarshal([]byte(d), &np); err != nil {
			t.Fatal(err)
		}
		if np.Name == "" {
			continue // a refused workload: comments only
		}
		fn(&np)
		y, _ := yaml.Marshal(np)
		docs = append(docs, string(y))
	}
	if err := os.WriteFile(out, []byte(strings.Join(docs, "---\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSkillHelmWorkflow drives the podpeers-netpol skill's workflow end to end
// against a real Helm release: baseline -> suggestions -> apply -> verify, then
// proves the verification catches two different kinds of breakage.
func TestSkillHelmWorkflow(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Fatal("helm is required for the skill workflow test")
	}
	chart, _ := filepath.Abs("../../examples/shop")
	exec.Command("helm", "--kubeconfig", kubeconfig, "--kube-context", kubeCtx, "uninstall", "shop", "-n", helmNS, "--wait").Run()
	exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "namespace", helmNS, "--ignore-not-found", "--wait=true", "--timeout=120s").Run()
	helm(t, "install", "shop", chart, "-n", helmNS, "--create-namespace", "--wait", "--timeout", "2m")
	t.Cleanup(func() {
		if os.Getenv("PODPEERS_E2E_KEEP") == "" {
			exec.Command("helm", "--kubeconfig", kubeconfig, "--kube-context", kubeCtx, "uninstall", "shop", "-n", helmNS).Run()
			exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "delete", "namespace", helmNS, "--wait=false").Run()
		}
	})
	work := filepath.Join(outDir, "skill")
	os.RemoveAll(work)
	os.MkdirAll(work, 0o755)
	baseline := filepath.Join(work, "baseline.json")
	suggested := filepath.Join(work, "policy.yaml")

	t.Run("baseline captures the release while helm test runs, and suggests policies", func(t *testing.T) {
		r := skill(t, "baseline", "--release", "shop", "--duration", "30s", "--out", work)
		t.Logf("exit=%d\n%s", r.code, r.stdout)
		if r.code != 0 {
			t.Fatalf("baseline exit %d", r.code)
		}
		res := load(t, baseline)
		report, _ := os.ReadFile(filepath.Join(work, "baseline.txt"))
		t.Logf("baseline report:\n%s", report)
		var web, api string
		for _, p := range res.Pods {
			switch p.Workload {
			case "Deployment/shop-web":
				web = p.ID()
			case "Deployment/shop-api":
				api = p.ID()
			}
		}
		expectEdges(t, res, web,
			"inbound pp-helm/shop-smoke tcp/8080 closed",
			"outbound svc/pp-helm/shop-api tcp/80 open")
		expectEdges(t, res, api, "inbound "+web+" tcp/9000 open")

		var rep policy.Report
		b, _ := os.ReadFile(filepath.Join(work, "policy.json"))
		if err := json.Unmarshal(b, &rep); err != nil {
			t.Fatal(err)
		}
		y, _ := os.ReadFile(suggested)
		t.Logf("suggested policy.yaml:\n%s", y)
		if len(rep.Suggestions) != 2 {
			t.Fatalf("want suggestions for shop-api and shop-web, got %d", len(rep.Suggestions))
		}
		for _, s := range rep.Suggestions {
			if s.Refused != "" || s.Policy == nil {
				t.Fatalf("%s refused: %s", s.Workload, s.Refused)
			}
			if s.Workload == "Deployment/shop-web" {
				// The only client of web:8080 in the window was the helm test
				// pod, which completed: suggest must warn that the policy
				// would admit nothing but the test.
				warned := false
				for _, g := range s.Gaps {
					warned = warned || (strings.Contains(g, "ENTRY POINT WARNING: ingress on tcp/8080") && strings.Contains(g, "shop-smoke"))
				}
				if !warned {
					t.Errorf("no entry-point warning for web:8080 seen only from the completed test pod: %v", s.Gaps)
				}
				var api, dns int
				for _, rule := range s.Policy.Spec.Egress {
					sel := rule.To[0].PodSelector.MatchLabels
					switch {
					case sel["app.kubernetes.io/component"] == "api":
						api++
						if rule.Ports[0].Port.String() != "api" {
							t.Errorf("web egress should target the named port 'api' behind service port 80: %+v", rule)
						}
					case sel["k8s-app"] == "kube-dns":
						dns++
						if len(rule.Ports) != 2 {
							t.Errorf("DNS rule should cover udp and tcp 53: %+v", rule.Ports)
						}
					}
				}
				if api != 1 || dns != 1 || len(s.Policy.Spec.Egress) != 2 {
					t.Errorf("web egress = %+v", s.Policy.Spec.Egress)
				}
				flagged := false
				for _, r := range s.Reasons {
					flagged = flagged || r.Assumed || strings.Contains(strings.Join(r.Evidence, " "), "ASSUMED")
				}
				if !flagged {
					t.Error("whatever part of DNS was not observed must be flagged ASSUMED")
				}
			}
		}
	})

	t.Run("verify: the suggested policy keeps the app working", func(t *testing.T) {
		r := skill(t, "verify", "--release", "shop", "--policy", suggested, "--baseline", baseline, "--duration", "30s", "--out", filepath.Join(work, "good"))
		t.Logf("exit=%d\n%s", r.code, r.stdout)
		if r.code != 0 || !strings.Contains(r.stdout, "verdict: OK") {
			t.Fatalf("want OK, got exit %d", r.code)
		}
		// verify restarts the workloads; pods replaced mid-window must still
		// resolve to their workload, never to a bare address.
		if regexp.MustCompile(`(?m)^(new|lost|blocked|preexisting)\s+\d+\.\d+\.\d+\.\d+`).MatchString(r.stdout) {
			t.Fatal("a replaced pod resolved as a bare IP in the diff")
		}
	})

	t.Run("verify --no-apply checks the policy already in the cluster", func(t *testing.T) {
		// The good policy is still applied from the previous subtest: this is
		// how the skill verifies a policy the chart ships.
		r := skill(t, "verify", "--release", "shop", "--no-apply", "--baseline", baseline, "--duration", "30s", "--out", filepath.Join(work, "no-apply"))
		t.Logf("exit=%d\n%s", r.code, r.stdout)
		if r.code != 0 || !strings.Contains(r.stdout, "verdict: OK") || !strings.Contains(r.stdout, "already in the cluster (--no-apply)") {
			t.Fatalf("want OK without applying anything, got exit %d", r.code)
		}
		if strings.Contains(r.stdout, "created") || strings.Contains(r.stdout, "configured") {
			t.Error("--no-apply applied something")
		}
		log, _ := os.ReadFile(filepath.Join(work, "no-apply", "after-helm-test.log"))
		if !strings.Contains(string(log), "smoke: front door answered") {
			t.Errorf("helm test log should include the test pod's own output (--logs):\n%s", log)
		}
	})

	t.Run("the applied policy permits nothing else", func(t *testing.T) {
		out, _ := exec.Command("kubectl", "--kubeconfig", kubeconfig, "--context", kubeCtx, "run", "intruder", "-n", helmNS,
			"--image=busybox:1.36", "--image-pull-policy=IfNotPresent", "--restart=Never", "--rm", "-i", "--labels=app=intruder", "--command", "--",
			"sh", "-c", "sleep 10; if timeout 8 nc -z -w 5 shop-api."+helmNS+".svc.cluster.local 80; then echo CONNECTED; else echo BLOCKED; fi").CombinedOutput()
		t.Logf("unobserved client -> shop-api:80 (after 10s, so not the new-pod race): %s", strings.TrimSpace(string(out)))
		if !strings.Contains(string(out), "BLOCKED") {
			t.Fatal("a client that was never observed reached shop-api")
		}
	})

	t.Run("verify catches breakage helm test cannot see (blocked web->api)", func(t *testing.T) {
		broken := filepath.Join(work, "policy-no-web-egress-to-api.yaml")
		editPolicies(t, suggested, broken, func(np *netv1.NetworkPolicy) {
			if np.Name == "podpeers-shop-web" {
				// Drop the rule to api by what it selects, not by position:
				// when DNS happens to be observed, its rule can come first.
				var keep []netv1.NetworkPolicyEgressRule
				for _, r := range np.Spec.Egress {
					if r.To[0].PodSelector.MatchLabels["app.kubernetes.io/component"] != "api" {
						keep = append(keep, r)
					}
				}
				if len(keep) != len(np.Spec.Egress)-1 {
					t.Fatalf("expected exactly one egress rule to api in %+v", np.Spec.Egress)
				}
				np.Spec.Egress = keep
			}
		})
		r := skill(t, "verify", "--release", "shop", "--policy", broken, "--baseline", baseline, "--duration", "30s", "--out", filepath.Join(work, "broken-egress"))
		t.Logf("exit=%d\n%s", r.code, r.stdout)
		if r.code != 4 || !strings.Contains(r.stdout, "helm test: passed") ||
			!strings.Contains(r.stdout, "blocked pp-helm/Deployment/shop-web -> svc/pp-helm/shop-api tcp/80") {
			t.Fatalf("want exit 4 with helm test passing and web->api blocked, got %d", r.code)
		}
	})

	t.Run("verify catches breakage helm test does see, and rolls back", func(t *testing.T) {
		broken := filepath.Join(work, "policy-no-web-ingress.yaml")
		editPolicies(t, suggested, broken, func(np *netv1.NetworkPolicy) {
			if np.Name == "podpeers-shop-web" {
				np.Spec.Ingress = []netv1.NetworkPolicyIngressRule{}
			}
		})
		r := skill(t, "verify", "--release", "shop", "--policy", broken, "--baseline", baseline, "--duration", "30s",
			"--out", filepath.Join(work, "broken-ingress"), "--rollback-on-fail")
		t.Logf("exit=%d\n%s", r.code, r.stdout)
		if r.code != 5 || !strings.Contains(r.stdout, "BROKEN: helm test failed") {
			t.Fatalf("want exit 5, got %d", r.code)
		}
		left := kubectl(t, "get", "networkpolicy", "-n", helmNS, "-o", "name")
		if strings.TrimSpace(left) != "" {
			t.Fatalf("--rollback-on-fail left policies behind: %s", left)
		}
	})

	t.Run("the skill script refuses a context podpeers refuses", func(t *testing.T) {
		cfg := filepath.Join(t.TempDir(), "kubeconfig")
		b, _ := os.ReadFile(kubeconfig)
		os.WriteFile(cfg, []byte(strings.ReplaceAll(string(b), kubeCtx, "prod-like")), 0o600)
		script, _ := filepath.Abs("../../skills/podpeers-netpol/scripts/netpol-check.sh")
		cmd := exec.CommandContext(context.Background(), script, "verify", "--release", "shop", "--namespace", helmNS,
			"--kubeconfig", cfg, "--context", "prod-like", "--policy", suggested, "--baseline", baseline)
		cmd.Env = append(os.Environ(), "PODPEERS="+binary)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		t.Logf("exit=%d\n%s", code, out)
		if strings.Contains(string(out), "networkpolicy") || strings.Contains(string(out), "dry run") {
			t.Errorf("the script touched the cluster despite the refused context")
		}
		if code != 2 {
			t.Fatalf("want refusal (exit 2) before any apply, got %d", code)
		}
	})
}
