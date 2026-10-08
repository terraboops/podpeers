package guard

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckDefaultsToRefusal(t *testing.T) {
	cases := []struct {
		name    string
		target  Target
		allow   string
		allowed bool
		optIn   bool
		reason  string
	}{
		{"kind on loopback", Target{"kind-dev", "https://127.0.0.1:6443", ""}, "", true, false, "local cluster"},
		{"k3d on loopback v6", Target{"k3d-dev", "https://[::1]:6443", ""}, "", true, false, "local cluster"},
		{"k3d on unspecified", Target{"k3d-dev", "https://0.0.0.0:6550", ""}, "", true, false, "local cluster"},
		{"minikube on localhost", Target{"minikube", "https://localhost:8443", ""}, "", true, false, "local cluster"},
		{"remote name remote server", Target{"prod-eu", "https://cluster.example.invalid", ""}, "", false, false, "not a recognised local cluster"},
		{"remote name loopback server", Target{"prod-eu", "https://127.0.0.1:6443", ""}, "", false, false, "not a recognised local cluster"},
		{"local name remote server", Target{"kind-dev", "https://cluster.example.invalid:6443", ""}, "", false, false, "not on loopback"},
		{"local name private ip", Target{"k3d-dev", "https://192.0.2.10:6443", ""}, "", false, false, "not on loopback"},
		{"bare prefix is not a name", Target{"kind-", "https://127.0.0.1:6443", ""}, "", false, false, "not a recognised"},
		{"prefix must be a prefix", Target{"mykind-dev", "https://127.0.0.1:6443", ""}, "", false, false, "not a recognised"},
		{"no context", Target{"", "https://127.0.0.1", ""}, "", false, false, "no kubeconfig context"},
		{"unparseable server", Target{"kind-dev", "::not a url", ""}, "", false, false, "not on loopback"},
		{"local name loopback server via proxy", Target{"k3d-dev", "https://127.0.0.1:6443", "socks5://127.0.0.1:1080"}, "", false, false, "proxy-url"},
		{"opt-in still allows a proxied context", Target{"k3d-dev", "https://127.0.0.1:6443", "socks5://127.0.0.1:1080"}, "k3d-dev", true, true, "explicitly allowed"},
		{"opt-in names the context", Target{"prod-eu", "https://cluster.example.invalid", ""}, "prod-eu", true, true, "explicitly allowed"},
		{"opt-in for other context refuses", Target{"prod-eu", "https://cluster.example.invalid", ""}, "staging", false, false, "does not match"},
		{"opt-in mismatch refuses even local", Target{"kind-dev", "https://127.0.0.1:6443", ""}, "kind-other", false, false, "does not match"},
		{"opt-in is case sensitive", Target{"Prod", "https://cluster.example.invalid", ""}, "prod", false, false, "does not match"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Check(c.target, c.allow)
			if d.Allowed != c.allowed || d.OptIn != c.optIn {
				t.Fatalf("Check(%+v, %q) = %+v; want allowed=%v optIn=%v", c.target, c.allow, d, c.allowed, c.optIn)
			}
			if !strings.Contains(d.Reason, c.reason) {
				t.Fatalf("reason %q does not mention %q", d.Reason, c.reason)
			}
		})
	}
}

func TestRefusalTellsOperatorHowToOptIn(t *testing.T) {
	d := Check(Target{"prod-eu", "https://cluster.example.invalid", ""}, "")
	if !strings.Contains(d.Reason, "--allow-context=prod-eu") {
		t.Fatalf("refusal should show the exact opt-in flag, got %q", d.Reason)
	}
}

func TestCheckNodes(t *testing.T) {
	local := Check(Target{"k3d-dev", "https://127.0.0.1:6550", ""}, "")
	optIn := Check(Target{"prod-eu", "https://cluster.example.invalid", ""}, "prod-eu")
	refused := Check(Target{"prod-eu", "https://cluster.example.invalid", ""}, "")

	cases := []struct {
		name    string
		pre     Decision
		ids     []string
		err     error
		allowed bool
		reason  string
	}{
		{"k3s nodes", local, []string{"k3s://k3d-dev-server-0"}, nil, true, "kind/k3d nodes"},
		{"kind nodes", local, []string{"kind://docker/dev/dev-control-plane", "kind://docker/dev/dev-worker"}, nil, true, "kind/k3d"},
		{"tunnel to cloud", local, []string{"k3s://a", "aws:///zone-a/i-0000000000"}, nil, false, "aws://..."},
		{"empty provider id", local, []string{""}, nil, false, "(empty)"},
		{"no nodes", local, nil, nil, false, "no nodes"},
		{"list forbidden", local, nil, errors.New("forbidden"), false, "cannot list nodes"},
		{"opt-in skips node check", optIn, []string{"gce://project/zone/vm"}, nil, true, "explicitly allowed"},
		{"refusal stays refusal", refused, []string{"k3s://a"}, nil, false, "not a recognised"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := CheckNodes(c.pre, c.ids, c.err)
			if d.Allowed != c.allowed || !strings.Contains(d.Reason, c.reason) {
				t.Fatalf("CheckNodes = %+v; want allowed=%v reason~%q", d, c.allowed, c.reason)
			}
		})
	}
}

func TestRefusalDoesNotEchoProviderDetails(t *testing.T) {
	local := Check(Target{"k3d-dev", "https://127.0.0.1:6550", ""}, "")
	d := CheckNodes(local, []string{"aws:///zone-a/i-0123456789abcdef0"}, nil)
	if strings.Contains(d.Reason, "i-0123456789abcdef0") {
		t.Fatalf("refusal leaked instance id: %q", d.Reason)
	}
}
