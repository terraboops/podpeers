// Package guard decides whether podpeers may touch a cluster at all.
//
// podpeers launches a debug container in every pod a selector matches. Pointed
// at the wrong cluster that is an intrusive change to someone else's live
// system, and a kubeconfig's current-context is very easy to get wrong. So the
// default is refusal: a cluster is only accepted without an explicit opt-in when
// every signal says it is a disposable local one. Anything else needs
// --allow-context=<exact context name>, which forces the operator to type the
// name of the cluster they are about to modify.
package guard

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Target describes the cluster a command is about to talk to, as resolved from
// the kubeconfig before any API request is made.
type Target struct {
	Context string // resolved context name
	Server  string // API server URL of that context's cluster
	Proxy   string // that cluster's proxy-url, if any
}

// Decision is the guard's verdict.
type Decision struct {
	Allowed bool
	OptIn   bool   // allowed only because of an explicit --allow-context
	Reason  string // human-readable explanation, always set
	Context string // the context judged, for the node gate to hold it to
}

// localContextPrefixes are the context names that local-cluster tools write.
var localContextPrefixes = []string{"kind-", "k3d-"}

// localContextNames are exact context names written by local-cluster tools.
var localContextNames = map[string]bool{
	"minikube": true, "docker-desktop": true, "rancher-desktop": true,
	"orbstack": true, "colima": true,
}

// LooksLocalName reports whether ctx is a name a local-cluster tool would write.
func LooksLocalName(ctx string) bool {
	if localContextNames[ctx] {
		return true
	}
	for _, p := range localContextPrefixes {
		if strings.HasPrefix(ctx, p) && len(ctx) > len(p) {
			return true
		}
	}
	return false
}

// IsLoopbackServer reports whether the API server URL points at this machine.
// Only literal loopback/unspecified addresses and "localhost" count: a hostname
// that merely resolves locally today is not proof of anything.
func IsLoopbackServer(server string) bool {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// Check is the pre-flight gate, evaluated from the kubeconfig alone so that a
// refusal happens before any network traffic. allowContext is the value of
// --allow-context ("" when not given).
func Check(t Target, allowContext string) Decision {
	if t.Context == "" {
		return Decision{Reason: "no kubeconfig context is selected; refusing"}
	}
	if allowContext != "" {
		if allowContext == t.Context {
			return Decision{Allowed: true, OptIn: true,
				Reason: fmt.Sprintf("context %q explicitly allowed with --allow-context", t.Context)}
		}
		// A mismatch is a refusal, not a fallback to the default rules: the
		// operator named a cluster and this is not it.
		return Decision{Reason: fmt.Sprintf(
			"--allow-context=%q does not match the active context %q; refusing", allowContext, t.Context)}
	}
	name, loop := LooksLocalName(t.Context), IsLoopbackServer(t.Server)
	switch {
	case name && loop && t.Proxy != "":
		// Requests go to the proxy, which can forward them anywhere: the
		// loopback server URL no longer says which cluster answers.
		return Decision{Reason: fmt.Sprintf(
			"context %q has a loopback API server but sends requests through proxy-url %q, which can lead to any cluster; refusing. Re-run with --allow-context=%s only if you mean to modify that cluster",
			t.Context, t.Proxy, t.Context)}
	case name && loop:
		return Decision{Allowed: true, Context: t.Context, Reason: fmt.Sprintf(
			"context %q is a local cluster (local tool name, loopback API server)", t.Context)}
	case !name:
		return Decision{Reason: fmt.Sprintf(
			"context %q is not a recognised local cluster; podpeers modifies every pod it targets, so it refuses non-local contexts. Re-run with --allow-context=%s only if you mean to modify that cluster",
			t.Context, t.Context)}
	default:
		return Decision{Reason: fmt.Sprintf(
			"context %q has a local-looking name but its API server is not on loopback; refusing. Re-run with --allow-context=%s only if you mean to modify that cluster",
			t.Context, t.Context)}
	}
}

// exactNameNodes are the node identities each exact-name local tool gives
// its single cluster. These come from the tools' defaults and were not run
// here (starting them rewrites the default kubeconfig); a wrong one only
// refuses a genuine local cluster, which --allow-context then opts into.
// A local name with no entry here (minikube) matches no node at all; neither
// do kubeadm-mode Docker Desktop's nodes, which carry no kind provider ID.
var exactNameNodes = map[string]string{
	"colima":          `^k3s://colima$`,
	"rancher-desktop": `^k3s://lima-rancher-desktop$`,
	"orbstack":        `^k3s://orbstack$`,
	"docker-desktop":  `^kind://[a-z]+/desktop/desktop-(control-plane|worker)[0-9]*$`,
}

// ownNodes matches the provider IDs of the nodes of the cluster a local
// context names. Every local name gets a pattern: a name with no known node
// identity matches no node at all, so no foreign k3s or kind cluster can ride
// a local tool's name through a loopback tunnel.
func ownNodes(context string) *regexp.Regexp {
	switch {
	case strings.HasPrefix(context, "k3d-"):
		return regexp.MustCompile(`^k3s://k3d-` + regexp.QuoteMeta(strings.TrimPrefix(context, "k3d-")) + `-(server|agent)-[0-9]+$`)
	case strings.HasPrefix(context, "kind-"):
		n := regexp.QuoteMeta(strings.TrimPrefix(context, "kind-"))
		return regexp.MustCompile(`^kind://[a-z]+/` + n + `/` + n + `-(control-plane|worker)[0-9]*$`)
	}
	if p, ok := exactNameNodes[context]; ok {
		return regexp.MustCompile(p)
	}
	return regexp.MustCompile(`^\b$`) // matches no provider ID
}

// localProviderPrefixes are node spec.providerID schemes written by local
// cluster distributions (kind and k3s/k3d).
var localProviderPrefixes = []string{"kind://", "k3s://"}

// CheckNodes is the second gate, run after connecting and before any pod is
// modified. A loopback API address can still be a tunnel to a remote cluster,
// so when the pre-flight decision was not an explicit opt-in, every node must
// carry a local provider ID. Cloud nodes (aws://, gce://, azure://, ...) and
// nodes with no provider ID at all fail this check. A local provider scheme is
// not enough on its own: every k3s cluster, remote and production ones
// included, writes k3s://. So the nodes must also belong to the cluster the
// context names: a k3d-NAME context only to k3s://k3d-NAME-(server|agent)-N
// nodes, a kind-NAME context only to kind://<runtime>/NAME/NAME-... nodes.
func CheckNodes(pre Decision, providerIDs []string, listErr error) Decision {
	if !pre.Allowed || pre.OptIn {
		return pre
	}
	if listErr != nil {
		return Decision{Reason: fmt.Sprintf(
			"cannot list nodes to confirm the cluster is local (%v); refusing. Grant 'list nodes' or use --allow-context", listErr)}
	}
	if len(providerIDs) == 0 {
		return Decision{Reason: "cluster reports no nodes; cannot confirm it is local; refusing"}
	}
	for _, id := range providerIDs {
		ok := false
		for _, p := range localProviderPrefixes {
			if strings.HasPrefix(id, p) {
				ok = true
				break
			}
		}
		if !ok {
			shown := id
			if shown == "" {
				shown = "(empty)"
			}
			return Decision{Reason: fmt.Sprintf(
				"a node has provider ID %s, which is not a local kind/k3d node; refusing. Use --allow-context if you mean to modify this cluster", schemeOnly(shown))}
		}
		if !ownNodes(pre.Context).MatchString(id) {
			// The node names are not echoed: through a tunnel they could be
			// another cluster's.
			return Decision{Reason: fmt.Sprintf(
				"context %q names a local cluster, but the API server answering it reports nodes of a different cluster (a tunnel or a reused port?); refusing. Use --allow-context if you mean to modify this cluster", pre.Context)}
		}
	}
	return Decision{Allowed: true, Reason: pre.Reason + "; all nodes are kind/k3d nodes"}
}

// schemeOnly trims a provider ID to its scheme so refusal messages do not echo
// cloud instance or account identifiers into terminals and CI logs.
func schemeOnly(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[:i+3] + "..."
	}
	return id
}
