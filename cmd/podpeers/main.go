// Command podpeers maps the network peers of Kubernetes pods by sampling their
// socket tables from short-lived ephemeral debug containers, so NetworkPolicy
// can be written from observed traffic without a flow-log pipeline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/terraboops/podpeers/internal/capture"
	"github.com/terraboops/podpeers/internal/diff"
	"github.com/terraboops/podpeers/internal/gql"
	"github.com/terraboops/podpeers/internal/graph"
	"github.com/terraboops/podpeers/internal/guard"
	"github.com/terraboops/podpeers/internal/mcp"
	"github.com/terraboops/podpeers/internal/policy"
	"github.com/terraboops/podpeers/internal/render"
)

// Exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitRefused = 2 // the safety guard refused the target cluster
	exitPartial = 3 // capture written, but some targeted pods could not be observed
	exitBroken  = 4 // diff: traffic that worked before is blocked or missing
	// diff: no breakage seen, but some flows were only observed on
	// connections that predate the change, so the change was not exercised.
	exitInconclusive = 5
)

var version = "dev"

// buildVersion reports the module version for `go install …@version` builds
// (e.g. a v0.0.0-<date>-<commit> pseudo-version), where no -ldflags version
// was set. Everything that reports a version uses it: `podpeers version`, the
// MCP server's serverInfo and the API client's user agent.
var buildVersion = func() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

const usage = `podpeers - map pod network peers from observed sockets

Usage:
  podpeers capture -l SELECTOR [-n NS | -A] [--duration 5m] [--interval 1s] [-o peers.json]
  podpeers check-context [--kubeconfig PATH] [--context NAME] [--allow-context NAME]
  podpeers render  [-format text|dot|html|json] [-o FILE] peers.json
  podpeers query   peers.json '{ pods { id peers { id kind } } }'
  podpeers serve   [-addr 127.0.0.1:8080] peers.json
  podpeers suggest [-n NS] [-workload Kind/name] [-dns auto|always|never] [-format yaml|json] peers.json
  podpeers diff    [-existing-pods FILE] before.json after.json
  podpeers mcp     peers.json            (MCP server on stdio; read-only)
  podpeers version

SAFETY: capture adds a debug container to every pod the selector matches. It
refuses any kubeconfig context that is not a local kind/k3d cluster unless you
pass --allow-context=<that exact context name>.

Run 'podpeers <command> -h' for flags.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "capture":
		return cmdCapture(ctx, rest, stdout, stderr)
	case "check-context":
		return cmdCheckContext(ctx, rest, stdout, stderr)
	case "render":
		return cmdRender(rest, stdout, stderr)
	case "query":
		return cmdQuery(rest, stdout, stderr)
	case "serve":
		return cmdServe(ctx, rest, stderr)
	case "suggest":
		return cmdSuggest(rest, stdout, stderr)
	case "diff":
		return cmdDiff(rest, stdout, stderr)
	case "mcp":
		return cmdMCP(rest, os.Stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "podpeers", buildVersion())
		return exitOK
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return exitOK
	}
	fmt.Fprintf(stderr, "podpeers: unknown command %q\n\n%s", cmd, usage)
	return exitError
}

// clusterFlags are shared by every command that talks to a cluster.
type clusterFlags struct {
	kubeconfig, context, allowContext string
}

func (c *clusterFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	fs.StringVar(&c.context, "context", "", "kubeconfig context to use (default: current-context)")
	fs.StringVar(&c.allowContext, "allow-context", "", "explicitly allow this exact NON-LOCAL context (required for anything but local kind/k3d)")
}

// connection is a guarded, ready-to-use cluster client.
type connection struct {
	cs        kubernetes.Interface
	namespace string        // from the context, used when -n is not given
	nodes     []corev1.Node // listed for the node guard; reused to name node IPs
}

// connect resolves the kubeconfig, applies the pre-flight guard (no network),
// then connects and applies the node guard. Any refusal returns exitRefused.
func connect(ctx context.Context, cf clusterFlags, stderr io.Writer) (*connection, int) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if cf.kubeconfig != "" {
		rules.ExplicitPath = cf.kubeconfig
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: cf.context})
	raw, err := cc.RawConfig()
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: reading kubeconfig: %v\n", err)
		return nil, exitError
	}
	target := guard.Target{Context: cf.context}
	if target.Context == "" {
		target.Context = raw.CurrentContext
	}
	if kc, ok := raw.Contexts[target.Context]; ok {
		if cl, ok := raw.Clusters[kc.Cluster]; ok {
			target.Server = cl.Server
		}
	} else if target.Context != "" {
		fmt.Fprintf(stderr, "podpeers: context %q not found in kubeconfig\n", target.Context)
		return nil, exitError
	}
	pre := guard.Check(target, cf.allowContext)
	if !pre.Allowed {
		fmt.Fprintf(stderr, "podpeers: REFUSED: %s\n", pre.Reason)
		return nil, exitRefused
	}

	rc, err := cc.ClientConfig()
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: building client config: %v\n", err)
		return nil, exitError
	}
	rc.UserAgent = "podpeers/" + buildVersion()
	// Injection and polling touch every targeted pod; client-go's default
	// 5 QPS makes that slow and logs throttling warnings mid-output.
	rc.QPS, rc.Burst = 50, 100
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return nil, exitError
	}
	nodes, nerr := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	var ids []string
	var nodeList []corev1.Node
	if nerr == nil {
		nodeList = nodes.Items
		for _, n := range nodeList {
			ids = append(ids, n.Spec.ProviderID)
		}
	}
	dec := guard.CheckNodes(pre, ids, nerr)
	if !dec.Allowed {
		fmt.Fprintf(stderr, "podpeers: REFUSED: %s\n", dec.Reason)
		return nil, exitRefused
	}
	fmt.Fprintf(stderr, "podpeers: %s\n", dec.Reason)
	ns, _, _ := cc.Namespace()
	return &connection{cs: cs, namespace: ns, nodes: nodeList}, exitOK
}

func cmdCheckContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-context", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf clusterFlags
	cf.register(fs)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	_, code := connect(ctx, cf, stderr)
	if code == exitOK {
		fmt.Fprintln(stdout, "allowed")
	}
	return code
}

func cmdCapture(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var cf clusterFlags
	cf.register(fs)
	var opts capture.Options
	var out, format string
	fs.StringVar(&opts.LabelSelector, "l", "", "label selector of the pods to probe (required)")
	fs.StringVar(&opts.Namespace, "n", "", "namespace (default: the context's namespace)")
	fs.BoolVar(&opts.AllNamespaces, "A", false, "select pods in all namespaces")
	fs.DurationVar(&opts.Duration, "duration", capture.DefaultDuration, "measurement window: what was not happening inside it is not seen (longer beats faster)")
	fs.DurationVar(&opts.Interval, "interval", capture.DefaultInterval, "time between socket-table samples (minimum 100ms; sub-second costs CPU on the pods' nodes)")
	fs.DurationVar(&opts.StartTimeout, "start-timeout", 60*time.Second, "how long a debug container may take to start")
	fs.StringVar(&opts.Image, "image", "busybox:1.36", "debug container image (needs sh, cat, date, sleep)")
	fs.StringVar(&out, "o", "peers.json", "write the capture (JSON) here; '-' for stdout")
	fs.StringVar(&format, "summary", "text", "summary printed to stderr when done: text or none")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "podpeers: unexpected argument %q\n", fs.Arg(0))
		return exitError
	}
	if opts.AllNamespaces && opts.Namespace != "" {
		fmt.Fprintln(stderr, "podpeers: -n and -A are mutually exclusive")
		return exitError
	}
	if err := opts.Validate(); err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	if opts.Interval < time.Second {
		fmt.Fprintf(stderr, "podpeers: WARNING: --interval %s costs about %s. The default is %s; see docs/method.md for when shorter helps (mostly UDP).\n",
			opts.Interval, capture.SamplingCost(opts.Interval), capture.DefaultInterval)
	}
	conn, code := connect(ctx, cf, stderr)
	if code != exitOK {
		return code
	}
	if !opts.AllNamespaces && opts.Namespace == "" {
		opts.Namespace = conn.namespace
	}
	opts.Logf = func(f string, a ...any) { fmt.Fprintf(stderr, "podpeers: "+f+"\n", a...) }

	res, err := capture.Run(ctx, conn.cs, conn.nodes, opts)
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: capture failed: %v\n", err)
		return exitError
	}
	if err := writeJSON(out, stdout, res); err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	if format == "text" {
		fmt.Fprintln(stderr)
		_ = render.Text(stderr, res)
	}
	if out != "-" {
		fmt.Fprintf(stderr, "podpeers: wrote %s\n", out)
	}
	for _, p := range res.Pods {
		if p.Probe.Status == graph.ProbeFailed {
			return exitPartial
		}
	}
	return exitOK
}

func writeJSON(path string, stdout io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "-" {
		_, err = stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func loadArg(fs *flag.FlagSet, stderr io.Writer) (graph.Result, bool) {
	if fs.NArg() < 1 {
		fmt.Fprintln(stderr, "podpeers: missing capture file argument")
		return graph.Result{}, false
	}
	res, err := graph.LoadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return graph.Result{}, false
	}
	return res, true
}

func cmdRender(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("render", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "text, dot, html or json")
	out := fs.String("o", "-", "output file ('-' for stdout)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	res, ok := loadArg(fs, stderr)
	if !ok {
		return exitError
	}
	w := stdout
	if *out != "-" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(stderr, "podpeers: %v\n", err)
			return exitError
		}
		defer f.Close()
		w = f
	}
	var err error
	switch *format {
	case "text":
		err = render.Text(w, res)
	case "dot":
		err = render.DOT(w, res)
	case "html":
		err = render.HTML(w, res, "")
	case "json":
		err = writeJSON("-", w, res)
	default:
		fmt.Fprintf(stderr, "podpeers: unknown format %q\n", *format)
		return exitError
	}
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	return exitOK
}

func cmdQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("query", flag.ContinueOnError)
	fs.SetOutput(stderr)
	vars := fs.String("vars", "", "JSON object of query variables")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	res, ok := loadArg(fs, stderr)
	if !ok {
		return exitError
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(stderr, "podpeers: missing GraphQL query argument")
		return exitError
	}
	var vm map[string]any
	if *vars != "" {
		if err := json.Unmarshal([]byte(*vars), &vm); err != nil {
			fmt.Fprintf(stderr, "podpeers: -vars: %v\n", err)
			return exitError
		}
	}
	schema, err := gql.NewSchema(res)
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	r := gql.Do(schema, strings.Join(fs.Args()[1:], " "), vm)
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Fprintln(stdout, string(b))
	if r.HasErrors() {
		return exitError
	}
	return exitOK
}

// Handler serves the visualization at / and the GraphQL API at /graphql.
func Handler(res graph.Result) (http.Handler, error) {
	schema, err := gql.NewSchema(res)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query     string         `json:"query"`
			Variables map[string]any `json:"variables"`
		}
		switch r.Method {
		case http.MethodGet:
			req.Query = r.URL.Query().Get("query")
		case http.MethodPost:
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
				http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "use GET or POST", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gql.Do(schema, req.Query, req.Variables))
	})
	// Browsers ask every server for a favicon; answering 404 puts an error in
	// the console of a page that has none.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = render.HTML(w, res, "graphql")
	})
	return mux, nil
}

func cmdServe(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	res, ok := loadArg(fs, stderr)
	if !ok {
		return exitError
	}
	h, err := Handler(res)
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	srv := &http.Server{Addr: *addr, Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	fmt.Fprintf(stderr, "podpeers: serving http://%s/ (GraphQL at /graphql)\n", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	return exitOK
}

func cmdSuggest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("suggest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o policy.Options
	format := fs.String("format", "yaml", "yaml (apply-ready, reasoning as comments) or json")
	out := fs.String("o", "-", "output file ('-' for stdout)")
	fs.StringVar(&o.Namespace, "n", "", "only workloads in this namespace")
	fs.StringVar(&o.Workload, "workload", "", "only this workload, Kind/name (e.g. Deployment/web)")
	fs.StringVar(&o.DNS, "dns", policy.DNSAuto, "DNS egress: auto (if the workload has outbound traffic), always, never")
	fs.IntVar(&o.MinSamples, "min-samples", 3, "refuse to suggest for pods with fewer samples")
	fs.DurationVar(&o.MinWindow, "min-window", 24*time.Hour, "warn when the capture window is shorter than this")
	fs.BoolVar(&o.AllowEmpty, "allow-empty", false, "emit deny-all for workloads with no observed traffic instead of refusing")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if o.DNS != policy.DNSAuto && o.DNS != policy.DNSAlways && o.DNS != policy.DNSNever {
		fmt.Fprintln(stderr, "podpeers: -dns must be auto, always or never")
		return exitError
	}
	res, ok := loadArg(fs, stderr)
	if !ok {
		return exitError
	}
	rep := policy.Suggest(res, o)
	var body string
	switch *format {
	case "yaml":
		y, err := rep.YAML()
		if err != nil {
			fmt.Fprintf(stderr, "podpeers: %v\n", err)
			return exitError
		}
		body = y
	case "json":
		b, _ := json.MarshalIndent(rep, "", "  ")
		body = string(b) + "\n"
	default:
		fmt.Fprintf(stderr, "podpeers: unknown format %q\n", *format)
		return exitError
	}
	if *out == "-" {
		io.WriteString(stdout, body)
	} else if err := os.WriteFile(*out, []byte(body), 0o644); err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	ready, refused := len(rep.Ready()), len(rep.Suggestions)-len(rep.Ready())
	fmt.Fprintf(stderr, "podpeers: %d policy suggestion(s), %d workload(s) refused for thin evidence\n", ready, refused)
	return exitOK
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "machine-readable output")
	existing := fs.String("existing-pods", "", "file listing the pods (ns/name, one per line) that existed when the change took effect; connections of pods not on it count as made under the change")
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(stderr, "podpeers: diff needs two capture files: before.json after.json")
		return exitError
	}
	before, err := graph.LoadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	after, err := graph.LoadFile(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	var o diff.Options
	if *existing != "" {
		b, err := os.ReadFile(*existing)
		if err != nil {
			fmt.Fprintf(stderr, "podpeers: -existing-pods: %v\n", err)
			return exitError
		}
		o.ExistingPods = map[string]bool{}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "pod/")); l != "" {
				o.ExistingPods[l] = true
			}
		}
	}
	d := diff.CompareWith(before, after, o)
	if *asJSON {
		b, _ := json.MarshalIndent(map[string]any{"broken": d.Broken(), "inconclusive": d.Inconclusive(), "changes": d.Changes, "unverifiable": d.Unverifiable}, "", "  ")
		fmt.Fprintln(stdout, string(b))
	} else {
		d.Text(stdout)
	}
	if d.Broken() {
		return exitBroken
	}
	if d.Inconclusive() {
		return exitInconclusive
	}
	return exitOK
}

func cmdMCP(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "podpeers: mcp needs the capture file to serve")
		return exitError
	}
	if _, err := graph.LoadFile(fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "podpeers: %v\n", err)
		return exitError
	}
	srv := &mcp.Server{CapturePath: fs.Arg(0), Version: buildVersion()}
	if err := srv.Serve(stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "podpeers: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
